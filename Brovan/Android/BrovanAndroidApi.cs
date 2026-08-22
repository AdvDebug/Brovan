using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Brovan.Core.Emulation;
using Brovan.Core.Emulation.OS.SharedHelpers;
using Brovan.Core.Helpers;
using Brovan.Core.Helpers.WindowsImage;

namespace Brovan.Android
{
    internal static unsafe class BrovanAndroidApi
    {
        public const int StatusOk = 0;
        public const int StatusNotInitialized = -1;
        public const int StatusAlreadyRunning = -2;
        public const int StatusInvalidArgument = -3;
        public const int StatusMissingWindowsLibs = -4;
        public const int StatusMissingRegistry = -5;
        public const int StatusApiSetMapFailed = -6;
        public const int StatusBinaryNotFound = -7;
        public const int StatusFailed = -8;

        private static int _initialized;
        private static int _running;
        private static bool _verbose;
        private static IntPtr _exitSink;
        private static IntPtr _installProgressSink;

        [UnmanagedCallersOnly(EntryPoint = "brovan_init")]
        public static int Init(byte* baseDirectory)
        {
            if (Interlocked.Exchange(ref _initialized, 1) != 0)
                return StatusOk;

            try
            {
                string directory = Marshal.PtrToStringUTF8((IntPtr)baseDirectory);
                if (string.IsNullOrWhiteSpace(directory))
                    return StatusInvalidArgument;

                Directory.CreateDirectory(directory);

                // getFilesDir() returns /data/user/0/<pkg>, but /data/user/0 symlinks to /data/data.
                // The IO sandbox resolves the symlink, causing paths under WindowsLibs and VirtualFS
                // to fall outside the allowed root, so the guest fails to load DLLs.
                directory = Canonicalize(directory);

                if (!directory.EndsWith(Path.DirectorySeparatorChar))
                    directory += Path.DirectorySeparatorChar;

                // Every path in the emulator is derived from AppContext.BaseDirectory, and several of those
                // are static field initializers, so this has to land before anything else is touched.
                AppContext.SetData("APP_CONTEXT_BASE_DIRECTORY", directory);

                AndroidHost.MarkActive();

                AndroidLog.RedirectStandardStreams();
                Console.SetOut(new AndroidLogWriter(AndroidNative.LogInfo));
                Console.SetError(new AndroidLogWriter(AndroidNative.LogError));

                AppDomain.CurrentDomain.UnhandledException += (sender, e) =>
                {
                    Exception exception = (Exception)e.ExceptionObject;
                    Utils.LogError($"[Global Unhandled Exception]: {exception.Message}\nStack Trace:\n\n{exception.StackTrace}");
                    AndroidLog.Write(AndroidNative.LogError, $"[Global Unhandled Exception]: {exception.Message}");
                };

                NativeLibraryResolver.Register();
                return StatusOk;
            }
            catch (Exception exception)
            {
                AndroidLog.Write(AndroidNative.LogError, $"[brovan_init] {exception}");
                Volatile.Write(ref _initialized, 0);
                return StatusFailed;
            }
        }

        [UnmanagedCallersOnly(EntryPoint = "brovan_set_log_sink")]
        public static void SetLogSink(IntPtr sink) => AndroidLog.SetSink(sink);

        [UnmanagedCallersOnly(EntryPoint = "brovan_set_exit_sink")]
        public static void SetExitSink(IntPtr sink) => Volatile.Write(ref _exitSink, sink);

        [UnmanagedCallersOnly(EntryPoint = "brovan_set_install_progress_sink")]
        public static void SetInstallProgressSink(IntPtr sink) => Volatile.Write(ref _installProgressSink, sink);

        [UnmanagedCallersOnly(EntryPoint = "brovan_set_text_sink")]
        public static void SetTextSink(IntPtr sink) => AndroidText.SetSink(sink);

        [UnmanagedCallersOnly(EntryPoint = "brovan_set_verbose")]
        public static void SetVerbose(int enabled) => _verbose = enabled != 0;

        [UnmanagedCallersOnly(EntryPoint = "brovan_set_jit_cache")]
        public static void SetJitCache(int enabled) => UnicornCodeCache.Enabled = enabled != 0;

        [UnmanagedCallersOnly(EntryPoint = "brovan_set_surface")]
        public static void SetSurface(IntPtr nativeWindow, int width, int height, int densityDpi)
        {
            Guard(() =>
            {
                AndroidHost.SetSurface(nativeWindow, width, height, densityDpi);
                HostDisplayMetrics.Invalidate();

                if (nativeWindow != IntPtr.Zero)
                    AndroidInput.Resize(AndroidHost.Width, AndroidHost.Height);
            }, nameof(SetSurface));
        }

        [UnmanagedCallersOnly(EntryPoint = "brovan_clear_surface")]
        public static void ClearSurface()
        {
            Guard(() => AndroidHost.SetSurface(IntPtr.Zero, 0, 0, 0), nameof(ClearSurface));
        }

        [UnmanagedCallersOnly(EntryPoint = "brovan_start")]
        public static int Start(byte* binaryPath, byte* guestCommandLine, byte* workingDirectory, byte* commands, int networkMode)
        {
            if (Volatile.Read(ref _initialized) == 0)
                return StatusNotInitialized;

            if (Interlocked.Exchange(ref _running, 1) != 0)
                return StatusAlreadyRunning;

            try
            {
                string path = Marshal.PtrToStringUTF8((IntPtr)binaryPath);
                int validation = ValidateEnvironment(path);
                if (validation != StatusOk)
                {
                    Volatile.Write(ref _running, 0);
                    return validation;
                }

                string rawArguments = Marshal.PtrToStringUTF8((IntPtr)guestCommandLine);
                string directory = Marshal.PtrToStringUTF8((IntPtr)workingDirectory);
                string command = Marshal.PtrToStringUTF8((IntPtr)commands);
                string[] arguments = string.IsNullOrEmpty(rawArguments)
                    ? Array.Empty<string>()
                    : Program.SplitCommandLine(rawArguments);

                NetworkAccessMode mode = networkMode switch
                {
                    0 => NetworkAccessMode.None,
                    2 => NetworkAccessMode.Full,
                    _ => NetworkAccessMode.Loopback,
                };

                Thread guestThread = new Thread(() =>
                {
                    AndroidHost.PinToPerformanceCores();
                    RunGuest(path, rawArguments, arguments, directory, command, EmulationBackendKind.Unicorn, new NetworkAccessPolicy(mode));
                })
                {
                    IsBackground = false,
                    Name = "BrovanGuestMain",
                };

                guestThread.Start();
                return StatusOk;
            }
            catch (Exception exception)
            {
                AndroidLog.Write(AndroidNative.LogError, $"[brovan_start] {exception}");
                Volatile.Write(ref _running, 0);
                return StatusFailed;
            }
        }

        [UnmanagedCallersOnly(EntryPoint = "brovan_is_running")]
        public static int IsRunning() => Volatile.Read(ref _running);

        [UnmanagedCallersOnly(EntryPoint = "brovan_send_command")]
        public static void SendCommand(byte* command)
        {
            Guard(() =>
            {
                // LogError buffers and only flushes every N writes; the CLI gets away with it because the
                // process exits, but an app process keeps the buffer alive forever and error_log.log stays
                // empty exactly when something has gone wrong.
                Utils.FlushLog();
                CommandReader.Instance.Post(Marshal.PtrToStringUTF8((IntPtr)command));
            }, nameof(SendCommand));
        }

        [UnmanagedCallersOnly(EntryPoint = "brovan_debug_pause")]
        public static void DebugPause() => Guard(Helpers.RequestDebuggerPause, nameof(DebugPause));

        [UnmanagedCallersOnly(EntryPoint = "brovan_debug_query")]
        public static int DebugQuery(byte* request, byte* buffer, int capacity)
        {
            if (buffer == null || capacity <= 0)
                return StatusInvalidArgument;

            try
            {
                string text = AndroidDebugQuery.Run(Marshal.PtrToStringUTF8((IntPtr)request));
                return WriteUtf8Records(text, buffer, capacity);
            }
            catch (Exception exception)
            {
                AndroidLog.Write(AndroidNative.LogError, $"[brovan_debug_query] {exception}");
                return StatusFailed;
            }
        }

        [UnmanagedCallersOnly(EntryPoint = "brovan_request_close")]
        public static void RequestClose() => Guard(HostEventQueue.RequestClose, nameof(RequestClose));

        [UnmanagedCallersOnly(EntryPoint = "brovan_request_repaint")]
        public static void RequestRepaint() => Guard(HostEventQueue.MarkRepaint, nameof(RequestRepaint));

        [UnmanagedCallersOnly(EntryPoint = "brovan_inject_pointer")]
        public static void InjectPointer(int action, int button, int x, int y, int buttons)
        {
            Guard(() => AndroidInput.Pointer((PointerAction)action, (PointerButton)button, x, y, (uint)buttons), nameof(InjectPointer));
        }

        [UnmanagedCallersOnly(EntryPoint = "brovan_inject_scroll")]
        public static void InjectScroll(int delta, int x, int y, int buttons)
        {
            Guard(() => AndroidInput.Scroll(delta, x, y, (uint)buttons), nameof(InjectScroll));
        }

        [UnmanagedCallersOnly(EntryPoint = "brovan_inject_key")]
        public static void InjectKey(int down, int virtualKey, int scanCode)
        {
            Guard(() => AndroidInput.Key(down != 0, (uint)virtualKey, (uint)scanCode), nameof(InjectKey));
        }

        [UnmanagedCallersOnly(EntryPoint = "brovan_inject_focus")]
        public static void InjectFocus(int focused)
        {
            Guard(() => AndroidInput.Focus(focused != 0), nameof(InjectFocus));
        }

        [UnmanagedCallersOnly(EntryPoint = "brovan_list_windows")]
        public static int ListWindows(byte* buffer, int capacity)
        {
            if (buffer == null || capacity <= 0)
                return StatusInvalidArgument;

            try
            {
                List<GuestWindowInfo> windows = AndroidGuestWindows.Enumerate();
                StringBuilder text = new StringBuilder();

                foreach (GuestWindowInfo window in windows)
                {
                    text.Append(window.Hwnd).Append('|')
                        .Append(window.Width).Append('|')
                        .Append(window.Height).Append('|')
                        .Append(window.Visible ? 1 : 0).Append('|')
                        .Append(window.Title.Replace('|', ' ').Replace('\n', ' '))
                        .Append('\n');
                }

                return WriteUtf8(text.ToString(), buffer, capacity);
            }
            catch (Exception exception)
            {
                AndroidLog.Write(AndroidNative.LogError, $"[brovan_list_windows] {exception}");
                return StatusFailed;
            }
        }

        [UnmanagedCallersOnly(EntryPoint = "brovan_select_window")]
        public static void SelectWindow(ulong hwnd)
        {
            Guard(() =>
            {
                AndroidGuestWindows.Select(hwnd);
                AndroidWinManager.Current?.InvalidateSurface();
                HostEventQueue.MarkRepaint();
            }, nameof(SelectWindow));
        }

        [UnmanagedCallersOnly(EntryPoint = "brovan_get_window_title")]
        public static int GetWindowTitle(byte* buffer, int capacity)
        {
            if (buffer == null || capacity <= 0)
                return StatusInvalidArgument;

            return WriteUtf8(AndroidHost.WindowTitle, buffer, capacity);
        }

        private static int ValidateEnvironment(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return StatusInvalidArgument;

            if (!File.Exists(path))
                return StatusBinaryNotFound;

            if (!Directory.Exists(GeneralHelper.WindowsLibsPath))
                return StatusMissingWindowsLibs;

            if (!Directory.Exists(Path.Combine(AppContext.BaseDirectory, WindowsImageImporter.RegistryDirectory)))
                return StatusMissingRegistry;

            if (!File.Exists(BinaryEmulator.ApiSetMapPath) && !TryGenerateApiSetMap())
                return StatusApiSetMapFailed;

            return StatusOk;
        }

        private static void RunGuest(string path, string rawArguments, string[] arguments, string workingDirectory, string command, EmulationBackendKind backend, NetworkAccessPolicy policy)
        {
            int reason = 0;
            try
            {
                if (_verbose)
                {
                    // The verbose path runs the command chain, then falls into a Console.ReadLine loop, so
                    // handing it nothing leaves the guest loaded at the debugger prompt. An app process has no
                    // stdin, so an unparked reader would spin returning null forever.
                    Console.SetIn(CommandReader.Instance);
                    EmulationMenu.EmulationMenu.RunEmulator(path, true, false, command,
                        rawArguments, arguments, policy, false, backend, workingDirectory);
                }
                else
                {
                    EmulationMenu.EmulationMenu.RunEmulator(path, true, true, command,
                        rawArguments, arguments, policy, true, backend, workingDirectory);
                }
            }
            catch (Exception exception)
            {
                reason = 1;
                AndroidLog.Write(AndroidNative.LogError, $"[brovan] Guest terminated with an exception: {exception}");
            }
            finally
            {
                Utils.FlushLog();
                Volatile.Write(ref _running, 0);
                NotifyExit(reason);
            }
        }

        private static void NotifyExit(int reason)
        {
            IntPtr sink = Volatile.Read(ref _exitSink);
            if (sink == IntPtr.Zero)
                return;

            ((delegate* unmanaged<int, void>)sink)(reason);
        }

        [UnmanagedCallersOnly(EntryPoint = "brovan_install_windows")]
        public static int InstallWindows(byte* media, int mediaDescriptor, int acceptLicense, int imageIndex)
        {
            if (Volatile.Read(ref _initialized) == 0)
                return StatusNotInitialized;

            if (Volatile.Read(ref _running) != 0)
                return StatusAlreadyRunning;

            if (acceptLicense == 0)
                return StatusInvalidArgument;

            WindowsSetupOptions options = new WindowsSetupOptions
            {
                Media = media == null ? null : Marshal.PtrToStringUTF8((IntPtr)media),
                MediaDescriptor = mediaDescriptor,
                LicenseAccepted = true,
                ImageIndex = imageIndex < 1 ? 1 : imageIndex,
            };

            bool installed = WindowsSetup.Install(AppContext.BaseDirectory, options,
                message => AndroidLog.Write(AndroidNative.LogInfo, message), null, ReportInstallProgress);

            return installed ? StatusOk : StatusFailed;
        }

        [UnmanagedCallersOnly(EntryPoint = "brovan_install_runtimes")]
        public static int InstallRuntimes(int acceptLicense)
        {
            if (Volatile.Read(ref _initialized) == 0)
                return StatusNotInitialized;

            if (Volatile.Read(ref _running) != 0)
                return StatusAlreadyRunning;

            if (acceptLicense == 0)
                return StatusInvalidArgument;

            bool installed = WindowsSetup.InstallRuntimes(AppContext.BaseDirectory, true,
                message => AndroidLog.Write(AndroidNative.LogInfo, message), null, ReportInstallProgress);

            return installed ? StatusOk : StatusFailed;
        }

        [UnmanagedCallersOnly(EntryPoint = "brovan_install_dxvk")]
        public static int InstallDxvk(byte* version)
        {
            if (Volatile.Read(ref _initialized) == 0)
                return StatusNotInitialized;

            if (Volatile.Read(ref _running) != 0)
                return StatusAlreadyRunning;

            bool installed = DxvkImporter.Import(AppContext.BaseDirectory,
                version == null ? null : Marshal.PtrToStringUTF8((IntPtr)version),
                message => AndroidLog.Write(AndroidNative.LogInfo, message), ReportInstallProgress);

            return installed ? StatusOk : StatusFailed;
        }

        private static void ReportInstallProgress(long filesDone, long filesTotal, long bytesDone, long bytesTotal)
        {
            IntPtr sink = Volatile.Read(ref _installProgressSink);
            if (sink == IntPtr.Zero)
                return;

            ((delegate* unmanaged<long, long, long, long, void>)sink)(filesDone, filesTotal, bytesDone, bytesTotal);
        }

        private static bool TryGenerateApiSetMap()
        {
            try
            {
                File.WriteAllBytes(BinaryEmulator.ApiSetMapPath, CrossGenerator.GenerateMap());
                return true;
            }
            catch (Exception exception)
            {
                AndroidLog.Write(AndroidNative.LogError, $"[brovan_start] ApiSetMap generation failed: {exception.Message}");
                return false;
            }
        }

        private static string Canonicalize(string directory)
        {
            IntPtr resolved = AndroidNative.RealPath(directory, IntPtr.Zero);
            if (resolved == IntPtr.Zero)
                return directory;

            try
            {
                return Marshal.PtrToStringUTF8(resolved) ?? directory;
            }
            finally
            {
                AndroidNative.Free(resolved);
            }
        }

        private static int WriteUtf8(string value, byte* buffer, int capacity)
        {
            Span<byte> destination = new Span<byte>(buffer, capacity);
            destination[0] = 0;

            value ??= string.Empty;
            if (Encoding.UTF8.GetByteCount(value) + 1 > capacity)
                return StatusInvalidArgument;

            int written = Encoding.UTF8.GetBytes(value.AsSpan(), destination);
            destination[written] = 0;
            return written;
        }

        private static int WriteUtf8Records(string value, byte* buffer, int capacity)
        {
            Span<byte> destination = new Span<byte>(buffer, capacity);
            destination[0] = 0;

            if (string.IsNullOrEmpty(value))
                return 0;

            // Debugger output is unbounded, so what does not fit is dropped at a record boundary rather
            // than failing the whole query.
            int length = value.Length;
            while (length > 0 && Encoding.UTF8.GetByteCount(value.AsSpan(0, length)) + 1 > capacity)
            {
                int newline = value.LastIndexOf('\n', Math.Max(length - 2, 0));
                length = newline < 0 ? 0 : newline + 1;
            }

            if (length <= 0)
                return 0;

            int written = Encoding.UTF8.GetBytes(value.AsSpan(0, length), destination);
            destination[written] = 0;
            return written;
        }

        private static void Guard(Action action, string name)
        {
            try
            {
                action();
            }
            catch (Exception exception)
            {
                AndroidLog.Write(AndroidNative.LogError, $"[brovan_{name}] {exception}");
            }
        }

        private sealed class CommandReader : TextReader
        {
            public static readonly CommandReader Instance = new CommandReader();

            private readonly BlockingCollection<string> _pending = new BlockingCollection<string>();

            public void Post(string command)
            {
                if (!string.IsNullOrEmpty(command))
                    _pending.Add(command);
            }

            public override string ReadLine() => _pending.Take();

            public override int Read() => -1;
        }
    }
}
