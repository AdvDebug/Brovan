using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Formats.Tar;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Brovan.Core.Emulation;
using Brovan.Core.Helpers;
using Microsoft.Win32.SafeHandles;
using static Brovan.Core.Helpers.BinaryHelpers;
using static Brovan.Core.Helpers.Utils;

namespace Brovan
{
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public uint cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    internal class NativeWinImports
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UIntPtr VirtualQuery(IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, UIntPtr dwLength);

        [DllImport("kernel32.dll")]
        public static extern bool GetProcessMitigationPolicy(IntPtr hProcess, uint MitigationPolicy, out uint Buffer, UIntPtr Length);

        [DllImport("kernelbase.dll", SetLastError = true)]
        public static extern IntPtr GetModuleHandleA(string Library);

        [DllImport("kernelbase.dll", SetLastError = true)]
        public static extern IntPtr LoadLibraryA(string Library);

        [DllImport("kernelbase.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string Function);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessW(string lpApplicationName, StringBuilder lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetConsoleScreenBufferInfo(IntPtr hConsoleOutput, out ConsoleScreenBufferInfo lpConsoleScreenBufferInfo);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool ReadConsoleOutputCharacterW(IntPtr hConsoleOutput, StringBuilder lpCharacter, uint nLength, int dwReadCoord, out uint lpNumberOfCharsRead);

        [DllImport("kernel32.dll")]
        public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out int lpMode);

        [DllImport("kernel32.dll")]
        public static extern bool SetConsoleMode(IntPtr hConsoleHandle, int dwMode);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern SafeFileHandle CreateFileW(string FileName, uint DesiredAccess, FileShare ShareMode, IntPtr SecurityAttributes, FileMode CreationDisposition, uint FlagsAndAttributes, IntPtr TemplateFile);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateHardLinkW(string lpFileName, string lpExistingFileName, IntPtr lpSecurityAttributes);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateSymbolicLinkW(string lpSymlinkFileName, string lpTargetFileName, int dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DeviceIoControl(SafeFileHandle Handle, uint IoControlCode, IntPtr InBuffer, int InBufferSize, byte[] OutBuffer, int OutBufferSize, out int BytesReturned, IntPtr Overlapped);

        [DllImport("user32.dll")]
        public static extern int GetSystemMetrics(int nIndex);

        [DllImport("user32.dll")]
        public static extern int GetSystemMetricsForDpi(int nIndex, uint dpi);
    }

    internal class NativeUnixImports
    {
        [DllImport("libc", EntryPoint = "link", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern int Link(string oldpath, string newpath);

        [DllImport("libc", EntryPoint = "symlink", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern int Symlink(string oldpath, string newpath);
    }

    internal class GeneralHelper
    {
        public static bool IsWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        public static bool IsLinux = RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        public static string WindowsLibsPath = Path.Combine(AppContext.BaseDirectory, "WindowsLibs");

        public static string System32
        {
            get
            {
                if (IsWindows)
                {
                    return "C:\\Windows\\System32";
                }
                else
                {
                    return Path.Combine(AppContext.BaseDirectory, "WindowsLibs");
                }
            }
        }

        public static string SysWOW64
        {
            get
            {
                if (IsWindows)
                {
                    return "C:\\Windows\\SysWOW64";
                }
                else
                {
                    return Path.Combine(AppContext.BaseDirectory, "WindowsLibs\\SysWOW64");
                }
            }
        }

        private delegate IntPtr GetPebPtr();

        public static string GetWindowsLibPath(string Library, bool IsWow64 = false, BinaryArchitecture Arch = BinaryArchitecture.x64)
        {
            if (string.IsNullOrWhiteSpace(Library))
                return string.Empty;

            if (!Library.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                Library += ".dll";

            string BasePath;

            if (IsWindows)
            {
                string WindowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

                if (Environment.Is64BitOperatingSystem)
                {
                    if (IsWow64 || Arch == BinaryArchitecture.x86)
                    {
                        // x86 view on x64 OS
                        BasePath = Path.Combine(WindowsDir, "SysWOW64");
                    }
                    else
                    {
                        // native x64
                        BasePath = Path.Combine(WindowsDir, "System32");
                    }
                }
                else
                {
                    // 32-bit OS
                    BasePath = Path.Combine(WindowsDir, "System32");
                }
            }
            else
            {
                // Linux / non-Windows: use shipped Windows DLLs
                BasePath = (IsWow64 || Arch == BinaryArchitecture.x86)
                    ? Path.Combine(WindowsLibsPath, "SysWOW64")
                    : WindowsLibsPath;
            }

            string Result = Path.Combine(BasePath, Library);

            if (!File.Exists(Result))
                PrintHighlight($"[-] Windows library not found: {Result}", true);

            return Result;
        }

        public static bool DumpApiSetMap()
        {
            try
            {
                const uint MEM_COMMIT = 0x1000;
                const uint MEM_RESERVE = 0x2000;
                const uint PAGE_READWRITE = 0x04;
                const uint PAGE_EXECUTE_READ = 0x20;
                const uint MEM_COMMIT_STATE = 0x1000;
                const uint PAGE_NOACCESS = 0x01;
                const uint PAGE_GUARD = 0x100;

                byte[] StubX64 = { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0xC3 };
                byte[] StubX86 = { 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0xC3 };
                bool IsX64 = IntPtr.Size == 8;
                byte[] Stub = IsX64 ? StubX64 : StubX86;

                IntPtr AllocatedMemory = NativeWinImports.VirtualAlloc(IntPtr.Zero, (UIntPtr)Stub.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (AllocatedMemory == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualAlloc failed while allocating memory for the PEB-retrieval code.");

                Marshal.Copy(Stub, 0, AllocatedMemory, Stub.Length);

                if (!NativeWinImports.VirtualProtect(AllocatedMemory, (UIntPtr)Stub.Length, PAGE_EXECUTE_READ, out _))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualProtect failed while changing protection for the PEB-retrieval code.");

                var PEB = Marshal.GetDelegateForFunctionPointer<GetPebPtr>(AllocatedMemory);
                IntPtr ApiSetMapPtr = PEB() + (IsX64 ? 0x68 : 0x38);

                unsafe
                {
                    IntPtr ApiSetMap = (IntPtr)(IsX64 ? *(ulong*)ApiSetMapPtr : *(uint*)ApiSetMapPtr);

                    if (NativeWinImports.VirtualQuery(ApiSetMap, out var mbi0, (UIntPtr)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) == UIntPtr.Zero)
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualQuery failed");

                    IntPtr AllocationBase = mbi0.AllocationBase;

                    long TotalSize = 0;
                    IntPtr Cursor = AllocationBase;

                    while (true)
                    {
                        if (NativeWinImports.VirtualQuery(Cursor, out var mbi, (UIntPtr)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) == UIntPtr.Zero)
                            break;

                        if (mbi.AllocationBase != AllocationBase)
                            break;

                        int RegionSize = (int)(long)mbi.RegionSize;
                        if (RegionSize <= 0)
                            break;

                        TotalSize += RegionSize;
                        Cursor = IntPtr.Add(mbi.BaseAddress, RegionSize);
                    }

                    if (TotalSize <= 0 || TotalSize > 128L * 1024 * 1024)
                        throw new InvalidOperationException("Invalid allocation size");

                    byte[] Dump = new byte[TotalSize];

                    Cursor = AllocationBase;
                    long Offset = 0;

                    while (Offset < TotalSize)
                    {
                        if (NativeWinImports.VirtualQuery(Cursor, out var mbi, (UIntPtr)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) == UIntPtr.Zero)
                            break;

                        if (mbi.AllocationBase != AllocationBase)
                            break;

                        int RegionSize = (int)(long)mbi.RegionSize;
                        if (RegionSize <= 0)
                            break;

                        bool Readable = mbi.State == MEM_COMMIT_STATE &&
                                        (mbi.Protect & PAGE_GUARD) == 0 &&
                                        (mbi.Protect & PAGE_NOACCESS) == 0;

                        if (Readable)
                            Marshal.Copy(mbi.BaseAddress, Dump, (int)Offset, RegionSize);

                        Offset += RegionSize;
                        Cursor = IntPtr.Add(mbi.BaseAddress, RegionSize);
                    }

                    File.WriteAllBytes(BinaryEmulator.ApiSetMapPath, Dump);
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        public static bool RunSilent(string FileName, string Arguments)
        {
            try
            {
                using var p = new Process();
                p.StartInfo.FileName = FileName;
                p.StartInfo.Arguments = Arguments;
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.CreateNoWindow = true;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.RedirectStandardError = true;

                p.Start();
                p.WaitForExit();
                return p.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }

        public static bool VerifyRegDump(string RegDir, bool SilentFinalMsg)
        {
            string[] Files =
            {
                Path.Combine(RegDir, "SYSTEM"),
                Path.Combine(RegDir, "SECURITY"),
                Path.Combine(RegDir, "SOFTWARE"),
                Path.Combine(RegDir, "HARDWARE"),
                Path.Combine(RegDir, "SAM"),
            };

            bool Ok = true;

            foreach (string FilePath in Files)
            {
                if (!File.Exists(FilePath))
                {
                    PrintHighlight($"[-] Missing registry file: {FilePath}");
                    Ok = false;
                    continue;
                }

                try
                {
                    long Size = new FileInfo(FilePath).Length;
                    if (Size <= 0)
                    {
                        PrintHighlight($"[-] Empty registry file: {FilePath}");
                        Ok = false;
                    }
                }
                catch
                {
                    PrintHighlight($"[-] Failed to validate registry file: {FilePath}");
                    Ok = false;
                }
            }

            if (!SilentFinalMsg)
            {
                if (Ok)
                    PrintHighlight("[*] Registry dump is ready.");
                else
                    PrintHighlight("[-] Registry dump is incomplete.");
            }

            return Ok;
        }

        public static bool DumpReg(string RegDir)
        {
            try
            {
                Directory.CreateDirectory(RegDir);

                RunSilent("reg", $"save HKLM\\SYSTEM \"{Path.Combine(RegDir, "SYSTEM")}\" /y");
                RunSilent("reg", $"save HKLM\\SECURITY \"{Path.Combine(RegDir, "SECURITY")}\" /y");
                RunSilent("reg", $"save HKLM\\SOFTWARE \"{Path.Combine(RegDir, "SOFTWARE")}\" /y");
                RunSilent("reg", $"save HKLM\\HARDWARE \"{Path.Combine(RegDir, "HARDWARE")}\" /y");
                RunSilent("reg", $"save HKLM\\SAM \"{Path.Combine(RegDir, "SAM")}\" /y");

                return true;
            }
            catch
            {
                return false;
            }
        }

        public static bool RunAdminWait(string Arguments, out int ExitCode)
        {
            ExitCode = -1;

            string ExePath = Environment.ProcessPath ?? string.Empty;
            if (string.IsNullOrEmpty(ExePath))
                return false;

            ProcessStartInfo StartInfo = new ProcessStartInfo
            {
                FileName = ExePath,
                Arguments = Arguments,
                UseShellExecute = true,
                Verb = "runas"
            };

            try
            {
                using Process p = Process.Start(StartInfo);
                if (p == null)
                    return false;

                p.WaitForExit();
                ExitCode = p.ExitCode;
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// returns whether the current proccess is running as an admin.
        /// </summary>
        /// <returns>returns true if running as an admin, otherwise false.</returns>
        public static bool IsAdmin()
        {
            if (!IsWindows)
                return false;

#pragma warning disable
            using WindowsIdentity Identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal Principal = new WindowsPrincipal(Identity);
            return Principal.IsInRole(WindowsBuiltInRole.Administrator);
#pragma warning restore
        }

        internal static string QuoteCommandLineArg(string Arg)
        {
            if (Arg == null)
                return "\"\"";
            bool NeedsQuotes = Arg.Length == 0 || Arg.Any(Ch => char.IsWhiteSpace(Ch) || Ch == '"');
            if (!NeedsQuotes)
                return Arg;

            StringBuilder Builder = new StringBuilder();
            Builder.Append('"');

            int Backslashes = 0;
            foreach (char Ch in Arg)
            {
                if (Ch == '\\')
                {
                    Backslashes++;
                    continue;
                }

                if (Ch == '"')
                {
                    Builder.Append('\\', Backslashes * 2 + 1);
                    Builder.Append('"');
                    Backslashes = 0;
                    continue;
                }

                if (Backslashes != 0)
                {
                    Builder.Append('\\', Backslashes);
                    Backslashes = 0;
                }

                Builder.Append(Ch);
            }

            if (Backslashes != 0)
                Builder.Append('\\', Backslashes * 2);

            Builder.Append('"');
            return Builder.ToString();
        }

        private static string BuildCommandLine(string ExePath, string[] Args)
        {
            StringBuilder Builder = new StringBuilder();
            Builder.Append(QuoteCommandLineArg(ExePath));

            for (int i = 0; i < Args.Length; i++)
            {
                Builder.Append(' ');
                Builder.Append(QuoteCommandLineArg(Args[i]));
            }

            return Builder.ToString();
        }

        /// <summary>
        /// Restarts the current process with CFG disabled.
        /// </summary>
        /// <param name="KeepAlive">Keeps the parent alive/waiting till the process finishes.</param>
        /// <returns>returns true if the process was restarted, otherwise false.</returns>
        public static bool RestartProcessWithCfgDisabled(bool KeepAlive)
        {
            if (!IsWindows)
                return false;

            string ExePath = Environment.ProcessPath ?? string.Empty;
            if (string.IsNullOrEmpty(ExePath))
                return false;

            string[] Args = Environment.GetCommandLineArgs().Skip(1).ToArray();
            string CommandLine = BuildCommandLine(ExePath, Args);

            const uint ExtendedStartupInfoPresent = 0x00080000;
            const int ProcThreadAttributeMitigationPolicy = 0x00020007;

            ulong MitigationPolicy = 0x00000002UL << 40;
            ulong MitigationPolicy2 = 0x00000002UL << 8;

            IntPtr AttributeListSize = IntPtr.Zero;
            NativeWinImports.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref AttributeListSize);

            if (AttributeListSize == IntPtr.Zero)
                return false;

            IntPtr AttributeList = IntPtr.Zero;
            IntPtr MitigationPtr = IntPtr.Zero;
            bool AttributeListInitialized = false;

            try
            {
                AttributeList = Marshal.AllocHGlobal(AttributeListSize);

                if (!NativeWinImports.InitializeProcThreadAttributeList(AttributeList, 1, 0, ref AttributeListSize))
                    return false;

                AttributeListInitialized = true;

                STARTUPINFOEX StartupInfoEx = new STARTUPINFOEX();
                StartupInfoEx.StartupInfo.cb = (uint)Marshal.SizeOf<STARTUPINFOEX>();
                StartupInfoEx.lpAttributeList = AttributeList;

                bool AttributeOk = false;

                MitigationPtr = Marshal.AllocHGlobal(sizeof(ulong) * 2);
                Marshal.WriteInt64(MitigationPtr, unchecked((long)MitigationPolicy));
                Marshal.WriteInt64(IntPtr.Add(MitigationPtr, sizeof(ulong)), unchecked((long)MitigationPolicy2));

                AttributeOk = NativeWinImports.UpdateProcThreadAttribute(AttributeList, 0, (IntPtr)ProcThreadAttributeMitigationPolicy, MitigationPtr, (IntPtr)(sizeof(ulong) * 2), IntPtr.Zero, IntPtr.Zero);

                if (!AttributeOk)
                {
                    Marshal.WriteInt64(MitigationPtr, unchecked((long)MitigationPolicy));
                    AttributeOk = NativeWinImports.UpdateProcThreadAttribute(AttributeList, 0, (IntPtr)ProcThreadAttributeMitigationPolicy, MitigationPtr, (IntPtr)sizeof(ulong), IntPtr.Zero, IntPtr.Zero);
                }

                if (!AttributeOk)
                    return false;

                string PrevEnv = Environment.GetEnvironmentVariable("BROVAN_CFG_DISABLED");
                Environment.SetEnvironmentVariable("BROVAN_CFG_DISABLED", "1");

                try
                {
                    PROCESS_INFORMATION ProcessInfo;
                    bool Created = NativeWinImports.CreateProcessW(null, new StringBuilder(CommandLine), IntPtr.Zero, IntPtr.Zero, false, ExtendedStartupInfoPresent, IntPtr.Zero, Environment.CurrentDirectory, ref StartupInfoEx, out ProcessInfo);
                    if (!Created)
                    {
                        if (PrevEnv == null)
                            Environment.SetEnvironmentVariable("BROVAN_CFG_DISABLED", null);
                        else
                            Environment.SetEnvironmentVariable("BROVAN_CFG_DISABLED", PrevEnv);

                        return false;
                    }

                    if (ProcessInfo.hThread != IntPtr.Zero)
                        NativeWinImports.CloseHandle(ProcessInfo.hThread);

                    if (KeepAlive)
                    {
                        NativeWinImports.WaitForSingleObject(ProcessInfo.hProcess, 0xFFFFFFFF);
                    }

                    if (ProcessInfo.hProcess != IntPtr.Zero)
                        NativeWinImports.CloseHandle(ProcessInfo.hProcess);
                }
                catch
                {
                    if (PrevEnv == null)
                        Environment.SetEnvironmentVariable("BROVAN_CFG_DISABLED", null);
                    else
                        Environment.SetEnvironmentVariable("BROVAN_CFG_DISABLED", PrevEnv);

                    return false;
                }
            }
            finally
            {
                if (AttributeList != IntPtr.Zero)
                {
                    if (AttributeListInitialized)
                    {
                        try
                        {
                            NativeWinImports.DeleteProcThreadAttributeList(AttributeList);
                        }
                        catch
                        {

                        }
                    }
                    Marshal.FreeHGlobal(AttributeList);
                }

                if (MitigationPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(MitigationPtr);
            }

            Environment.Exit(0);
            return true;
        }

        /// <summary>
        /// Appends a single byte using the escaped guest-console representation.
        /// </summary>
        private static void AppendEscapedConsoleByte(StringBuilder Builder, byte Value)
        {
            switch (Value)
            {
                case 0x09:
                    Builder.Append('\t');
                    break;

                case 0x0A:
                    Builder.Append('\n');
                    break;

                case 0x0D:
                    Builder.Append("\\r");
                    break;

                case 0x1B:
                    Builder.Append("\\x1B");
                    break;

                case 0x08:
                    Builder.Append("\\b");
                    break;

                case 0x07:
                    Builder.Append("\\a");
                    break;

                default:
                    if (Value < 0x20 || Value == 0x7F)
                        Builder.Append("\\x").Append(Value.ToString("X2"));
                    else
                        Builder.Append((char)Value);
                    break;
            }
        }

        /// <summary>
        /// Appends a byte range using the escaped guest-console representation.
        /// </summary>
        private static void AppendEscapedConsoleBytes(StringBuilder Builder, ReadOnlySpan<byte> Data, int Start, int Length)
        {
            int End = Start + Length;
            for (int i = Start; i < End; i++)
                AppendEscapedConsoleByte(Builder, Data[i]);
        }

        /// <summary>
        /// Checks whether a CSI sequence is safe to forward in light escaped console mode.
        /// </summary>
        private static bool IsSafeLightConsoleCsiSequence(ReadOnlySpan<byte> Data, int Start, int Length)
        {
            if (Length < 3 || Data[Start] != 0x1B || Data[Start + 1] != (byte)'[')
                return false;

            byte Final = Data[Start + Length - 1];
            bool IsSgr = Final == (byte)'m';
            bool IsCursorMotion =
                Final == (byte)'A' || Final == (byte)'B' || Final == (byte)'C' || Final == (byte)'D' ||
                Final == (byte)'E' || Final == (byte)'F' || Final == (byte)'G' || Final == (byte)'H' ||
                Final == (byte)'f' || Final == (byte)'s' || Final == (byte)'u';

            if (!IsSgr && !IsCursorMotion)
                return false;

            for (int i = Start + 2; i < Start + Length - 1; i++)
            {
                byte Value = Data[i];

                if (IsSgr && Value == (byte)':')
                    continue;

                if (!((Value >= (byte)'0' && Value <= (byte)'9') || Value == (byte)';'))
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Attempts to find the end of a guest-provided virtual terminal sequence.
        /// </summary>
        private static bool TryGetConsoleEscapeSequenceLength(ReadOnlySpan<byte> Data, int Start, out int Length)
        {
            Length = 1;

            if (Start + 1 >= Data.Length)
                return true;

            byte Type = Data[Start + 1];

            if (Type == (byte)'[')
            {
                for (int i = Start + 2; i < Data.Length; i++)
                {
                    byte Value = Data[i];
                    if (Value >= 0x40 && Value <= 0x7E)
                    {
                        Length = i - Start + 1;
                        return true;
                    }
                }

                Length = Data.Length - Start;
                return false;
            }

            if (Type == (byte)']' || Type == (byte)'P' || Type == (byte)'^' || Type == (byte)'_' || Type == (byte)'X')
            {
                for (int i = Start + 2; i < Data.Length; i++)
                {
                    if (Data[i] == 0x07)
                    {
                        Length = i - Start + 1;
                        return true;
                    }

                    if (Data[i] == 0x1B && i + 1 < Data.Length && Data[i + 1] == (byte)'\\')
                    {
                        Length = i - Start + 2;
                        return true;
                    }
                }

                Length = Data.Length - Start;
                return false;
            }

            Length = 2;
            return true;
        }

        /// <summary>
        /// Writes guest-controlled console bytes while allowing safe styling and cursor-positioning escape sequences.
        /// </summary>
        private static void WriteLightEscapedConsoleBytes(ReadOnlySpan<byte> Data, Stream Output)
        {
            StringBuilder Builder = new StringBuilder(Data.Length);

            for (int i = 0; i < Data.Length; i++)
            {
                byte Value = Data[i];

                if (Value == 0x0D)
                {
                    Builder.Append('\r');
                    continue;
                }

                if (Value != 0x1B)
                {
                    AppendEscapedConsoleByte(Builder, Value);
                    continue;
                }

                TryGetConsoleEscapeSequenceLength(Data, i, out int SequenceLength);

                if (IsSafeLightConsoleCsiSequence(Data, i, SequenceLength))
                    Builder.Append(Encoding.ASCII.GetString(Data.Slice(i, SequenceLength)));
                else
                    AppendEscapedConsoleBytes(Builder, Data, i, SequenceLength);

                i += SequenceLength - 1;
            }

            byte[] Escaped = Encoding.UTF8.GetBytes(Builder.ToString());
            Output.Write(Escaped, 0, Escaped.Length);
        }

        /// <summary>
        /// Writes guest-controlled console bytes with terminal control characters escaped.
        /// </summary>
        private static void WriteEscapedConsoleBytes(ReadOnlySpan<byte> Data, Stream Output)
        {
            StringBuilder Builder = new StringBuilder(Data.Length);

            for (int i = 0; i < Data.Length; i++)
                AppendEscapedConsoleByte(Builder, Data[i]);

            byte[] Escaped = Encoding.UTF8.GetBytes(Builder.ToString());
            Output.Write(Escaped, 0, Escaped.Length);
        }

        private static Stream Stdout = null;

        /// <summary>
        /// Writes guest-controlled console output to the host console using the selected safety policy.
        /// </summary>
        public static void ConsoleWrite(ReadOnlySpan<byte> Data, Stream Output, GuestConsoleOutputMode Mode)
        {
            if (Data.Length == 0 || Output == null)
                return;

            switch (Mode)
            {
                case GuestConsoleOutputMode.Suppressed:
                    return;

                case GuestConsoleOutputMode.Raw:
                    Output.Write(Data);
                    Output.Flush();
                    return;

                case GuestConsoleOutputMode.LightEscaped:
                    WriteLightEscapedConsoleBytes(Data, Output);
                    Output.Flush();
                    return;

                case GuestConsoleOutputMode.Escaped:
                default:
                    WriteEscapedConsoleBytes(Data, Output);
                    Output.Flush();
                    return;
            }
        }

        /// <summary>
        /// Writes guest-controlled console output to the host console using the selected safety policy.
        /// </summary>
        public static void ConsoleWrite(byte[] Data, Stream Output, GuestConsoleOutputMode Mode)
        {
            if (Data == null)
                return;

            ConsoleWrite(Data.AsSpan(), Output, Mode);
        }

        /// <summary>
        /// Writes guest-controlled console output to the host standard output stream using the configured safety policy.
        /// </summary>
        public static void ConsoleWrite(byte[] Data, GuestConsoleOutputMode Mode)
        {
            if (Data == null)
                return;

            if (Stdout == null)
                Stdout = Console.OpenStandardOutput();

            ConsoleWrite(Data.AsSpan(), Stdout, Mode);
        }

        /// <summary>
        /// Writes guest-controlled console output to the host standard output stream using the configured safety policy.
        /// </summary>
        public static void ConsoleWrite(ReadOnlySpan<byte> Data, GuestConsoleOutputMode Mode)
        {
            if (Stdout == null)
                Stdout = Console.OpenStandardOutput();

            ConsoleWrite(Data, Stdout, Mode);
        }

        /// <summary>
        /// Cross-platform IO helper used to translate emulated paths into host paths.
        /// </summary>
        public static class IO
        {
            private static readonly object WindowsLibsIndexLock = new();
            private static Dictionary<string, string> WindowsLibsFileIndex;

            private static readonly object DriveMapLock = new();
            private static readonly Dictionary<char, string> DriveMappings = new();
            private static readonly HashSet<string> AllowedRoots = new(IsWindows ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
            private static readonly Dictionary<string, string> LinuxMountMappings = new(StringComparer.Ordinal);

            public static string VirtualFileSystemRoot = Path.Combine(AppContext.BaseDirectory, "VirtualFS");
            public static string LinuxVirtualFileSystemRoot = Path.Combine(VirtualFileSystemRoot, "Linux");
            public static string LinuxCurrentDirectory = "/";
            public static string DefaultDriveLetter = "C";

            public static bool Wow64FileRedirect;

            private const string System32WindowsPath = "C:\\Windows\\System32";
            private const string SysWow64WindowsPath = "C:\\Windows\\SysWOW64";
            private const string SysnativeWindowsPath = "C:\\Windows\\Sysnative";

            private static readonly string[] Wow64RedirectExclusions =
            {
                "catroot", "catroot2", "driverstore", "drivers\\etc", "logfiles", "spool"
            };

            /// <summary>
            /// Initializes the default sandbox drive mappings and allowed IO roots.
            /// </summary>
            static IO()
            {
                // Keep the emulator sandboxed by default.
                EnsureDriveMapping('C', Path.Combine(VirtualFileSystemRoot, "C"));
                EnsureDriveMapping('E', Path.Combine(VirtualFileSystemRoot, "E"));
                EnsureLinuxMountMapping("/", LinuxVirtualFileSystemRoot);

                try
                {
                    Directory.CreateDirectory(VirtualFileSystemRoot);
                    Directory.CreateDirectory(LinuxVirtualFileSystemRoot);
                    EnsureLinuxBaseFilesystem(LinuxVirtualFileSystemRoot);
                }
                catch (Exception ex)
                {
                    Utils.LogError($"[IO] Failed to create the Virtual File System: {ex.Message}");
                }

                RefreshAllowedRoots();
            }

            /// <summary>
            /// Creates a small Linux root filesystem skeleton for programs that inspect common system files.
            /// Existing files are left untouched.
            /// </summary>
            /// <param name="Root">host directory mapped to the emulated Linux root.</param>
            private static void EnsureLinuxBaseFilesystem(string Root)
            {
                if (string.IsNullOrWhiteSpace(Root))
                    return;

                string[] Directories =
                {
                    "bin",
                    "boot",
                    "dev",
                    "etc",
                    "home",
                    "home/brovan",
                    "lib",
                    "lib64",
                    "media",
                    "mnt",
                    "opt",
                    "proc",
                    "root",
                    "run",
                    "sbin",
                    "srv",
                    "sys",
                    "tmp",
                    "usr",
                    "usr/bin",
                    "usr/lib",
                    "usr/lib64",
                    "usr/local",
                    "usr/local/bin",
                    "usr/sbin",
                    "var",
                    "var/cache",
                    "var/lib",
                    "var/log",
                    "var/run",
                    "var/tmp"
                };

                foreach (string DirectoryPath in Directories)
                    CreateLinuxDirectoryIfMissing(Root, DirectoryPath);

                WriteLinuxTextFileIfMissing(Root, "etc/passwd",
                    "root:x:0:0:root:/root:/bin/sh\n" +
                    "brovan:x:1000:1000:Brovan User:/home/brovan:/bin/sh\n" +
                    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n");

                WriteLinuxTextFileIfMissing(Root, "etc/group",
                    "root:x:0:\n" +
                    "brovan:x:1000:brovan\n" +
                    "nogroup:x:65534:\n");

                WriteLinuxTextFileIfMissing(Root, "etc/shadow",
                    "root:*:19700:0:99999:7:::\n" +
                    "brovan:*:19700:0:99999:7:::\n" +
                    "nobody:*:19700:0:99999:7:::\n");

                WriteLinuxTextFileIfMissing(Root, "etc/gshadow",
                    "root:*::\n" +
                    "brovan:*::brovan\n" +
                    "nogroup:*::\n");

                WriteLinuxTextFileIfMissing(Root, "etc/hostname", "brovan\n");

                WriteLinuxTextFileIfMissing(Root, "etc/hosts",
                    "127.0.0.1\tlocalhost\n" +
                    "127.0.1.1\tbrovan\n" +
                    "::1\tlocalhost ip6-localhost ip6-loopback\n" +
                    "ff02::1\tip6-allnodes\n" +
                    "ff02::2\tip6-allrouters\n");

                WriteLinuxTextFileIfMissing(Root, "etc/resolv.conf",
                    "nameserver 1.1.1.1\n" +
                    "nameserver 8.8.8.8\n" +
                    "options edns0 trust-ad\n");

                WriteLinuxTextFileIfMissing(Root, "etc/nsswitch.conf",
                    "passwd: files\n" +
                    "group: files\n" +
                    "shadow: files\n" +
                    "hosts: files dns\n" +
                    "networks: files\n" +
                    "protocols: files\n" +
                    "services: files\n" +
                    "ethers: files\n" +
                    "rpc: files\n");

                string OsRelease =
                    "NAME=\"Brovan Linux\"\n" +
                    "PRETTY_NAME=\"Brovan Linux\"\n" +
                    "ID=brovan\n" +
                    "VERSION_ID=\"1.0\"\n" +
                    "HOME_URL=\"https://github.com/AdvDebug/Brovan\"\n" +
                    "SUPPORT_URL=\"https://github.com/AdvDebug/Brovan\"\n" +
                    "BUG_REPORT_URL=\"https://github.com/AdvDebug/Brovan\"\n";

                WriteLinuxTextFileIfMissing(Root, "etc/os-release", OsRelease);
                WriteLinuxTextFileIfMissing(Root, "usr/lib/os-release", OsRelease);

                WriteLinuxTextFileIfMissing(Root, "etc/issue", "Brovan Linux \\n \\l\n");
                WriteLinuxTextFileIfMissing(Root, "etc/locale.conf", "LANG=C.UTF-8\n");
                WriteLinuxTextFileIfMissing(Root, "etc/profile", "export PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin\n");
                WriteLinuxTextFileIfMissing(Root, "etc/shells", "/bin/sh\n/bin/bash\n/usr/bin/sh\n/usr/bin/bash\n");
                WriteLinuxTextFileIfMissing(Root, "etc/fstab", "# <file system> <mount point> <type> <options> <dump> <pass>\n");
                WriteLinuxTextFileIfMissing(Root, "etc/mtab", "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\nsysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n");
                WriteLinuxTextFileIfMissing(Root, "etc/machine-id", CreateStableMachineId(Root) + "\n");

                WriteLinuxTextFileIfMissing(Root, "etc/protocols",
                    "ip 0 IP\n" +
                    "icmp 1 ICMP\n" +
                    "tcp 6 TCP\n" +
                    "udp 17 UDP\n" +
                    "ipv6 41 IPv6\n" +
                    "raw 255 RAW\n");

                WriteLinuxTextFileIfMissing(Root, "etc/services",
                    "tcpmux 1/tcp\n" +
                    "echo 7/tcp\n" +
                    "echo 7/udp\n" +
                    "domain 53/tcp\n" +
                    "domain 53/udp\n" +
                    "http 80/tcp www\n" +
                    "https 443/tcp\n");
            }

            /// <summary>
            /// Creates a Linux VFS directory if it is missing.
            /// </summary>
            /// <param name="Root">host directory mapped to the emulated Linux root.</param>
            /// <param name="RelativePath">linux-style relative directory path.</param>
            private static void CreateLinuxDirectoryIfMissing(string Root, string RelativePath)
            {
                string HostPath = CombineLinuxRelativePath(Root, RelativePath);
                if (string.IsNullOrWhiteSpace(HostPath))
                    return;

                Directory.CreateDirectory(HostPath);
            }

            /// <summary>
            /// Writes a Linux VFS text file when no file is already present.
            /// </summary>
            /// <param name="Root">host directory mapped to the emulated Linux root.</param>
            /// <param name="RelativePath">linux-style relative file path.</param>
            /// <param name="Content">file content to write.</param>
            private static void WriteLinuxTextFileIfMissing(string Root, string RelativePath, string Content)
            {
                string HostPath = CombineLinuxRelativePath(Root, RelativePath);
                if (string.IsNullOrWhiteSpace(HostPath) || File.Exists(HostPath) || Directory.Exists(HostPath))
                    return;

                string Parent = Path.GetDirectoryName(HostPath);
                if (!string.IsNullOrWhiteSpace(Parent))
                    Directory.CreateDirectory(Parent);

                File.WriteAllText(HostPath, Content, new UTF8Encoding(false));
            }

            private sealed class UbuntuRootfsPendingLink
            {
                public string EntryPath;
                public string LinkName;
                public TarEntryType EntryType;
                public UnixFileMode Mode;
                public DateTimeOffset ModificationTime;
            }

            private static string GetUbuntuBaseRootfsUrl(BinaryArchitecture Architecture)
            {
                return Architecture switch
                {
                    BinaryArchitecture.x64 => "https://cdimage.ubuntu.com/ubuntu-base/releases/26.04/release/ubuntu-base-26.04-base-amd64.tar.gz",
                    _ => null,
                };
            }

            private static bool IsUbuntuBaseRootfsInstalled()
            {
                string[] RequiredFiles =
                {
                    Path.Combine(LinuxVirtualFileSystemRoot, "lib64", "ld-linux-x86-64.so.2"),
                    Path.Combine(LinuxVirtualFileSystemRoot, "bin", "bash"),
                    Path.Combine(LinuxVirtualFileSystemRoot, "usr", "bin", "bash"),
                };

                for (int i = 0; i < RequiredFiles.Length; i++)
                {
                    if (File.Exists(RequiredFiles[i]))
                        return true;
                }

                return false;
            }
            public static bool EnsureUbuntuBaseRootfs(BinaryArchitecture Architecture)
            {
                if (IsUbuntuBaseRootfsInstalled())
                    return true;

                string RootfsUrl = GetUbuntuBaseRootfsUrl(Architecture);
                if (string.IsNullOrWhiteSpace(RootfsUrl))
                {
                    Utils.LogError($"[IO] Ubuntu Base rootfs is not available for architecture '{Architecture}'.");
                    return false;
                }

                try
                {
                    Directory.CreateDirectory(LinuxVirtualFileSystemRoot);
                    PrintHighlight("[+] Downloading Ubuntu Base rootfs...", true);

                    using HttpClient Client = new HttpClient();
                    Client.Timeout = TimeSpan.FromMinutes(30);

                    using HttpResponseMessage Response = Client.GetAsync(RootfsUrl, HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult();
                    Response.EnsureSuccessStatusCode();

                    using Stream ResponseStream = Response.Content.ReadAsStreamAsync().GetAwaiter().GetResult();
                    using GZipStream GzipStream = new GZipStream(ResponseStream, CompressionMode.Decompress, leaveOpen: false);
                    using TarReader Reader = new TarReader(GzipStream);

                    List<UbuntuRootfsPendingLink> PendingLinks = new();
                    Dictionary<string, UbuntuRootfsPendingLink> PendingLinksByArchivePath = new(StringComparer.Ordinal);
                    TarEntry Entry;

                    while ((Entry = Reader.GetNextEntry()) != null)
                    {
                        string NormalizedEntryPath = NormalizeUbuntuRootfsArchivePath(Entry.Name);
                        if (string.IsNullOrWhiteSpace(NormalizedEntryPath))
                            continue;

                        string HostPath = ResolveUbuntuRootfsHostPath(NormalizedEntryPath);
                        if (string.IsNullOrWhiteSpace(HostPath))
                            continue;


                        if (Entry.EntryType == TarEntryType.Directory)
                        {
                            DeletePathIfExists(HostPath);
                            Directory.CreateDirectory(HostPath);
                            ApplyTarMetadata(HostPath, Entry, true);
                            continue;
                        }

                        if (Entry.EntryType == TarEntryType.SymbolicLink || Entry.EntryType == TarEntryType.HardLink)
                        {

                            UbuntuRootfsPendingLink PendingLink = new UbuntuRootfsPendingLink
                            {
                                EntryPath = HostPath,
                                LinkName = Entry.LinkName,
                                EntryType = Entry.EntryType,
                                Mode = Entry.Mode,
                                ModificationTime = Entry.ModificationTime,
                            };

                            PendingLinks.Add(PendingLink);
                            PendingLinksByArchivePath[NormalizedEntryPath] = PendingLink;
                            continue;
                        }

                        if (Entry.EntryType != TarEntryType.RegularFile)
                            continue;

                        if (Entry.DataStream == null)
                            continue;

                        string Parent = Path.GetDirectoryName(HostPath);
                        if (!string.IsNullOrWhiteSpace(Parent))
                            Directory.CreateDirectory(Parent);

                        DeletePathIfExists(HostPath);

                        using (FileStream Output = new FileStream(HostPath, FileMode.Create, FileAccess.Write, FileShare.None))
                        {
                            Entry.DataStream.CopyTo(Output);
                        }

                        ApplyTarMetadata(HostPath, Entry, false);
                    }

                    List<UbuntuRootfsPendingLink> PendingHardLinks = PendingLinks.Where(Link => Link.EntryType == TarEntryType.HardLink).ToList();
                    while (PendingHardLinks.Count > 0)
                    {
                        bool Progress = false;
                        List<UbuntuRootfsPendingLink> Remaining = new();

                        foreach (UbuntuRootfsPendingLink Link in PendingHardLinks)
                        {
                            if (TryMaterializeRootfsHardLink(Link, PendingLinksByArchivePath))
                            {
                                Progress = true;
                                continue;
                            }

                            Remaining.Add(Link);
                        }

                        if (!Progress)
                        {
                            PendingHardLinks = Remaining;
                            break;
                        }

                        PendingHardLinks = Remaining;
                    }

                    if (PendingHardLinks.Count > 0)
                        Utils.LogError($"[IO] {PendingHardLinks.Count} rootfs hardlink(s) could not be resolved after retries.");

                    List<UbuntuRootfsPendingLink> PendingSymlinks = PendingLinks.Where(Link => Link.EntryType == TarEntryType.SymbolicLink).ToList();
                    while (PendingSymlinks.Count > 0)
                    {
                        bool Progress = false;
                        List<UbuntuRootfsPendingLink> Remaining = new();

                        foreach (UbuntuRootfsPendingLink Link in PendingSymlinks)
                        {
                            if (TryMaterializeRootfsSymlink(Link, PendingLinksByArchivePath))
                            {
                                Progress = true;
                                continue;
                            }

                            Remaining.Add(Link);
                        }

                        if (!Progress)
                        {
                            PendingSymlinks = Remaining;
                            break;
                        }

                        PendingSymlinks = Remaining;
                    }

                    if (PendingSymlinks.Count > 0)
                        Utils.LogError($"[IO] {PendingSymlinks.Count} rootfs symlink(s) could not be resolved after retries.");

                    if (!IsUbuntuBaseRootfsInstalled())
                        Utils.LogError("[IO] Ubuntu Base rootfs download completed, but the expected interpreter file was still not found.");

                    return IsUbuntuBaseRootfsInstalled();
                }
                catch (Exception ex)
                {
                    Utils.LogError($"[IO] Failed to download or extract Ubuntu Base rootfs: {ex.Message}");
                    return false;
                }
            }

            private static bool CreateHardLinkPortable(string LinkPath, string ExistingPath)
            {
                try
                {
                    if (IsWindows)
                        return NativeWinImports.CreateHardLinkW(LinkPath, ExistingPath, IntPtr.Zero);

                    return NativeUnixImports.Link(ExistingPath, LinkPath) == 0;
                }
                catch (Exception ex)
                {
                    Utils.LogError($"[IO] Failed to create hardlink '{LinkPath}' -> '{ExistingPath}': {ex.Message}");
                    return false;
                }
            }

            private static bool CreateSymbolicLinkPortable(string LinkPath, string TargetPath, bool IsDirectory)
            {
                try
                {
                    if (IsWindows)
                    {
                        const int SYMBOLIC_LINK_FLAG_DIRECTORY = 0x1;
                        const int SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE = 0x2;
                        int Flags = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
                        if (IsDirectory)
                            Flags |= SYMBOLIC_LINK_FLAG_DIRECTORY;

                        return NativeWinImports.CreateSymbolicLinkW(LinkPath, TargetPath, Flags);
                    }

                    return NativeUnixImports.Symlink(TargetPath, LinkPath) == 0;
                }
                catch (Exception ex)
                {
                    Utils.LogError($"[IO] Failed to create symlink '{LinkPath}' -> '{TargetPath}': {ex.Message}");
                    return false;
                }
            }

            private static void ApplyTarMetadata(string TargetPath, TarEntry Entry, bool IsDirectory)
            {
                if (Entry == null)
                    return;

                ApplyTarMetadata(TargetPath, Entry.Mode, Entry.ModificationTime, IsDirectory);
            }

            private static void ApplyTarMetadata(string TargetPath, UnixFileMode Mode, DateTimeOffset ModificationTime, bool IsDirectory)
            {
                if (string.IsNullOrWhiteSpace(TargetPath))
                    return;

                try
                {
                    if (ModificationTime != default)
                        File.SetLastWriteTimeUtc(TargetPath, ModificationTime.UtcDateTime);
                }
                catch
                {
                }

                try
                {
                    FileSystemInfo Info = IsDirectory ? new DirectoryInfo(TargetPath) : new FileInfo(TargetPath);
                    Info.UnixFileMode = Mode;
                }
                catch
                {
                }
            }
            private static bool TryMaterializeRootfsHardLink(UbuntuRootfsPendingLink Link, IReadOnlyDictionary<string, UbuntuRootfsPendingLink> PendingLinksByArchivePath)
            {
                if (Link == null || string.IsNullOrWhiteSpace(Link.EntryPath) || string.IsNullOrWhiteSpace(Link.LinkName))
                    return false;

                if (!TryResolveUbuntuRootfsArchivePath(Link.LinkName, PendingLinksByArchivePath, out string ResolvedArchivePath))
                {
                    Utils.LogError($"[IO] Failed to resolve hardlink target '{Link.LinkName}' for '{Link.EntryPath}'.");
                    return false;
                }

                string HardLinkTarget = ResolveUbuntuRootfsHostPath(ResolvedArchivePath);
                if (string.IsNullOrWhiteSpace(HardLinkTarget) || !File.Exists(HardLinkTarget))
                {
                    Utils.LogError($"[IO] Failed to resolve hardlink target '{Link.LinkName}' for '{Link.EntryPath}'.");
                    return false;
                }

                string HardLinkParent = Path.GetDirectoryName(Link.EntryPath);
                if (!string.IsNullOrWhiteSpace(HardLinkParent))
                    Directory.CreateDirectory(HardLinkParent);

                DeletePathIfExists(Link.EntryPath);

                if (!CreateHardLinkPortable(Link.EntryPath, HardLinkTarget))
                {
                    Utils.LogError($"[IO] Failed to create hardlink '{Link.EntryPath}' -> '{Link.LinkName}'.");
                    return false;
                }

                ApplyTarMetadata(Link.EntryPath, Link.Mode, Link.ModificationTime, false);
                return true;
            }

            private static bool TryMaterializeRootfsSymlink(UbuntuRootfsPendingLink Link, IReadOnlyDictionary<string, UbuntuRootfsPendingLink> PendingLinksByArchivePath)
            {
                string ResolvedTarget = ResolveUbuntuRootfsLinkTargetHostPath(Link.EntryPath, Link.LinkName, PendingLinksByArchivePath);
                if (string.IsNullOrWhiteSpace(ResolvedTarget) || (!File.Exists(ResolvedTarget) && !Directory.Exists(ResolvedTarget)))
                {
                    Utils.LogError($"[IO] Failed to resolve symlink target '{Link.LinkName}' for '{Link.EntryPath}'.");
                    return false;
                }

                string Parent = Path.GetDirectoryName(Link.EntryPath);
                if (!string.IsNullOrWhiteSpace(Parent))
                    Directory.CreateDirectory(Parent);

                string EntryFullPath = Path.GetFullPath(Link.EntryPath);
                string TargetFullPath = Path.GetFullPath(ResolvedTarget);

                StringComparison Comparison = IsWindows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
                if (string.Equals(TargetFullPath, EntryFullPath, Comparison))
                {
                    bool IsDirectory = Directory.Exists(ResolvedTarget) && !File.Exists(ResolvedTarget);
                    ApplyTarMetadata(Link.EntryPath, Link.Mode, Link.ModificationTime, IsDirectory);
                    return true;
                }

                bool EntryIsDirectory = Directory.Exists(Link.EntryPath) && !File.Exists(Link.EntryPath);
                bool TargetIsDirectory = Directory.Exists(ResolvedTarget) && !File.Exists(ResolvedTarget);

                if (EntryIsDirectory && TargetIsDirectory)
                {
                    if (ArePathsNested(EntryFullPath, TargetFullPath))
                    {
                        Utils.LogError($"[IO] Refusing to flatten recursive directory symlink '{Link.EntryPath}' -> '{Link.LinkName}'.");
                        return false;
                    }

                    if (!TryCopyDirectoryRecursive(Link.EntryPath, ResolvedTarget, Link.Mode, Link.ModificationTime))
                    {
                        Utils.LogError($"[IO] Failed to merge existing directory '{Link.EntryPath}' into symlink target '{ResolvedTarget}'.");
                        return false;
                    }
                }

                DeletePathIfExists(Link.EntryPath);

                if (TargetIsDirectory)
                {
                    if (!TryCopyDirectoryRecursive(ResolvedTarget, Link.EntryPath, Link.Mode, Link.ModificationTime))
                    {
                        Utils.LogError($"[IO] Failed to flatten symlink directory '{Link.EntryPath}' -> '{Link.LinkName}'.");
                        return false;
                    }

                    return true;
                }

                try
                {
                    File.Copy(ResolvedTarget, Link.EntryPath, true);
                    ApplyTarMetadata(Link.EntryPath, Link.Mode, Link.ModificationTime, false);
                    return true;
                }
                catch (Exception ex)
                {
                    Utils.LogError($"[IO] Failed to flatten symlink '{Link.EntryPath}' -> '{Link.LinkName}': {ex.Message}");
                    return false;
                }
            }

            private static bool ArePathsNested(string FirstPath, string SecondPath)
            {
                if (string.IsNullOrWhiteSpace(FirstPath) || string.IsNullOrWhiteSpace(SecondPath))
                    return false;

                string FirstFullPath = Path.GetFullPath(FirstPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                string SecondFullPath = Path.GetFullPath(SecondPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

                StringComparison Comparison = IsWindows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
                if (string.Equals(FirstFullPath, SecondFullPath, Comparison))
                    return true;
                return SecondFullPath.StartsWith(FirstFullPath + Path.DirectorySeparatorChar, Comparison) ||
                       SecondFullPath.StartsWith(FirstFullPath + Path.AltDirectorySeparatorChar, Comparison) ||
                       FirstFullPath.StartsWith(SecondFullPath + Path.DirectorySeparatorChar, Comparison) ||
                       FirstFullPath.StartsWith(SecondFullPath + Path.AltDirectorySeparatorChar, Comparison);
            }

            private static bool TryCopyDirectoryRecursive(string SourceDirectory, string DestinationDirectory, UnixFileMode Mode, DateTimeOffset ModificationTime)
            {
                if (string.IsNullOrWhiteSpace(SourceDirectory) || string.IsNullOrWhiteSpace(DestinationDirectory))
                    return false;

                try
                {
                    string SourceFullPath = Path.GetFullPath(SourceDirectory);
                    string DestinationFullPath = Path.GetFullPath(DestinationDirectory);

                    StringComparison Comparison = IsWindows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
                    if (string.Equals(SourceFullPath, DestinationFullPath, Comparison))
                    {
                        Directory.CreateDirectory(DestinationFullPath);
                        ApplyTarMetadata(DestinationFullPath, Mode, ModificationTime, true);
                        return true;
                    }

                    Directory.CreateDirectory(DestinationFullPath);

                    foreach (string DirectoryPath in Directory.EnumerateDirectories(SourceFullPath, "*", SearchOption.AllDirectories))
                    {
                        string RelativePath = Path.GetRelativePath(SourceFullPath, DirectoryPath);
                        string DestinationPath = Path.Combine(DestinationFullPath, RelativePath);
                        Directory.CreateDirectory(DestinationPath);

                        try
                        {
                            DirectoryInfo SourceInfo = new DirectoryInfo(DirectoryPath);
                            DirectoryInfo DestinationInfo = new DirectoryInfo(DestinationPath);
                            if (SourceInfo.Exists)
                            {
                                if (SourceInfo.LastWriteTimeUtc != default)
                                    Directory.SetLastWriteTimeUtc(DestinationPath, SourceInfo.LastWriteTimeUtc);

                                DestinationInfo.UnixFileMode = SourceInfo.UnixFileMode;
                            }
                        }
                        catch
                        {
                        }
                    }

                    foreach (string FilePath in Directory.EnumerateFiles(SourceFullPath, "*", SearchOption.AllDirectories))
                    {
                        string RelativePath = Path.GetRelativePath(SourceFullPath, FilePath);
                        string DestinationPath = Path.Combine(DestinationFullPath, RelativePath);
                        string DestinationParent = Path.GetDirectoryName(DestinationPath);
                        if (!string.IsNullOrWhiteSpace(DestinationParent))
                            Directory.CreateDirectory(DestinationParent);

                        File.Copy(FilePath, DestinationPath, true);

                        try
                        {
                            FileInfo SourceInfo = new FileInfo(FilePath);
                            FileInfo DestinationInfo = new FileInfo(DestinationPath);
                            if (SourceInfo.Exists)
                            {
                                if (SourceInfo.LastWriteTimeUtc != default)
                                    File.SetLastWriteTimeUtc(DestinationPath, SourceInfo.LastWriteTimeUtc);

                                DestinationInfo.UnixFileMode = SourceInfo.UnixFileMode;
                            }
                        }
                        catch
                        {
                        }
                    }

                    ApplyTarMetadata(DestinationFullPath, Mode, ModificationTime, true);
                    return true;
                }
                catch (Exception ex)
                {
                    Utils.LogError($"[IO] Failed to copy directory '{SourceDirectory}' to '{DestinationDirectory}': {ex.Message}");
                    return false;
                }
            }
            private static string ResolveUbuntuRootfsArchiveLinkTarget(string LinkEntryPath, string LinkName)
            {
                if (string.IsNullOrWhiteSpace(LinkEntryPath) || string.IsNullOrWhiteSpace(LinkName))
                    return null;

                string NormalizedLinkName = LinkName.Replace('\\', '/').Trim();
                if (NormalizedLinkName.Length == 0)
                    return null;

                string RelativeEntryPath = NormalizeUbuntuRootfsArchivePath(LinkEntryPath);
                if (RelativeEntryPath == null)
                    return null;

                string CombinedPath = NormalizedLinkName.StartsWith("/", StringComparison.Ordinal)
                    ? NormalizedLinkName
                    : Path.Combine(Path.GetDirectoryName(RelativeEntryPath) ?? string.Empty, NormalizedLinkName).Replace('\\', '/');

                return NormalizeUbuntuRootfsArchivePath(CombinedPath);
            }

            private static bool TryResolveUbuntuRootfsArchivePath(string PathValue, IReadOnlyDictionary<string, UbuntuRootfsPendingLink> PendingLinksByArchivePath, out string ResolvedPath)
            {
                ResolvedPath = NormalizeUbuntuRootfsArchivePath(PathValue);
                if (ResolvedPath == null)
                    return false;

                if (ResolvedPath.Length == 0)
                    return true;

                HashSet<string> VisitedPaths = new(StringComparer.Ordinal);

                while (true)
                {
                    if (!VisitedPaths.Add(ResolvedPath))
                        return false;

                    string[] Parts = ResolvedPath.Split('/', StringSplitOptions.RemoveEmptyEntries);
                    bool AppliedLink = false;

                    for (int PrefixLength = Parts.Length; PrefixLength >= 1; PrefixLength--)
                    {
                        string Prefix = string.Join('/', Parts.Take(PrefixLength));
                        if (!PendingLinksByArchivePath.TryGetValue(Prefix, out UbuntuRootfsPendingLink PendingLink) || PendingLink.EntryType != TarEntryType.SymbolicLink)
                            continue;

                        string ResolvedPrefix = ResolveUbuntuRootfsArchiveLinkTarget(Prefix, PendingLink.LinkName);
                        if (string.IsNullOrWhiteSpace(ResolvedPrefix))
                            return false;

                        if (PrefixLength == Parts.Length)
                            ResolvedPath = ResolvedPrefix;
                        else
                        {
                            string Suffix = string.Join('/', Parts.Skip(PrefixLength));
                            ResolvedPath = string.IsNullOrWhiteSpace(Suffix) ? ResolvedPrefix : $"{ResolvedPrefix}/{Suffix}";
                            ResolvedPath = NormalizeUbuntuRootfsArchivePath(ResolvedPath);
                            if (ResolvedPath == null)
                                return false;
                        }

                        AppliedLink = true;
                        break;
                    }

                    if (!AppliedLink)
                        return true;
                }
            }
            private static string ResolveUbuntuRootfsLinkTargetHostPath(string LinkEntryPath, string LinkName, IReadOnlyDictionary<string, UbuntuRootfsPendingLink> PendingLinksByArchivePath)
            {
                string ResolvedArchiveTarget = ResolveUbuntuRootfsArchiveLinkTarget(LinkEntryPath, LinkName);
                if (ResolvedArchiveTarget == null)
                    return null;

                if (!TryResolveUbuntuRootfsArchivePath(ResolvedArchiveTarget, PendingLinksByArchivePath, out string FullyResolvedArchivePath))
                    return null;

                return ResolveUbuntuRootfsHostPath(FullyResolvedArchivePath);
            }

            private static string NormalizeUbuntuRootfsArchivePath(string PathValue)
            {
                if (string.IsNullOrWhiteSpace(PathValue))
                    return null;

                string Normalized = PathValue.Replace('\\', '/').Trim();
                if (Normalized.Length == 0)
                    return null;

                while (Normalized.StartsWith("./", StringComparison.Ordinal))
                    Normalized = Normalized.Substring(2);

                while (Normalized.StartsWith("/", StringComparison.Ordinal))
                    Normalized = Normalized.Substring(1);

                if (Normalized.Length == 0)
                    return string.Empty;

                List<string> Parts = new();
                foreach (string Part in Normalized.Split('/', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (Part == ".")
                        continue;

                    if (Part == "..")
                    {
                        if (Parts.Count == 0)
                            return null;

                        Parts.RemoveAt(Parts.Count - 1);
                        continue;
                    }

                    Parts.Add(Part);
                }

                if (Parts.Count == 0)
                    return string.Empty;

                return string.Join('/', Parts);
            }

            private static string ResolveUbuntuRootfsHostPath(string RelativePath)
            {
                string Normalized = NormalizeUbuntuRootfsArchivePath(RelativePath);
                if (Normalized == null)
                    return null;

                string Root = Path.GetFullPath(LinuxVirtualFileSystemRoot);
                string Combined = string.IsNullOrEmpty(Normalized)
                    ? Root
                    : Path.GetFullPath(Path.Combine(Root, Normalized.Replace('/', Path.DirectorySeparatorChar)));

                StringComparison Comparison = IsWindows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
                string RootPrefix = Root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                if (!(string.Equals(Combined, RootPrefix, Comparison) || Combined.StartsWith(RootPrefix + Path.DirectorySeparatorChar, Comparison)))
                    return null;

                return Combined;
            }

            private static void DeletePathIfExists(string PathValue)
            {
                if (string.IsNullOrWhiteSpace(PathValue))
                    return;

                try
                {
                    if (File.Exists(PathValue))
                    {
                        File.Delete(PathValue);
                        return;
                    }

                    if (Directory.Exists(PathValue))
                    {
                        try
                        {
                            FileAttributes Attributes = File.GetAttributes(PathValue);
                            if ((Attributes & FileAttributes.ReparsePoint) != 0)
                            {
                                Directory.Delete(PathValue);
                                return;
                            }
                        }
                        catch
                        {
                        }

                        Directory.Delete(PathValue, true);
                    }
                }
                catch
                {
                }
            }

            /// <summary>
            /// Creates a deterministic machine-id for the Linux VFS root.
            /// </summary>
            /// <param name="Root">host directory mapped to the emulated Linux root.</param>
            /// <returns>returns a 32-character lowercase hexadecimal machine-id.</returns>
            private static string CreateStableMachineId(string Root)
            {
                byte[] Hash = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(Root)));
                StringBuilder Builder = new();

                for (int i = 0; i < 16; i++)
                    Builder.Append(Hash[i].ToString("x2"));

                return Builder.ToString();
            }

            /// <summary>
            /// Sets a host directory mapping for an emulated drive letter.
            /// </summary>
            /// <param name="DriveLetter">drive letter to map (for example 'C').</param>
            /// <param name="HostRoot">host directory root for the drive.</param>
            public static void SetDriveMapping(char DriveLetter, string HostRoot)
            {
                EnsureDriveMapping(DriveLetter, HostRoot);
                RefreshAllowedRoots();
            }

            /// <summary>
            /// Sets a host directory mapping for an emulated linux mount point.
            /// </summary>
            /// <param name="MountPoint">linux mount point to map (for example "/" or "/tmp").</param>
            /// <param name="HostRoot">host directory root for the mount point.</param>
            public static void SetLinuxMountMapping(string MountPoint, string HostRoot)
            {
                EnsureLinuxMountMapping(MountPoint, HostRoot);
                RefreshAllowedRoots();
            }

            /// <summary>
            /// Resolves an emulated path into an absolute host path that can be used for real IO.
            /// </summary>
            /// <param name="EmulatedPath">emulated path to resolve.</param>
            /// <param name="Format">binary format of the emulated process (used to apply platform rules).</param>
            /// <param name="CreateDirectories">whether to create parent directories for the resolved path.</param>
            /// <param name="PreserveFinalLink">whether to preserve the final filesystem link so the caller can inspect it.</param>
            /// <returns>returns the resolved host path, or null if the path is not allowed or cannot be resolved.</returns>
            /// <remarks>
            /// This method shouldn't be called when resolving for writes, for resolving writes use <see cref="ResolveVirtualHostPath"/> instead.
            /// </remarks>
            public static string ResolveHostPath(string EmulatedPath, BinaryFormat Format, bool CreateDirectories = false, bool PreserveFinalLink = false)
            {
                if (string.IsNullOrWhiteSpace(EmulatedPath))
                    return null;

                string Raw = EmulatedPath.Trim().TrimEnd('\0');
                if (Raw.Length == 0)
                    return null;

                if (Format == BinaryFormat.ELF)
                    return ResolveLinuxHostPath(Raw, CreateDirectories, PreserveFinalLink);

                // Non-Windows binaries keep normal host semantics.
                if (Format != BinaryFormat.PE)
                    return GetNativeFullPath(Raw, CreateDirectories);

                string RawWinPath = Raw.Replace('/', '\\').Trim();

                if (RawWinPath.StartsWith("\\KnownDlls\\", StringComparison.OrdinalIgnoreCase))
                {
                    string KnownDllLeaf = Path.GetFileName(RawWinPath);
                    if (!string.IsNullOrEmpty(KnownDllLeaf))
                        RawWinPath = @"C:\Windows\System32\\" + KnownDllLeaf;
                }
                else if (RawWinPath.StartsWith("\\KnownDlls32\\", StringComparison.OrdinalIgnoreCase))
                {
                    string KnownDllLeaf = Path.GetFileName(RawWinPath);
                    if (!string.IsNullOrEmpty(KnownDllLeaf))
                        RawWinPath = @"C:\Windows\SysWOW64\\" + KnownDllLeaf;
                }

                if (!LooksLikeAbsoluteWindowsPath(RawWinPath) && !RawWinPath.StartsWith("\\", StringComparison.Ordinal))
                {
                    string LeafOnly = Path.GetFileName(RawWinPath);
                    if (!string.IsNullOrEmpty(LeafOnly) && string.Equals(LeafOnly, RawWinPath, StringComparison.OrdinalIgnoreCase))
                    {
                        if (Wow64FileRedirect)
                        {
                            string Wow64LeafPath = TryResolveFromWindowsLibsRelative(Path.Combine(WindowsLibsPath, "SysWOW64"), LeafOnly);
                            if (!string.IsNullOrEmpty(Wow64LeafPath))
                                return Wow64LeafPath;
                        }

                        string LeafLibPath = TryResolveFromWindowsLibsByLeaf(LeafOnly);
                        if (!string.IsNullOrEmpty(LeafLibPath))
                            return LeafLibPath;
                    }
                }

                string WinPath = NormalizeWindowsEmulatedPath(RawWinPath);
                if (string.IsNullOrEmpty(WinPath))
                    return null;

                WinPath = ApplyWow64FileRedirect(WinPath);

                string VirtualPath = ResolveVirtualHostPathInternal(WinPath, CreateDirectories, PreserveFinalLink);
                if (!string.IsNullOrEmpty(VirtualPath))
                {
                    if (CreateDirectories || File.Exists(VirtualPath) || Directory.Exists(VirtualPath))
                        return VirtualPath;
                }

                // this resolve function be called for writes, so i think this is secure when reading or checking files/directories.
                if (IsWindows)
                    return GetNativeFullPath(WinPath, CreateDirectories);

                string WindowsLibMapped = TryResolveFromWindowsLibs(WinPath);
                if (!string.IsNullOrEmpty(WindowsLibMapped))
                    return WindowsLibMapped;

                return VirtualPath;
            }

            /// <summary>
            /// Resolves an emulated path directly into the virtual filesystem.
            /// </summary>
            /// <param name="EmulatedPath">emulated path to resolve.</param>
            /// <param name="Format">binary format of the emulated process.</param>
            /// <param name="CreateDirectories">whether to create parent directories for the resolved path.</param>
            /// <returns>returns the resolved virtual path, or null if the path cannot be mapped into the sandbox.</returns>
            public static string ResolveVirtualHostPath(string EmulatedPath, BinaryFormat Format, bool CreateDirectories = false)
            {
                if (string.IsNullOrWhiteSpace(EmulatedPath))
                    return null;

                string Raw = EmulatedPath.Trim().TrimEnd('\0');
                if (Raw.Length == 0)
                    return null;

                if (Format == BinaryFormat.ELF)
                    return ResolveLinuxVirtualHostPath(Raw, CreateDirectories);

                if (Format != BinaryFormat.PE)
                    return GetNativeFullPath(Raw, CreateDirectories);

                string WinPath = NormalizeWindowsEmulatedPath(Raw);
                if (string.IsNullOrEmpty(WinPath))
                    return null;

                WinPath = ApplyWow64FileRedirect(WinPath);
                return ResolveVirtualHostPathInternal(WinPath, CreateDirectories);
            }

            private static string NormalizeWindowsEmulatedPath(string Raw)
            {
                if (string.IsNullOrWhiteSpace(Raw))
                    return null;

                string WinPath = Raw.Replace('/', '\\').Trim();

                if (WinPath.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase) ||
                    WinPath.StartsWith("\\\\.\\", StringComparison.OrdinalIgnoreCase))
                {
                    WinPath = WinPath.Substring(4);
                }
                else if (WinPath.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
                {
                    WinPath = WinPath.Substring(4);
                }
                else if (WinPath.StartsWith("\\DosDevices\\", StringComparison.OrdinalIgnoreCase))
                {
                    WinPath = WinPath.Substring("\\DosDevices\\".Length);
                }

                string Trimmed = WinPath.TrimStart('\\');

                static bool EqualsIgnoreCase(string A, string B) =>
                    string.Equals(A, B, StringComparison.OrdinalIgnoreCase);

                static void SplitFirst(string Value, out string First, out string Rest)
                {
                    int Index = Value.IndexOf('\\');
                    if (Index < 0)
                    {
                        First = Value;
                        Rest = string.Empty;
                        return;
                    }

                    First = Value.Substring(0, Index);
                    Rest = Value.Substring(Index + 1);
                }

                SplitFirst(Trimmed, out string First, out string Rest);

                if (EqualsIgnoreCase(First, "System32"))
                {
                    Rest = Rest.TrimStart('\\');
                    WinPath = string.IsNullOrEmpty(Rest) ? @"C:\Windows\System32" : $@"C:\Windows\System32\{Rest}";
                }
                else if (EqualsIgnoreCase(First, "SysWow64"))
                {
                    Rest = Rest.TrimStart('\\');
                    WinPath = string.IsNullOrEmpty(Rest) ? @"C:\Windows\SysWOW64" : $@"C:\Windows\SysWOW64\{Rest}";
                }
                else if (EqualsIgnoreCase(First, "Windows"))
                {
                    SplitFirst(Rest, out string Second, out string Rest2);

                    if (EqualsIgnoreCase(Second, "System32"))
                    {
                        Rest2 = Rest2.TrimStart('\\');
                        WinPath = string.IsNullOrEmpty(Rest2) ? @"C:\Windows\System32" : $@"C:\Windows\System32\{Rest2}";
                    }
                    else if (EqualsIgnoreCase(Second, "SysWow64"))
                    {
                        Rest2 = Rest2.TrimStart('\\');
                        WinPath = string.IsNullOrEmpty(Rest2) ? @"C:\Windows\SysWOW64" : $@"C:\Windows\SysWOW64\{Rest2}";
                    }
                }

                if (WinPath.Length >= 2 && char.IsLetter(WinPath[0]) && WinPath[1] == ':')
                {
                    if (WinPath.Length == 2)
                        WinPath += "\\";
                    else if (WinPath[2] != '\\')
                        WinPath = WinPath.Substring(0, 2) + "\\" + WinPath.Substring(2).TrimStart('\\');
                }
                else if (!LooksLikeAbsoluteWindowsPath(WinPath))
                {
                    WinPath = DefaultDriveLetter + ":\\" + WinPath.TrimStart('\\');
                }
                else if (WinPath.StartsWith("\\", StringComparison.Ordinal))
                {
                    WinPath = DefaultDriveLetter + ":" + WinPath;
                }

                return CanonicalizeWindowsAbsolutePath(WinPath);
            }

            /// <summary>
            /// Applies WOW64 file-system redirection to a canonical absolute Windows path.
            /// </summary>
            private static string ApplyWow64FileRedirect(string WinPath)
            {
                if (!Wow64FileRedirect || string.IsNullOrEmpty(WinPath))
                    return WinPath;

                if (WinPath.Equals(SysnativeWindowsPath, StringComparison.OrdinalIgnoreCase))
                    return System32WindowsPath;

                if (WinPath.StartsWith(SysnativeWindowsPath + "\\", StringComparison.OrdinalIgnoreCase))
                    return System32WindowsPath + "\\" + WinPath.Substring(SysnativeWindowsPath.Length + 1);

                if (WinPath.Equals(System32WindowsPath, StringComparison.OrdinalIgnoreCase))
                    return SysWow64WindowsPath;

                if (!WinPath.StartsWith(System32WindowsPath + "\\", StringComparison.OrdinalIgnoreCase))
                    return WinPath;

                string Rest = WinPath.Substring(System32WindowsPath.Length + 1);
                foreach (string Excluded in Wow64RedirectExclusions)
                {
                    if (Rest.Equals(Excluded, StringComparison.OrdinalIgnoreCase) ||
                        Rest.StartsWith(Excluded + "\\", StringComparison.OrdinalIgnoreCase))
                        return WinPath;
                }

                return SysWow64WindowsPath + "\\" + Rest;
            }

            private static string ResolveVirtualHostPathInternal(string WinPath, bool CreateDirectories, bool PreserveFinalLink = false)
            {
                if (string.IsNullOrWhiteSpace(WinPath))
                    return null;

                if (WinPath.Length < 2 || WinPath[1] != ':')
                    return null;

                char Drive = char.ToUpperInvariant(WinPath[0]);
                string DriveRelative = WinPath.Substring(2).TrimStart('\\');

                string Root = GetDriveRoot(Drive);
                if (string.IsNullOrEmpty(Root))
                    return null;

                string HostPath = CombineWindowsRelativePath(Root, DriveRelative);
                return GetSandboxedFullPath(HostPath, CreateDirectories, PreserveFinalLink);
            }

            /// <summary>
            /// Canonicalizes an absolute DOS-style Windows path by collapsing "." and ".." segments.
            /// The result always stays anchored to the original drive root.
            /// </summary>
            /// <param name="WinPath">absolute windows path to canonicalize.</param>
            /// <returns>returns the canonical absolute windows path, or null if the path is invalid.</returns>
            private static string CanonicalizeWindowsAbsolutePath(string WinPath)
            {
                if (string.IsNullOrWhiteSpace(WinPath))
                    return null;

                string Normalized = WinPath.Replace('/', '\\');

                if (Normalized.Length < 2 || !char.IsLetter(Normalized[0]) || Normalized[1] != ':')
                    return null;

                char Drive = char.ToUpperInvariant(Normalized[0]);
                string Relative = Normalized.Substring(2).TrimStart('\\');

                List<string> Parts = new();

                if (!string.IsNullOrEmpty(Relative))
                {
                    foreach (string Part in Relative.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        if (Part == ".")
                            continue;

                        if (Part == "..")
                        {
                            if (Parts.Count > 0)
                                Parts.RemoveAt(Parts.Count - 1);

                            continue;
                        }

                        Parts.Add(Part);
                    }
                }

                if (Parts.Count == 0)
                    return Drive + ":\\";

                return Drive + ":\\" + string.Join("\\", Parts);
            }

            /// <summary>
            /// Reads a file from the emulated filesystem.
            /// </summary>
            /// <param name="Path">path to read.</param>
            /// <param name="Format">binary format of the emulated process.</param>
            /// <returns>returns the file bytes, or null if the file doesn't exist or cannot be accessed.</returns>
            public static byte[] ReadFile(string Path, BinaryFormat Format)
            {
                string HostPath = ResolveHostPath(Path, Format);
                if (string.IsNullOrEmpty(HostPath))
                    return null;

                if (!File.Exists(HostPath))
                    return null;

                return File.ReadAllBytes(HostPath);
            }

            /// <summary>
            /// returns whether a file exists in the emulated filesystem.
            /// </summary>
            /// <param name="Path">path to check.</param>
            /// <param name="Format">binary format of the emulated process.</param>
            /// <returns>returns true if the file exists, otherwise false.</returns>
            public static bool FileExists(string Path, BinaryFormat Format)
            {
                string HostPath = ResolveHostPath(Path, Format);
                if (string.IsNullOrEmpty(HostPath))
                    return false;

                return File.Exists(HostPath);
            }

            /// <summary>
            /// returns whether a directory exists in the emulated filesystem.
            /// </summary>
            /// <param name="Path">path to check.</param>
            /// <param name="Format">binary format of the emulated process.</param>
            /// <returns>returns true if the directory exists, otherwise false.</returns>
            public static bool DirectoryExists(string Path, BinaryFormat Format)
            {
                string HostPath = ResolveHostPath(Path, Format);
                if (string.IsNullOrEmpty(HostPath))
                    return false;

                return Directory.Exists(HostPath);
            }

            /// <summary>
            /// Creates a directory inside the emulated virtual filesystem.
            /// </summary>
            /// <param name="Path">directory path to create.</param>
            /// <param name="Format">binary format of the emulated process.</param>
            /// <returns>returns true if the directory exists or was created successfully, otherwise false.</returns>
            public static bool CreateDirectory(string Path, BinaryFormat Format)
            {
                string HostPath = ResolveVirtualHostPath(Path, Format, CreateDirectories: true);
                if (string.IsNullOrEmpty(HostPath))
                    return false;

                try
                {
                    Directory.CreateDirectory(HostPath);
                    return true;
                }
                catch
                {
                    return false;
                }
            }

            /// <summary>
            /// Gets the file size in bytes for a path in the emulated filesystem.
            /// </summary>
            /// <param name="Path">file path to query.</param>
            /// <param name="Format">binary format of the emulated process.</param>
            /// <returns>returns the file length in bytes, or 0 if the file doesn't exist or cannot be accessed.</returns>
            public static long GetFileLength(string Path, BinaryFormat Format)
            {
                string HostPath = ResolveHostPath(Path, Format);
                if (string.IsNullOrEmpty(HostPath) || !File.Exists(HostPath))
                    return 0;

                try
                {
                    return new FileInfo(HostPath).Length;
                }
                catch
                {
                    return 0;
                }
            }

            /// <summary>
            /// Writes a file into the emulated filesystem.
            /// </summary>
            /// <param name="Path">path to write.</param>
            /// <param name="Data">file bytes to write.</param>
            /// <param name="Format">binary format of the emulated process.</param>
            /// <returns>returns true if the file was written successfully, otherwise false.</returns>
            public static bool WriteFile(string Path, byte[] Data, BinaryFormat Format)
            {
                if (Data == null)
                    return false;

                string HostPath = ResolveVirtualHostPath(Path, Format, CreateDirectories: true);
                if (string.IsNullOrEmpty(HostPath))
                    return false;

                try
                {
                    File.WriteAllBytes(HostPath, Data);
                    return true;
                }
                catch
                {
                    return false;
                }
            }

            /// <summary>
            /// Ensures an emulated drive letter has a host root mapping (creates the directory if possible).
            /// </summary>
            /// <param name="DriveLetter">drive letter to map.</param>
            /// <param name="HostRoot">host directory root for the drive.</param>
            private static void EnsureDriveMapping(char DriveLetter, string HostRoot)
            {
                DriveLetter = char.ToUpperInvariant(DriveLetter);
                if (!char.IsLetter(DriveLetter))
                    return;

                if (string.IsNullOrWhiteSpace(HostRoot))
                    return;

                lock (DriveMapLock)
                {
                    DriveMappings[DriveLetter] = HostRoot;
                }

                try
                {
                    Directory.CreateDirectory(HostRoot);
                }
                catch
                {
                    Utils.LogError("[IO] Failed to create drive mapping directory.");
                }
            }

            private static void EnsureLinuxMountMapping(string MountPoint, string HostRoot)
            {
                string NormalizedMountPoint = NormalizeLinuxMountPoint(MountPoint);
                if (string.IsNullOrEmpty(NormalizedMountPoint) || string.IsNullOrWhiteSpace(HostRoot))
                    return;

                lock (DriveMapLock)
                {
                    LinuxMountMappings[NormalizedMountPoint] = HostRoot;
                }

                try
                {
                    Directory.CreateDirectory(HostRoot);
                }
                catch
                {
                    Utils.LogError("[IO] Failed to create linux mount mapping directory.");
                }
            }

            private static string NormalizeLinuxMountPoint(string MountPoint)
            {
                string Normalized = NormalizeLinuxEmulatedPath(MountPoint);
                if (string.IsNullOrEmpty(Normalized))
                    return null;

                if (Normalized.Length > 1)
                    Normalized = Normalized.TrimEnd('/');

                return Normalized;
            }

            private static string ResolveLinuxHostPath(string EmulatedPath, bool CreateDirectories, bool PreserveFinalLink)
            {
                string LinuxPath = NormalizeLinuxEmulatedPath(EmulatedPath);
                if (string.IsNullOrEmpty(LinuxPath))
                    return null;

                string VirtualHostPath = ResolveLinuxVirtualHostPathInternal(LinuxPath, CreateDirectories, PreserveFinalLink);
                if (CreateDirectories || LinuxPath == "/")
                    return VirtualHostPath;

                if (LinuxHostPathExists(VirtualHostPath))
                    return VirtualHostPath;

                foreach (string AliasPath in EnumerateLinuxPathAliases(LinuxPath))
                {
                    if (string.Equals(AliasPath, LinuxPath, StringComparison.Ordinal))
                        continue;

                    string AliasVirtualHostPath = ResolveLinuxVirtualHostPathInternal(AliasPath, false, PreserveFinalLink);
                    if (LinuxHostPathExists(AliasVirtualHostPath))
                        return AliasVirtualHostPath;
                }

                if (IsLinux)
                {
                    string NativeHostPath = GetNativeFullPath(LinuxPath, false);
                    if (LinuxHostPathExists(NativeHostPath))
                        return NativeHostPath;

                    foreach (string AliasPath in EnumerateLinuxPathAliases(LinuxPath))
                    {
                        if (string.Equals(AliasPath, LinuxPath, StringComparison.Ordinal))
                            continue;

                        string AliasNativeHostPath = GetNativeFullPath(AliasPath, false);
                        if (LinuxHostPathExists(AliasNativeHostPath))
                            return AliasNativeHostPath;
                    }
                }

                return VirtualHostPath;
            }

            private static string ResolveLinuxVirtualHostPath(string EmulatedPath, bool CreateDirectories)
            {
                string LinuxPath = NormalizeLinuxEmulatedPath(EmulatedPath);
                if (string.IsNullOrEmpty(LinuxPath))
                    return null;

                return ResolveLinuxVirtualHostPathInternal(LinuxPath, CreateDirectories, PreserveFinalLink: false);
            }

            private static bool LinuxHostPathExists(string HostPath)
            {
                if (string.IsNullOrWhiteSpace(HostPath))
                    return false;

                return File.Exists(HostPath) || Directory.Exists(HostPath);
            }

            private static IEnumerable<string> EnumerateLinuxPathAliases(string LinuxPath)
            {
                if (string.IsNullOrWhiteSpace(LinuxPath) || !LinuxPath.StartsWith("/", StringComparison.Ordinal))
                    yield break;

                yield return LinuxPath;

                if (LinuxPath.StartsWith("/lib64/", StringComparison.Ordinal))
                    yield return "/usr" + LinuxPath;
                else if (LinuxPath.StartsWith("/usr/lib64/", StringComparison.Ordinal))
                    yield return LinuxPath.Substring(4);

                if (LinuxPath.StartsWith("/lib/", StringComparison.Ordinal))
                    yield return "/usr" + LinuxPath;
                else if (LinuxPath.StartsWith("/usr/lib/", StringComparison.Ordinal))
                    yield return LinuxPath.Substring(4);
            }

            private static string NormalizeLinuxEmulatedPath(string Raw)
            {
                if (string.IsNullOrWhiteSpace(Raw))
                    return null;

                string LinuxPath = Raw.Replace('\\', '/').Trim().TrimEnd(' ');
                if (LinuxPath.Length == 0)
                    return null;

                if (!LinuxPath.StartsWith("/", StringComparison.Ordinal))
                {
                    string CurrentDirectory = string.IsNullOrWhiteSpace(LinuxCurrentDirectory) ? "/" : LinuxCurrentDirectory;
                    if (!CurrentDirectory.StartsWith("/", StringComparison.Ordinal))
                        CurrentDirectory = "/" + CurrentDirectory;

                    LinuxPath = CurrentDirectory.TrimEnd('/') + "/" + LinuxPath;
                }

                List<string> Parts = new();
                foreach (string Part in LinuxPath.Split('/', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (Part == ".")
                        continue;

                    if (Part == "..")
                    {
                        if (Parts.Count > 0)
                            Parts.RemoveAt(Parts.Count - 1);

                        continue;
                    }

                    Parts.Add(Part);
                }

                if (Parts.Count == 0)
                    return "/";

                return "/" + string.Join('/', Parts);
            }

            private static string ResolveLinuxVirtualHostPathInternal(string LinuxPath, bool CreateDirectories, bool PreserveFinalLink = false)
            {
                if (string.IsNullOrWhiteSpace(LinuxPath) || !LinuxPath.StartsWith("/", StringComparison.Ordinal))
                    return null;

                string MountPoint = "/";
                string HostRoot = LinuxVirtualFileSystemRoot;

                lock (DriveMapLock)
                {
                    foreach (KeyValuePair<string, string> Pair in LinuxMountMappings)
                    {
                        string CandidateMount = Pair.Key;
                        if (string.IsNullOrWhiteSpace(CandidateMount) || string.IsNullOrWhiteSpace(Pair.Value))
                            continue;

                        bool IsMatch = LinuxPath == CandidateMount ||
                                       LinuxPath.StartsWith(CandidateMount + "/", StringComparison.Ordinal) ||
                                       CandidateMount == "/";
                        if (!IsMatch)
                            continue;

                        if (CandidateMount.Length > MountPoint.Length || (CandidateMount.Length == MountPoint.Length && !string.Equals(HostRoot, Pair.Value, StringComparison.Ordinal)))
                        {
                            MountPoint = CandidateMount;
                            HostRoot = Pair.Value;
                        }
                    }
                }

                string RelativePath = LinuxPath == MountPoint ? string.Empty : LinuxPath.Substring(MountPoint.Length).TrimStart('/');
                string HostPath = string.IsNullOrEmpty(RelativePath) ? HostRoot : CombineLinuxRelativePath(HostRoot, RelativePath);
                return GetSandboxedFullPath(HostPath, CreateDirectories, PreserveFinalLink);
            }

            private static string CombineLinuxRelativePath(string Root, string LinuxRelative)
            {
                if (string.IsNullOrWhiteSpace(Root))
                    return null;

                if (string.IsNullOrWhiteSpace(LinuxRelative))
                    return Root;

                string[] Parts = LinuxRelative.Split('/', StringSplitOptions.RemoveEmptyEntries);
                string Result = Root;

                for (int i = 0; i < Parts.Length; i++)
                    Result = Path.Combine(Result, Parts[i]);

                return Result;
            }

            /// <summary>
            /// Gets the host root directory for an emulated drive letter (creates a default mapping on demand).
            /// </summary>
            /// <param name="DriveLetter">drive letter to resolve.</param>
            /// <returns>returns the host root directory for the drive.</returns>
            private static string GetDriveRoot(char DriveLetter)
            {
                DriveLetter = char.ToUpperInvariant(DriveLetter);

                lock (DriveMapLock)
                {
                    if (DriveMappings.TryGetValue(DriveLetter, out string Root) && !string.IsNullOrWhiteSpace(Root))
                        return Root;
                }

                // Create a default mapping on demand.
                string DefaultRoot = Path.Combine(VirtualFileSystemRoot, DriveLetter.ToString());
                EnsureDriveMapping(DriveLetter, DefaultRoot);
                return DefaultRoot;
            }

            /// <summary>
            /// Rebuilds the allowed root list used to keep emulated IO sandboxed.
            /// </summary>
            private static void RefreshAllowedRoots()
            {
                lock (DriveMapLock)
                {
                    AllowedRoots.Clear();

                    foreach (KeyValuePair<char, string> Pair in DriveMappings)
                    {
                        if (string.IsNullOrWhiteSpace(Pair.Value))
                            continue;

                        try
                        {
                            AllowedRoots.Add(Path.GetFullPath(Pair.Value));
                        }
                        catch
                        {
                            // ignore
                        }
                    }

                    foreach (KeyValuePair<string, string> Pair in LinuxMountMappings)
                    {
                        if (string.IsNullOrWhiteSpace(Pair.Value))
                            continue;

                        try
                        {
                            AllowedRoots.Add(Path.GetFullPath(Pair.Value));
                        }
                        catch
                        {
                            // ignore
                        }
                    }

                    try
                    {
                        AllowedRoots.Add(Path.GetFullPath(WindowsLibsPath));
                    }
                    catch
                    {
                        // ignore
                    }
                }
            }

            /// <summary>
            /// Returns a full path only if it stays within the allowed sandbox roots.
            /// </summary>
            /// <param name="CandidatePath">candidate path to normalize and validate.</param>
            /// <param name="CreateDirectories">whether to create parent directories.</param>
            /// <param name="PreserveFinalLink">whether to keep the final path component unresolved.</param>
            /// <returns>returns the sandboxed full path, or null if it escapes the sandbox.</returns>
            private static string GetSandboxedFullPath(string CandidatePath, bool CreateDirectories, bool PreserveFinalLink = false)
            {
                if (string.IsNullOrWhiteSpace(CandidatePath))
                    return null;

                string Full;
                try
                {
                    Full = Path.GetFullPath(CandidatePath);
                }
                catch
                {
                    return null;
                }

                if (!IsUnderAllowedRoots(Full))
                    return null;

                bool IncludeFinal = !PreserveFinalLink && (File.Exists(Full) || Directory.Exists(Full));
                string Resolved = ResolveSandboxLinks(Full, IncludeFinal);
                if (string.IsNullOrEmpty(Resolved) || !IsUnderAllowedRoots(Resolved))
                    return null;

                if (CreateDirectories)
                {
                    try
                    {
                        string Dir = Path.GetDirectoryName(Resolved);
                        if (!string.IsNullOrEmpty(Dir))
                            Directory.CreateDirectory(Dir);
                    }
                    catch
                    {
                        return null;
                    }

                    IncludeFinal = !PreserveFinalLink && (File.Exists(Resolved) || Directory.Exists(Resolved));
                    Resolved = ResolveSandboxLinks(Resolved, IncludeFinal);
                    if (string.IsNullOrEmpty(Resolved) || !IsUnderAllowedRoots(Resolved))
                        return null;
                }

                return Resolved;
            }

            private static string ResolveSandboxLinks(string FullPath, bool IncludeFinal)
            {
                if (string.IsNullOrWhiteSpace(FullPath))
                    return null;

                string Normalized;
                try
                {
                    Normalized = Path.GetFullPath(FullPath);
                }
                catch
                {
                    return null;
                }

                string Root = Path.GetPathRoot(Normalized);
                if (string.IsNullOrEmpty(Root))
                    return null;

                string Relative = Normalized.Substring(Root.Length);
                string[] Parts = Relative.Split(new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries);

                if (Parts.Length == 0)
                    return Normalized;

                string Current = Root;
                for (int i = 0; i < Parts.Length; i++)
                {
                    Current = Path.Combine(Current, Parts[i]);

                    bool IsFinal = i == Parts.Length - 1;
                    if (IsFinal && !IncludeFinal)
                        continue;

                    if (!File.Exists(Current) && !Directory.Exists(Current))
                        continue;

                    FileAttributes Attributes;
                    try
                    {
                        Attributes = File.GetAttributes(Current);
                    }
                    catch
                    {
                        return null;
                    }

                    if ((Attributes & FileAttributes.ReparsePoint) == 0)
                        continue;

                    string Resolved = ResolveLinkTarget(Current, Attributes);
                    if (string.IsNullOrEmpty(Resolved))
                        return null;

                    Current = Resolved;
                    if (!IsUnderAllowedRoots(Current))
                        return null;
                }

                try
                {
                    return Path.GetFullPath(Current);
                }
                catch
                {
                    return null;
                }
            }

            private static string ResolveLinkTarget(string PathValue, FileAttributes Attributes)
            {
                try
                {
                    FileSystemInfo Target = (Attributes & FileAttributes.Directory) != 0
                        ? Directory.ResolveLinkTarget(PathValue, true)
                        : File.ResolveLinkTarget(PathValue, true);

                    if (Target == null || string.IsNullOrWhiteSpace(Target.FullName))
                        return null;

                    return Path.GetFullPath(Target.FullName);
                }
                catch
                {
                    return null;
                }
            }

            /// <summary>
            /// Returns a full path without sandbox validation (normal .NET path resolution).
            /// </summary>
            /// <param name="CandidatePath">candidate path to normalize.</param>
            /// <param name="CreateDirectories">whether to create parent directories.</param>
            /// <returns>returns the normalized full path, or null if it cannot be resolved.</returns>
            private static string GetNativeFullPath(string CandidatePath, bool CreateDirectories)
            {
                if (string.IsNullOrWhiteSpace(CandidatePath))
                    return null;

                string Full;
                try
                {
                    Full = Path.GetFullPath(CandidatePath);
                }
                catch
                {
                    return null;
                }

                if (CreateDirectories)
                {
                    try
                    {
                        string Dir = Path.GetDirectoryName(Full);
                        if (!string.IsNullOrEmpty(Dir))
                            Directory.CreateDirectory(Dir);
                    }
                    catch
                    {
                        // ignore
                    }
                }

                return Full;
            }

            /// <summary>
            /// returns whether a full path is inside any allowed sandbox root directory.
            /// </summary>
            /// <param name="FullPath">full path to validate.</param>
            /// <returns>returns true if the path is allowed, otherwise false.</returns>
            private static bool IsUnderAllowedRoots(string FullPath)
            {
                if (string.IsNullOrWhiteSpace(FullPath))
                    return false;

                string Normalized;
                try
                {
                    Normalized = Path.GetFullPath(FullPath);
                }
                catch
                {
                    return false;
                }

                lock (DriveMapLock)
                {
                    foreach (string Root in AllowedRoots)
                    {
                        if (string.IsNullOrWhiteSpace(Root))
                            continue;

                        string RootNorm = Root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                        StringComparison Comparison = IsWindows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
                        if (Normalized.StartsWith(RootNorm + Path.DirectorySeparatorChar, Comparison) ||
                            string.Equals(Normalized, RootNorm, Comparison))
                        {
                            return true;
                        }
                    }
                }

                return false;
            }

            /// <summary>
            /// Combines a host root directory with a Windows-style relative path.
            /// </summary>
            /// <param name="Root">host root directory.</param>
            /// <param name="WindowsRelative">windows-style relative path using backslashes.</param>
            /// <returns>returns the combined host path.</returns>
            private static string CombineWindowsRelativePath(string Root, string WindowsRelative)
            {
                if (string.IsNullOrWhiteSpace(Root))
                    return null;

                if (string.IsNullOrWhiteSpace(WindowsRelative))
                    return Root;

                string[] Parts = WindowsRelative.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
                string Result = Root;

                for (int i = 0; i < Parts.Length; i++)
                    Result = Path.Combine(Result, Parts[i]);

                return Result;
            }

            /// <summary>
            /// returns whether the provided string looks like an absolute Windows path or UNC path.
            /// </summary>
            /// <param name="WinPath">path to check.</param>
            /// <returns>returns true if it looks absolute, otherwise false.</returns>
            private static bool LooksLikeAbsoluteWindowsPath(string WinPath)
            {
                if (string.IsNullOrEmpty(WinPath))
                    return false;

                if (WinPath.Length >= 3 && char.IsLetter(WinPath[0]) && WinPath[1] == ':' && WinPath[2] == '\\')
                    return true;

                if (WinPath.StartsWith("\\\\", StringComparison.Ordinal))
                    return true;

                if (WinPath.StartsWith("\\", StringComparison.Ordinal))
                    return true;

                return false;
            }

            /// <summary>
            /// Attempts to translate a Windows System32/SysWOW64/KnownDlls path into the shipped WindowsLibs directory.
            /// </summary>
            /// <param name="WinPath">windows-style path to resolve.</param>
            /// <returns>returns the resolved host path inside WindowsLibs, or null if no mapping applies.</returns>
            private static string TryResolveFromWindowsLibs(string WinPath)
            {
                if (string.IsNullOrWhiteSpace(WinPath))
                    return null;

                // Common shipped locations.
                const string System32Prefix = "C:\\Windows\\System32\\";
                const string SysWow64Prefix = "C:\\Windows\\SysWOW64\\";

                string Normalized = WinPath.Replace('/', '\\');

                if (Normalized.StartsWith(System32Prefix, StringComparison.OrdinalIgnoreCase))
                {
                    string Rel = Normalized.Substring(System32Prefix.Length);
                    return TryResolveFromWindowsLibsRelative(WindowsLibsPath, Rel);
                }

                if (Normalized.StartsWith(SysWow64Prefix, StringComparison.OrdinalIgnoreCase))
                {
                    string Rel = Normalized.Substring(SysWow64Prefix.Length);
                    return TryResolveFromWindowsLibsRelative(Path.Combine(WindowsLibsPath, "SysWOW64"), Rel);
                }

                // Some callers pass "\\KnownDlls\\xxx.dll" or similar, which ultimately maps to System32.
                if (Normalized.StartsWith("\\KnownDlls\\", StringComparison.OrdinalIgnoreCase) || Normalized.StartsWith("\\KnownDlls32\\", StringComparison.OrdinalIgnoreCase))
                {
                    string Leaf = Path.GetFileName(Normalized);
                    return TryResolveFromWindowsLibsByLeaf(Leaf);
                }

                return null;
            }

            /// <summary>
            /// Attempts to resolve a relative path inside WindowsLibs (falls back to a case-insensitive leaf search).
            /// </summary>
            /// <param name="BaseDir">base directory inside WindowsLibs.</param>
            /// <param name="WindowsRelative">windows-style relative path.</param>
            /// <returns>returns the resolved host path, or null if it cannot be found.</returns>
            private static string TryResolveFromWindowsLibsRelative(string BaseDir, string WindowsRelative)
            {
                if (string.IsNullOrWhiteSpace(BaseDir) || string.IsNullOrWhiteSpace(WindowsRelative))
                    return null;

                string Candidate = CombineWindowsRelativePath(BaseDir, WindowsRelative);
                if (string.IsNullOrWhiteSpace(Candidate))
                    return null;

                string Full = GetSandboxedFullPath(Candidate, CreateDirectories: false);
                if (!string.IsNullOrEmpty(Full) && (File.Exists(Full) || Directory.Exists(Full)))
                    return Full;

                // Fall back to a case-insensitive leaf search.
                string Leaf = Path.GetFileName(WindowsRelative);
                return TryResolveFromWindowsLibsByLeaf(Leaf);
            }

            /// <summary>
            /// Looks up a file by name inside WindowsLibs (case-insensitive).
            /// </summary>
            /// <param name="Leaf">file name to search for.</param>
            /// <returns>returns the resolved host path, or null if not found.</returns>
            private static string TryResolveFromWindowsLibsByLeaf(string Leaf)
            {
                if (string.IsNullOrWhiteSpace(Leaf))
                    return null;

                EnsureWindowsLibsIndex();

                lock (WindowsLibsIndexLock)
                {
                    if (WindowsLibsFileIndex != null && WindowsLibsFileIndex.TryGetValue(Leaf, out string Found))
                        return Found;
                }

                return null;
            }

            /// <summary>
            /// Builds the WindowsLibs leaf index on demand for fast case-insensitive resolution.
            /// </summary>
            private static void EnsureWindowsLibsIndex()
            {
                lock (WindowsLibsIndexLock)
                {
                    if (WindowsLibsFileIndex != null)
                        return;

                    WindowsLibsFileIndex = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

                    try
                    {
                        if (!Directory.Exists(WindowsLibsPath))
                            return;

                        foreach (string FilePath in Directory.EnumerateFiles(WindowsLibsPath, "*", SearchOption.AllDirectories))
                        {
                            string Leaf = Path.GetFileName(FilePath);
                            if (string.IsNullOrEmpty(Leaf))
                                continue;

                            // Keep first hit to avoid churn when duplicates exist.
                            if (!WindowsLibsFileIndex.ContainsKey(Leaf))
                            {
                                string Full = GetSandboxedFullPath(FilePath, CreateDirectories: false);
                                if (!string.IsNullOrEmpty(Full))
                                    WindowsLibsFileIndex[Leaf] = Full;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Utils.LogError($"[IO] Failed to build WindowsLibs Index: {ex.Message}");
                    }
                }
            }
        }
    }

    /// <summary>
    /// Generators for other platforms.
    /// </summary>
    public class CrossGenerator
    {
        /// <summary>
        /// Generate an ApiSetMap that the emulated binary can use.
        /// </summary>
        /// <returns>returns a byte array containing the generated ApiSetMap.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] GenerateMap()
        {
            Dictionary<string, string> ApiSetMap = HelperFunctions.ApiSetMap;
            Dictionary<ApiSetOverrideKey, string> ApiSetOverrideMap = HelperFunctions.ApiSetOverrideMap;
            if (ApiSetMap == null)
                throw new ArgumentNullException(nameof(ApiSetMap));

            ApiSetOverrideMap ??= new Dictionary<ApiSetOverrideKey, string>();

            // Aggregate everything per contract so offsets/counts are easy to compute later.
            Dictionary<string, ApiSetContractBuild> ContractTable = new(StringComparer.OrdinalIgnoreCase);

            foreach (KeyValuePair<string, string> Pair in ApiSetMap)
            {
                string ContractName = NormalizeContractName(Pair.Key);
                string HostName = NormalizeHostName(Pair.Value);

                if (string.IsNullOrWhiteSpace(ContractName) || string.IsNullOrWhiteSpace(HostName))
                    continue;

                ApiSetContractBuild Contract = GetOrCreateContract(ContractTable, ContractName);
                Contract.DefaultHostName = HostName;
            }

            foreach (KeyValuePair<ApiSetOverrideKey, string> Pair in ApiSetOverrideMap)
            {
                string ContractName = NormalizeContractName(Pair.Key.ContractName);
                string ImportingModuleName = NormalizeHostName(Pair.Key.ImportingModuleName);
                string HostName = NormalizeHostName(Pair.Value);

                if (string.IsNullOrWhiteSpace(ContractName) || string.IsNullOrWhiteSpace(ImportingModuleName) || string.IsNullOrWhiteSpace(HostName))
                    continue;

                ApiSetContractBuild Contract = GetOrCreateContract(ContractTable, ContractName);
                Contract.OverrideHosts[ImportingModuleName] = HostName;
            }

            List<ApiSetContractBuild> Contracts = ContractTable.Values
                .Where(Contract => !string.IsNullOrWhiteSpace(Contract.DefaultHostName) || Contract.OverrideHosts.Count != 0)
                .OrderBy(Contract => Contract.ContractName, StringComparer.OrdinalIgnoreCase)
                .ToList();

            int ContractCount = Contracts.Count;

            // Values are stored in one packed array, so count them up front.
            int TotalValueCount = 0;
            for (int Index = 0; Index < ContractCount; Index++)
            {
                int ValueCount = Contracts[Index].OverrideHosts.Count + (string.IsNullOrWhiteSpace(Contracts[Index].DefaultHostName) ? 0 : 1);
                TotalValueCount += ValueCount;
            }

            // ApiSet schema v6 (header + entry table + hash table + value table + UTF-16 string pool)
            const int NamespaceSize = 28;
            const int NamespaceEntrySize = 24;
            const int HashEntrySize = 8;
            const int ValueEntrySize = 20;

            int EntryOffset = NamespaceSize;
            int HashOffset = EntryOffset + (ContractCount * NamespaceEntrySize);
            int ValuesOffset = HashOffset + (ContractCount * HashEntrySize);
            int StringPoolOffset = ValuesOffset + (TotalValueCount * ValueEntrySize);

            using MemoryStream Stream = new();
            using BinaryWriter Writer = new(Stream, Encoding.Unicode, leaveOpen: true);

            Stream.SetLength(StringPoolOffset);

            Dictionary<string, ApiSetString> StringTable = new(StringComparer.OrdinalIgnoreCase);

            ApiSetString AddString(string Value)
            {
                if (StringTable.TryGetValue(Value, out ApiSetString Cached))
                    return Cached;

                uint Offset = checked((uint)Stream.Length);
                byte[] Bytes = Encoding.Unicode.GetBytes(Value);

                Writer.Seek((int)Stream.Length, SeekOrigin.Begin);
                Writer.Write(Bytes);

                ApiSetString Result = new(Offset, checked((uint)Bytes.Length));
                StringTable[Value] = Result;
                return Result;
            }

            // populate the pool first so all offsets are known before writing structs
            for (int Index = 0; Index < ContractCount; Index++)
            {
                AddString(Contracts[Index].ContractName);

                foreach (KeyValuePair<string, string> OverridePair in Contracts[Index].OverrideHosts.OrderBy(Pair => Pair.Key, StringComparer.OrdinalIgnoreCase))
                {
                    AddString(OverridePair.Key);
                    AddString(OverridePair.Value);
                }

                if (!string.IsNullOrWhiteSpace(Contracts[Index].DefaultHostName))
                    AddString(Contracts[Index].DefaultHostName);
            }

            const uint HashFactor = 0x1F;

            // hash table is sorted by hash, each entry points back into the namespace entry array by index.
            List<ApiSetHashItem> HashItems = new(ContractCount);
            for (int Index = 0; Index < ContractCount; Index++)
            {
                uint HashedLengthBytes = ComputeHashedLengthBytes(Contracts[Index].ContractName);
                uint Hash = ComputeApiSetHash(Contracts[Index].ContractName, HashedLengthBytes, HashFactor);
                HashItems.Add(new ApiSetHashItem(Hash, checked((uint)Index)));
            }

            HashItems.Sort((A, B) => A.Hash.CompareTo(B.Hash));

            uint TotalSize = checked((uint)Stream.Length);

            Writer.Seek(0, SeekOrigin.Begin);
            Writer.Write((uint)6);
            Writer.Write(TotalSize);
            Writer.Write((uint)0);
            Writer.Write((uint)ContractCount);
            Writer.Write((uint)EntryOffset);
            Writer.Write((uint)HashOffset);
            Writer.Write(HashFactor);

            int CurrentValueIndex = 0;

            for (int ContractIndex = 0; ContractIndex < ContractCount; ContractIndex++)
            {
                ApiSetContractBuild Contract = Contracts[ContractIndex];

                ApiSetString NameString = StringTable[Contract.ContractName];
                uint HashedLengthBytes = ComputeHashedLengthBytes(Contract.ContractName);

                int ValueCount = Contract.OverrideHosts.Count + (string.IsNullOrWhiteSpace(Contract.DefaultHostName) ? 0 : 1);
                uint ValueOffset = checked((uint)(ValuesOffset + (CurrentValueIndex * ValueEntrySize)));

                int EntryBase = EntryOffset + (ContractIndex * NamespaceEntrySize);
                Writer.Seek(EntryBase, SeekOrigin.Begin);

                Writer.Write((uint)0);
                Writer.Write(NameString.Offset);
                Writer.Write(NameString.ByteLength);
                Writer.Write(HashedLengthBytes);
                Writer.Write(ValueOffset);
                Writer.Write(checked((uint)ValueCount));

                foreach (KeyValuePair<string, string> OverridePair in Contract.OverrideHosts.OrderBy(Pair => Pair.Key, StringComparer.OrdinalIgnoreCase))
                {
                    ApiSetString ImportingModuleString = StringTable[OverridePair.Key];
                    ApiSetString HostString = StringTable[OverridePair.Value];

                    int ValueBase = ValuesOffset + (CurrentValueIndex * ValueEntrySize);
                    Writer.Seek(ValueBase, SeekOrigin.Begin);

                    Writer.Write((uint)0);
                    Writer.Write(ImportingModuleString.Offset);
                    Writer.Write(ImportingModuleString.ByteLength);
                    Writer.Write(HostString.Offset);
                    Writer.Write(HostString.ByteLength);

                    CurrentValueIndex++;
                }

                if (!string.IsNullOrWhiteSpace(Contract.DefaultHostName))
                {
                    ApiSetString HostString = StringTable[Contract.DefaultHostName];

                    int ValueBase = ValuesOffset + (CurrentValueIndex * ValueEntrySize);
                    Writer.Seek(ValueBase, SeekOrigin.Begin);

                    Writer.Write((uint)0);
                    Writer.Write((uint)0);
                    Writer.Write((uint)0);
                    Writer.Write(HostString.Offset);
                    Writer.Write(HostString.ByteLength);

                    CurrentValueIndex++;
                }
            }

            for (int Index = 0; Index < ContractCount; Index++)
            {
                int HashBase = HashOffset + (Index * HashEntrySize);
                Writer.Seek(HashBase, SeekOrigin.Begin);

                Writer.Write(HashItems[Index].Hash);
                Writer.Write(HashItems[Index].Index);
            }

            return Stream.ToArray();
        }

        private static ApiSetContractBuild GetOrCreateContract(Dictionary<string, ApiSetContractBuild> ContractTable, string ContractName)
        {
            if (!ContractTable.TryGetValue(ContractName, out ApiSetContractBuild Contract))
            {
                Contract = new ApiSetContractBuild(ContractName);
                ContractTable[ContractName] = Contract;
            }

            return Contract;
        }

        private static string NormalizeContractName(string Name)
        {
            Name = (Name ?? string.Empty).Trim();

            if (Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                Name = Name[..^4];

            return Name.ToLowerInvariant();
        }

        private static string NormalizeHostName(string Name)
        {
            Name = (Name ?? string.Empty).Trim();

            if (!Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                Name += ".dll";

            return Name.ToLowerInvariant();
        }

        private static uint ComputeHashedLengthBytes(string ContractNameWithoutDll)
        {
            if (string.IsNullOrEmpty(ContractNameWithoutDll))
                return 0;

            int LastDash = ContractNameWithoutDll.LastIndexOf('-');
            if (LastDash <= 0)
                return checked((uint)(ContractNameWithoutDll.Length * 2));

            string Tail = ContractNameWithoutDll[(LastDash + 1)..];
            bool TailIsDigits = Tail.Length > 0 && Tail.All(char.IsDigit);

            if (TailIsDigits)
                return checked((uint)(LastDash * 2));

            return checked((uint)(ContractNameWithoutDll.Length * 2));
        }

        private static uint ComputeApiSetHash(string ContractNameWithoutDll, uint HashedLengthBytes, uint HashFactor)
        {
            string DllName = (ContractNameWithoutDll ?? string.Empty) + ".dll";
            int HashedLengthChars = checked((int)(HashedLengthBytes / 2));
            int Limit = Math.Min(DllName.Length, HashedLengthChars);

            uint Hash = 0;

            for (int Index = 0; Index < Limit; Index++)
            {
                char CharValue = DllName[Index];

                if (CharValue >= 'A' && CharValue <= 'Z')
                    CharValue = (char)(CharValue + 0x20);

                Hash = unchecked((Hash * HashFactor) + CharValue);
            }

            return Hash;
        }

        private sealed class ApiSetContractBuild
        {
            public readonly string ContractName;
            public string DefaultHostName;
            public readonly Dictionary<string, string> OverrideHosts;

            public ApiSetContractBuild(string ContractName)
            {
                this.ContractName = ContractName;
                DefaultHostName = string.Empty;
                OverrideHosts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            }
        }

        private readonly struct ApiSetHashItem
        {
            public readonly uint Hash;
            public readonly uint Index;

            public ApiSetHashItem(uint Hash, uint Index)
            {
                this.Hash = Hash;
                this.Index = Index;
            }
        }

        private readonly struct ApiSetString
        {
            public readonly uint Offset;
            public readonly uint ByteLength;

            public ApiSetString(uint Offset, uint ByteLength)
            {
                this.Offset = Offset;
                this.ByteLength = ByteLength;
            }
        }
    }

    [Flags]
    public enum LinuxSignal
    {
        None = 0,

        SIGHUP = 1 << 0,
        SIGINT = 1 << 1,
        SIGQUIT = 1 << 2,
        SIGILL = 1 << 3,
        SIGTRAP = 1 << 4,
        SIGABRT = 1 << 5,
        SIGBUS = 1 << 6,
        SIGFPE = 1 << 7,
        SIGKILL = 1 << 8,
        SIGUSR1 = 1 << 9,
        SIGSEGV = 1 << 10,
        SIGUSR2 = 1 << 11,
        SIGPIPE = 1 << 12,
        SIGALRM = 1 << 13,
        SIGTERM = 1 << 14,
        SIGSTKFLT = 1 << 15,
        SIGCHLD = 1 << 16,
        SIGCONT = 1 << 17,
        SIGSTOP = 1 << 18,
        SIGTSTP = 1 << 19,
        SIGTTIN = 1 << 20,
        SIGTTOU = 1 << 21,
        SIGURG = 1 << 22,
        SIGXCPU = 1 << 23,
        SIGXFSZ = 1 << 24,
        SIGVTALRM = 1 << 25,
        SIGPROF = 1 << 26,
        SIGWINCH = 1 << 27,
        SIGIO = 1 << 28,
        SIGPWR = 1 << 29,
        SIGSYS = 1 << 30,

        FatalException = SIGILL | SIGBUS | SIGFPE | SIGSEGV
    }

    public static unsafe class LinuxNativeCrashHandler
    {
        private const int SA_SIGINFO = 0x00000004;
        private const int SA_RESETHAND = unchecked((int)0x80000000);

        private const int SIGILL = 4;
        private const int SIGTRAP = 5;
        private const int SIGABRT = 6;
        private const int SIGBUS = 7;
        private const int SIGFPE = 8;
        private const int SIGSEGV = 11;
        private const int SIGSYS = 31;

        private const int SEGV_MAPERR = 1;
        private const int SEGV_ACCERR = 2;

        private const int REG_RIP = 16;
        private const int REG_ERR = 19;
        private const int REG_TRAPNO = 20;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void CrashCallback(int sig, ulong faultAddress, ulong rip, IntPtr modulePathUtf8, ulong moduleBase, IntPtr symbolNameUtf8, ulong symbolAddress, int siCode, long trapNo, long err);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void SigActionHandler(int sig, SigInfo* info, void* ucontext);

        private static CrashCallback? _UserCallback;
        private static SigActionHandler? _SignalHandler;

        public static void Install(CrashCallback callback, LinuxSignal signals)
        {
            if (!OperatingSystem.IsLinux())
                return;

            _UserCallback = callback;
            _SignalHandler = OnSignal;

            var sa = default(SigAction);
            sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
            sa.sa_sigaction = Marshal.GetFunctionPointerForDelegate(_SignalHandler);

            foreach (var entry in SignalMap)
            {
                if ((signals & entry.Flag) != 0)
                    Register(entry.Number, &sa);
            }
        }

        public static string GetSegvReason(int siCode)
        {
            return siCode switch
            {
                SEGV_MAPERR => "UNMAPPED",
                SEGV_ACCERR => "PROTECTION",
                _ => $"CODE_{siCode}"
            };
        }

        public static string GetPageFaultAccess(long trapNo, long err)
        {
            if (trapNo != 14)
                return "UNKNOWN";

            bool isWrite = (err & (1 << 1)) != 0;
            bool isExec = (err & (1 << 4)) != 0;

            if (isExec) return "EXECUTE";
            return isWrite ? "WRITE" : "READ";
        }

        private static void Register(int sig, SigAction* sa)
        {
            if (sigaction(sig, sa, null) != 0)
                throw new InvalidOperationException($"sigaction({sig}) failed errno={Marshal.GetLastPInvokeError()}");
        }

        private static void OnSignal(int sig, SigInfo* info, void* uctx)
        {
            var cb = _UserCallback;
            if (cb == null)
            {
                _exit(128 + sig);
                return;
            }

            ulong fault = (ulong)(nuint)info->si_addr;

            ulong rip = 0;
            long err = 0;
            long trapNo = 0;
            TryGetContext(uctx, out rip, out err, out trapNo);

            IntPtr modulePath = IntPtr.Zero;
            ulong moduleBase = 0;
            IntPtr symbolName = IntPtr.Zero;
            ulong symbolAddr = 0;

            if (rip != 0 && dladdr((IntPtr)(nuint)rip, out var di) != 0)
            {
                modulePath = di.dli_fname;
                moduleBase = (ulong)(nuint)di.dli_fbase;
                symbolName = di.dli_sname;
                symbolAddr = (ulong)(nuint)di.dli_saddr;
            }

            cb(sig, fault, rip, modulePath, moduleBase, symbolName, symbolAddr, info->si_code, trapNo, err);

            _exit(128 + sig);
        }

        private static void TryGetContext(void* uctx, out ulong rip, out long err, out long trapNo)
        {
            rip = 0;
            err = 0;
            trapNo = 0;

            try
            {
                var ctx = (UContext64*)uctx;
                rip = (ulong)ctx->uc_mcontext.gregs[REG_RIP];
                err = ctx->uc_mcontext.gregs[REG_ERR];
                trapNo = ctx->uc_mcontext.gregs[REG_TRAPNO];
            }
            catch
            {
            }
        }

        private readonly struct SignalEntry
        {
            public readonly LinuxSignal Flag;
            public readonly int Number;

            public SignalEntry(LinuxSignal flag, int number)
            {
                Flag = flag;
                Number = number;
            }
        }

        private static readonly SignalEntry[] SignalMap =
        {
        new(LinuxSignal.SIGILL, SIGILL),
        new(LinuxSignal.SIGTRAP, SIGTRAP),
        new(LinuxSignal.SIGBUS, SIGBUS),
        new(LinuxSignal.SIGFPE, SIGFPE),
        new(LinuxSignal.SIGSEGV, SIGSEGV),
        new(LinuxSignal.SIGSYS, SIGSYS),
    };

        [StructLayout(LayoutKind.Sequential)]
        private struct SigInfo
        {
            public int si_signo;
            public int si_errno;
            public int si_code;
            public void* si_addr;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SigSet
        {
            public fixed ulong __val[16];
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SigAction
        {
            public IntPtr sa_sigaction;
            public SigSet sa_mask;
            public int sa_flags;
            public IntPtr sa_restorer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DlInfo
        {
            public IntPtr dli_fname;
            public IntPtr dli_fbase;
            public IntPtr dli_sname;
            public IntPtr dli_saddr;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StackT
        {
            public void* ss_sp;
            public int ss_flags;
            public nuint ss_size;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MContext64
        {
            public fixed long gregs[23];
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UContext64
        {
            public ulong uc_flags;
            public void* uc_link;
            public StackT uc_stack;
            public MContext64 uc_mcontext;
        }

        [DllImport("libc", SetLastError = true)]
        private static extern int sigaction(int signum, SigAction* act, SigAction* oldact);

        [DllImport("libc", SetLastError = true)]
        private static extern int dladdr(IntPtr addr, out DlInfo info);

        [DllImport("libc", SetLastError = true)]
        private static extern void _exit(int status);
    }
}
