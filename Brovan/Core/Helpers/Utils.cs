using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace Brovan.Core.Helpers
{
    [StructLayout(LayoutKind.Sequential)]
    public struct Coord
    {
        public short X;
        public short Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SmallRect
    {
        public short Left;
        public short Top;
        public short Right;
        public short Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ConsoleScreenBufferInfo
    {
        public Coord DwSize;
        public Coord DwCursorPosition;
        public short WAttributes;
        public SmallRect SrWindow;
        public Coord DwMaximumWindowSize;
    }

    internal class Utils
    {
        private const int LogFlushInterval = 64;

        private static readonly object LogLock = new object();
        private static readonly string LogPath = Path.Combine(AppContext.BaseDirectory, "error_log.log");
        private static readonly string UserProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) ?? string.Empty;

        private static readonly Regex WindowsUserDirRegex = new Regex(@"[A-Z]:\\Users\\[^\\]+", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static StreamWriter? _logWriter;
        private static int _logWriteCount;
        private static bool _logShutdownHooked;
        private static bool? _outputRedirected;

        private static bool OutputRedirected => _outputRedirected ??= Console.IsOutputRedirected;

        /// <summary>
        /// Suppresses Brovan host output while leaving guest console writes untouched.
        /// </summary>
        public static bool SilentMode { get; set; }

        public static bool DiscardErrorLog { get; set; }

        /// <summary>
        /// Removes user-identifying data from an error message.
        /// </summary>
        /// <param name="Error">Error to sanitize.</param>
        private static string SanitizeError(string Error)
        {
            string Result = Error;

            if (UserProfile.Length != 0 && Result.IndexOf(UserProfile, StringComparison.OrdinalIgnoreCase) >= 0)
                Result = Result.Replace(UserProfile, "<USER_PROFILE>", StringComparison.OrdinalIgnoreCase);

            if (Result.IndexOf(@":\Users\", StringComparison.OrdinalIgnoreCase) >= 0)
                Result = WindowsUserDirRegex.Replace(Result, "<USER_DIR>");

            return Result.Trim();
        }

        /// <summary>
        /// Open (or reuse) the process-lifetime log writer.
        /// </summary>
        private static StreamWriter? EnsureLogWriter()
        {
            if (_logWriter != null)
                return _logWriter;

            try
            {
                FileStream fs = new FileStream(LogPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete, bufferSize: 4096, options: FileOptions.SequentialScan);

                _logWriter = new StreamWriter(fs, new UTF8Encoding(false), bufferSize: 4096) { AutoFlush = false };
            }
            catch
            {
                _logWriter = null;
            }

            if (!_logShutdownHooked)
            {
                _logShutdownHooked = true;
                try
                {
                    AppDomain.CurrentDomain.ProcessExit += static (_, _) =>
                    {
                        try
                        {
                            lock (LogLock)
                            {
                                _logWriter?.Flush();
                                _logWriter?.Dispose();
                                _logWriter = null;
                            }
                        }
                        catch{}
                    };
                }
                catch{}
            }

            return _logWriter;
        }

        /// <summary>
        /// Log errors inside Brovan.
        /// </summary>
        /// <param name="Error">Error to log.</param>
        public static void LogError(string Error)
        {
            if (DiscardErrorLog || string.IsNullOrWhiteSpace(Error))
                return;

            string Timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
            string SanitizedError = SanitizeError(Error);

            lock (LogLock)
            {
                StreamWriter? w = EnsureLogWriter();
                if (w == null)
                    return;

                w.Write('[');
                w.Write(Timestamp);
                w.Write("] ERROR: ");
                w.Write(SanitizedError);
                w.WriteLine();

                _logWriteCount++;
                if (_logWriteCount >= LogFlushInterval)
                {
                    _logWriteCount = 0;
                    try { w.Flush(); } catch{};
                }
            }
        }

        /// <summary>
        /// Force the buffered log to disk.
        /// </summary>
        public static void FlushLog()
        {
            lock (LogLock)
            {
                _logWriteCount = 0;
                try { _logWriter?.Flush(); } catch{}
            }
        }

        /// <summary>
        /// Prepare the console for virtual terminal processing and Unicode output.
        /// </summary>
        public static void PrepareConsole()
        {
            if (!GeneralHelper.IsWindows)
                return;

            const int ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x4;

            try
            {
                Console.OutputEncoding = new UTF8Encoding(false);
            }
            catch (IOException)
            {
            }

            IntPtr Handle = NativeWinImports.GetStdHandle(NativeWinImports.StdOutputHandle);
            if (!NativeWinImports.GetConsoleMode(Handle, out int Mode))
                return;

            Mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            NativeWinImports.SetConsoleMode(Handle, Mode);
        }

        // Escape C0, C1 and DEL except line feed and tab.
        private static readonly System.Buffers.SearchValues<char> TerminalControls = System.Buffers.SearchValues.Create(
            "\0\x01\x02\x03\x04\x05\x06\x07\x08\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
            + "\x7F\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F");

        private static string EscapeTerminalControls(string Text)
        {
            int Next = Text.AsSpan().IndexOfAny(TerminalControls);
            if (Next < 0)
                return Text;

            StringBuilder Builder = new StringBuilder(Text.Length + 8);
            int Start = 0;
            while (Next >= 0)
            {
                Builder.Append(Text, Start, Next - Start).Append("\\x").Append(((int)Text[Next]).ToString("X2"));
                Start = Next + 1;
                int Found = Text.AsSpan(Start).IndexOfAny(TerminalControls);
                Next = Found < 0 ? -1 : Start + Found;
            }

            return Builder.Append(Text, Start, Text.Length - Start).ToString();
        }

        public static void PrintHighlight(string Message, bool ColorPrefixOnly = false, bool HidePrefix = false, bool IgnoreSilent = false)
        {
            if (!IgnoreSilent && SilentMode)
                return;

            Message = EscapeTerminalControls(Message ?? string.Empty);
            string Prefix = null;
            ConsoleColor? PrefixColor = null;
            string PrefixTextColor = null;

            if (Message.StartsWith("[!!]"))
            {
                Prefix = "[!!]";
                PrefixColor = ConsoleColor.Red;
            }
            else if (Message.StartsWith("[+]"))
            {
                Prefix = "[+]";
                PrefixColor = ConsoleColor.Green;
            }
            else if (Message.StartsWith("[*]"))
            {
                Prefix = "[*]";
                PrefixColor = ConsoleColor.DarkGreen;
            }
            else if (Message.StartsWith("[-]"))
            {
                Prefix = "[-]";
                PrefixColor = ConsoleColor.DarkRed;
            }
            else if (Message.StartsWith("[!]"))
            {
                Prefix = "[!]";
                PrefixColor = ConsoleColor.Yellow;
            }
            else if (Message.StartsWith("[#]"))
            {
                Prefix = "[#]";
                PrefixColor = ConsoleColor.Cyan;
            }
            else if (Message.StartsWith("[$]"))
            {
                Prefix = "[$]";
                PrefixColor = ConsoleColor.DarkMagenta;
            }
            else if (Message.StartsWith("[/]"))
            {
                Prefix = "[/]";
                PrefixColor = null;
                PrefixTextColor = "255;140;0";
            }

            if (Prefix == null)
            {
                Console.ResetColor();
                Console.WriteLine(Message);
                return;
            }

            string Text = Message.Substring(Prefix.Length).TrimStart();
            bool UseAnsi = PrefixColor == null && PrefixTextColor != null && !OutputRedirected;

            if (!HidePrefix || OutputRedirected)
            {
                if (UseAnsi)
                {
                    Console.Write($"\x1b[38;2;{PrefixTextColor}m");
                    Console.Write(Prefix + " ");
                    Console.Write("\x1b[0m");
                }
                else if (PrefixColor.HasValue && !OutputRedirected)
                {
                    Console.ForegroundColor = PrefixColor.Value;
                    Console.Write(Prefix + " ");
                    Console.ResetColor();
                }
                else
                {
                    Console.Write(Prefix + " ");
                }
            }

            if (ColorPrefixOnly)
            {
                Console.WriteLine(Text);
            }
            else
            {
                if (UseAnsi)
                {
                    Console.Write($"\x1b[38;2;{PrefixTextColor}m");
                    Console.WriteLine(Text);
                    Console.Write("\x1b[0m");
                }
                else if (PrefixColor.HasValue)
                {
                    Console.ForegroundColor = PrefixColor.Value;
                    Console.WriteLine(Text);
                    Console.ResetColor();
                }
                else
                {
                    Console.WriteLine(Text);
                }
            }
        }

        public static void PrintFatal(string Message)
        {
            PrintHighlight(Message, ColorPrefixOnly: true, IgnoreSilent: true);
            Environment.ExitCode = 1;
        }

        // A Linux host keeps only the low byte of an exit status, so a failure must not read as 0 there.
        public static void SetGuestExitCode(uint Code)
        {
            if (!GeneralHelper.IsWindows && Code > 0xFF)
                Code = Math.Max(Code & 0xFF, 1u);

            Environment.ExitCode = (int)Code;
        }

        public static void DumpConsole()
        {
            IntPtr ConsoleHandle = NativeWinImports.GetStdHandle(NativeWinImports.StdOutputHandle);
            if (ConsoleHandle == IntPtr.Zero)
            {
                PrintHighlight("[-] No console attached.", true);
                return;
            }

            if (!NativeWinImports.GetConsoleScreenBufferInfo(ConsoleHandle, out ConsoleScreenBufferInfo BufferInfo))
            {
                PrintHighlight($"[-] GetConsoleScreenBufferInfo failed. Last error: {Marshal.GetLastWin32Error()}", true);
                return;
            }

            int Width = BufferInfo.DwSize.X;
            int Height = BufferInfo.DwSize.Y;

            StringBuilder Result = new StringBuilder(Width * Height + Height);

            for (short y = 0; y < Height; y++)
            {
                StringBuilder lineBuffer = new StringBuilder(Width);
                uint charsRead;

                NativeWinImports.ReadConsoleOutputCharacterW(ConsoleHandle, lineBuffer, (uint)Width, 0, out charsRead);

                Result.Append(lineBuffer.ToString());
                Result.AppendLine();
            }

            try
            {
                string DumpPath = Path.Combine(AppContext.BaseDirectory, "Dump.txt");
                File.WriteAllText(DumpPath, Result.ToString());
                PrintHighlight($"[*] Dump is saved at: \"{DumpPath}\".", true);
            }
            catch (Exception ex)
            {
                PrintHighlight($"[-] Error while writing the dump: {ex.Message}", true);
            }
        }

        public static void ClearConsole()
        {
            Console.SetCursorPosition(0, 0);
            Console.Clear();
            Console.Write("\u001b[H\u001b[2J\u001b[3J"); // Virtual console support
        }
    }

    // The counters are plain fields, so every caller holds the lock that guards them.
    internal sealed class PeriodicStats
    {
        private const int ReportInterval = 256;

        private readonly string _title;
        private readonly Action<StringBuilder> _describe;
        private int _sinceReport;

        internal readonly bool Enabled;

        internal PeriodicStats(string variable, string title, Action<StringBuilder> describe)
        {
            Enabled = string.Equals(Environment.GetEnvironmentVariable(variable), "1", StringComparison.Ordinal);
            _title = title;
            _describe = describe;
        }

        internal void Tick()
        {
            if (++_sinceReport < ReportInterval)
                return;

            _sinceReport = 0;
            StringBuilder sb = new StringBuilder(_title);
            _describe(sb);
            Utils.LogError(sb.ToString());
            Utils.FlushLog();
        }
    }
}