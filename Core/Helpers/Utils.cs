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
        private const int StdOutputHandle = -11;

        private static readonly object LogLock = new object();
        private static readonly string LogPath = Path.Combine(AppContext.BaseDirectory, "error_log.log");
        private static readonly string UserProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) ?? string.Empty;

        private static readonly Regex WindowsUserDirRegex = new Regex(@"[A-Z]:\\Users\\[^\\]+", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        /// <summary>
        /// Suppresses Brovan host output while leaving guest console writes untouched.
        /// </summary>
        public static bool SilentMode { get; set; }

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
        /// Log errors inside Brovan.
        /// </summary>
        /// <param name="Error">Error to log.</param>
        public static void LogError(string Error)
        {
            if (string.IsNullOrWhiteSpace(Error))
                return;

            string Timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
            string SanitizedError = SanitizeError(Error);

            string LogLine = $"[{Timestamp}] ERROR: {SanitizedError}{Environment.NewLine}";

            lock (LogLock)
            {
                File.AppendAllText(LogPath, LogLine);
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
            const uint CP_UTF8 = 65001;

            try
            {
                Console.OutputEncoding = new UTF8Encoding(false);
            }
            catch (IOException)
            {
            }

            IntPtr Handle = NativeWinImports.GetStdHandle(StdOutputHandle);
            if (!NativeWinImports.GetConsoleMode(Handle, out int Mode))
                return;

            Mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            NativeWinImports.SetConsoleMode(Handle, Mode);
        }

        public static void PrintHighlight(string Message, bool ColorPrefixOnly = false, bool HidePrefix = false)
        {
            if (SilentMode)
                return;

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
            bool UseAnsi = PrefixColor == null && PrefixTextColor != null && !Console.IsOutputRedirected;

            if (!HidePrefix)
            {
                if (UseAnsi)
                {
                    Console.Write($"\x1b[38;2;{PrefixTextColor}m");
                    Console.Write(Prefix + " ");
                    Console.Write("\x1b[0m");
                }
                else if (PrefixColor.HasValue)
                {
                    Console.ForegroundColor = PrefixColor.Value;
                    Console.Write(Prefix + " ");
                    Console.ResetColor();
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

        public static void DumpConsole()
        {
            IntPtr ConsoleHandle = NativeWinImports.GetStdHandle(StdOutputHandle);
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
                string DumpPath = Path.Combine(Environment.CurrentDirectory, "Dump.txt");
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
}