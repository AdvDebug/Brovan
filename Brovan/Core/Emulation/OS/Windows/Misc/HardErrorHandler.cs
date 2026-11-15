using System;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;
using Brovan.Core.Emulation.OS.SharedHelpers;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static class HardErrorHandler
    {
        internal const int MaxParameters = 5;

        private const uint ResponseNotHandled = 1;
        private const uint ResponseOk = 6;
        private const uint OptionOkNoWait = 7;
        private const uint StatusServiceNotification = 0x40000018;
        private const uint StatusUnhandledException = 0xC0000144;
        private const uint StatusVdmHardError = 0xC000021D;
        private const uint StatusAssertionFailure = 0xC00002D1;
        private const int FormattedCharacters = 1024;
        private const uint ClassStyleIme = 0x10000;

        private const string ErrorModeKey = @"\Registry\Machine\System\CurrentControlSet\Control\Windows";
        private const string UnknownHardError = "Unknown Hard Error";
        private const string SystemProcess = "System Process";

        // NT: wOptions, wIcons, dwResponses (by MessageBox id) and dwResponseDefault (by option).
        private static readonly uint[] OptionStyles =
        {
            HostMessageBox.AbortRetryIgnore, HostMessageBox.Ok, HostMessageBox.OkCancel, HostMessageBox.RetryCancel,
            HostMessageBox.YesNo, HostMessageBox.YesNoCancel, HostMessageBox.Ok, HostMessageBox.Ok, HostMessageBox.CancelTryContinue,
        };

        private static readonly uint[] SeverityIcons = { 0, HostMessageBox.IconInformation, HostMessageBox.IconWarning, HostMessageBox.IconError };
        private static readonly uint[] ButtonResponses = { 1, 6, 3, 2, 7, 4, 8, 5, 1, 1, 9, 10 };
        private static readonly uint[] DefaultResponses = { 2, 6, 6, 3, 8, 8, 6, 6, 3 };

        // winsrvext messages 5 to 8, by severity, when its resource file is missing.
        private static readonly string[] SeverityCaptions = { "Success", "System Information", "System Warning", "System Error" };

        private enum ArgumentKind
        {
            None = -1,
            Number = 0,
            Ansi = 1,
            Wide = 2,
        }

        private struct Argument
        {
            public ArgumentKind Kind;
            public ulong Number;
            public string Text;
        }

        internal readonly record struct CapturedString(ushort Length, ulong Buffer);

        // The csrss side of a hard error, as in winsrvext!UserHardErrorEx. Answer is null when the response is final.
        internal static uint Raise(BinaryEmulator Instance, uint Status, uint Count, uint Mask, ReadOnlySpan<ulong> Parameters,
            ReadOnlySpan<CapturedString> Strings, uint Option, out Task<uint> Answer)
        {
            Answer = null;

            if (!IsShapeServed(Status, Count, Mask, Option, out uint Refused))
                return Refused;

            if (Status is StatusServiceNotification or StatusUnhandledException or StatusVdmHardError or StatusAssertionFailure)
            {
                if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage($"[-] NtRaiseHardError: the text of status 0x{Status:X8} is not modeled, so no one is asked.", LogFlags.Issues);

                return DefaultResponses[Option];
            }

            if (ReadErrorMode(Instance) == 2)
                return DefaultResponses[Option];

            string Caption = ComposeCaption(Instance, Status, out string MessageText);
            string Text = ComposeText(Instance, Status, Count, Mask, Parameters, Strings, MessageText);
            uint Style = OptionStyles[Option] | SeverityIcons[Status >> 30] | HostMessageBox.TopMost;

            if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                Instance.TriggerEventMessage($"[-] NtRaiseHardError 0x{Status:X8}: {Caption} | {Text}", LogFlags.Issues);

            Task<int> Asked = HostMessageBox.Ask(Caption, Text, Style);
            if (Option == OptionOkNoWait)
                return ResponseOk;

            Answer = Asked.ContinueWith(static (Done, State) => ToResponse(Done.Result, (uint)State), Option, TaskContinuationOptions.ExecuteSynchronously);
            return 0;
        }

        private static uint ToResponse(int ButtonId, uint Option)
        {
            if (ButtonId == 0)
                return DefaultResponses[Option];

            return (uint)ButtonId < ButtonResponses.Length ? ButtonResponses[ButtonId] : ButtonResponses[0];
        }

        private static bool IsShapeServed(uint Status, uint Count, uint Mask, uint Option, out uint Refused)
        {
            Refused = ResponseNotHandled;
            if (Count > MaxParameters || Option >= OptionStyles.Length)
                return false;

            return Status switch
            {
                StatusServiceNotification => Count is 3 or 4 && Mask == 3,
                StatusVdmHardError => Count == 5 && Mask == 12,
                StatusUnhandledException => Mask == 0,
                StatusAssertionFailure => Mask == 1,
                _ => true,
            };
        }

        // NT: 2 shows nothing. 1 shows nothing only for a process without an image name, which a guest always has.
        private static uint ReadErrorMode(BinaryEmulator Instance)
        {
            WinRegKey Key = Instance.WinHelper.ResolveRegistryKey(ErrorModeKey);
            return Key == null ? 0 : Instance.WinHelper.ReadRegistryDword(Key, "ErrorMode");
        }

        private static string ComposeCaption(BinaryEmulator Instance, uint Status, out string MessageText)
        {
            string Part = null;
            MessageText = UnknownHardError;

            string Ntdll = WinSysHelper.ResolveSystemFile("ntdll.dll");
            if (Ntdll != null && ImageResources.TryFindMessage(Ntdll, Status, out string Message))
            {
                ReadOnlySpan<char> Rest = Message;
                if (Rest.Length > 0 && Rest[0] == '{')
                {
                    int Close = Rest.IndexOf('}');
                    int PartLength = Close < 0 ? Rest.Length - 1 : Close - 1;
                    if (PartLength > 0)
                        Part = Rest.Slice(1, PartLength).ToString();

                    Rest = Close < 0 ? ReadOnlySpan<char>.Empty : Rest.Slice(Close + 1);
                    while (Rest.Length > 0 && Rest[0] <= ' ')
                        Rest = Rest.Slice(1);
                }

                if (!Rest.IsEmpty)
                    MessageText = Rest.ToString();
            }

            Part ??= SeverityCaption(Instance, Status >> 30);

            string Image = string.IsNullOrEmpty(Instance.GuestImagePath) ? SystemProcess : GeneralHelper.IO.GetWindowsFileName(Instance.GuestImagePath);
            string Title = ThreadWindowTitle(Instance);
            return (string.IsNullOrEmpty(Title) ? string.Empty : Title + ": ") + Image + " - " + Part;
        }

        private static string SeverityCaption(BinaryEmulator Instance, uint Severity)
        {
            string Mui = Instance.WinHelper.ResolveSystemMuiFile("winsrvext.dll");

            // NT: RtlLoadStringOrError drops the two characters of the line end.
            if (Mui != null && ImageResources.TryFindMessage(Mui, 5 + Severity, out string Text) && Text.Length > 2)
                return Text.Substring(0, Text.Length - 2);

            return SeverityCaptions[Severity];
        }

        // NT: FindWindowFromThread. The first unowned top-level window of the thread, else its first one; IME windows skipped.
        private static string ThreadWindowTitle(BinaryEmulator Instance)
        {
            WinSysHelper Helper = Instance.WinHelper;
            uint ThreadId = (uint)Instance.CurrentThreadId;
            WinWindow Chosen = null;

            for (int i = Helper.TopLevelWindows.Count - 1; i >= 0; i--)
            {
                WinWindow Window = Helper.GetWindow(Helper.TopLevelWindows[i]);
                if (Window == null || Window.Destroyed || Window.OwnerThreadId != ThreadId || IsImeWindow(Helper, Window))
                    continue;

                if (Chosen == null || Window.OwnerHwnd == 0)
                    Chosen = Window;

                if (Window.OwnerHwnd == 0)
                    break;
            }

            return Chosen?.Title;
        }

        private static bool IsImeWindow(WinSysHelper Helper, WinWindow Window)
        {
            if (Window.ClassName != null && Window.ClassName.StartsWith("IME", StringComparison.Ordinal))
                return true;

            WinWindowClass Class = Helper.GetWindowClass(Window.ClassAtom);
            return Class != null && (Class.Style & ClassStyleIme) != 0;
        }

        private static string ComposeText(BinaryEmulator Instance, uint Status, uint Count, uint Mask, ReadOnlySpan<ulong> Parameters,
            ReadOnlySpan<CapturedString> Strings, string Format)
        {
            Span<Argument> Arguments = new Argument[MaxParameters];
            for (int i = 0; i < MaxParameters; i++)
            {
                bool Masked = (Mask & (1u << i)) != 0;
                if (i >= Count || Masked)
                {
                    Arguments[i] = new Argument { Kind = ArgumentKind.Wide, Text = string.Empty };
                    if (i < Count && Instance.WinHelper.TryReadUnicodeBuffer(Strings[i].Buffer, (ushort)(Strings[i].Length & ~1), out string Text))
                        Arguments[i] = new Argument { Kind = ArgumentKind.Ansi, Text = ThroughAnsi(Instance, CleanPath(Text)) };
                }
                else
                {
                    Arguments[i] = new Argument { Kind = ArgumentKind.Number, Number = Parameters[i] };
                }
            }

            string Formatted = FormatMessage(Format, Arguments) ?? $"Exception Processing Message 0x{Status:x} - Unexpected parameters";
            return FoldLineEnds(Formatted);
        }

        private static string CleanPath(string Text)
        {
            if (Text.StartsWith(@"\Device", StringComparison.Ordinal))
                return WinSysHelper.ToDosDevicePath(Text);

            if (Text.Length > 4 && Text.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
                return Text.Substring(4);

            return Text;
        }

        // The ANSI form csrss builds, read back by %hs, whose C locale widens each byte as it is.
        private static string ThroughAnsi(BinaryEmulator Instance, string Text)
        {
            return Encoding.Latin1.GetString(Instance.WinHelper.ToAnsiBytes(Text));
        }

        private static string FoldLineEnds(string Text)
        {
            return Text.Replace("\r\n", " ").Replace('\r', ' ').Replace('\n', ' ');
        }

        // NT: ValidateFormatStringW checks each conversion against the parameter kinds, then StringCchPrintfW formats
        // with the first four parameters. Null means the check failed.
        private static string FormatMessage(string Format, ReadOnlySpan<Argument> Arguments)
        {
            StringBuilder Output = new StringBuilder();
            int Used = 0;
            int i = 0;

            while (i < Format.Length)
            {
                char Current = Format[i++];
                if (Current != '%')
                {
                    Output.Append(Current);
                    continue;
                }

                if (i < Format.Length && Format[i] == '%')
                {
                    Output.Append('%');
                    i++;
                    continue;
                }

                if (!TryParseConversion(Format, ref i, out Conversion Spec) || Used >= MaxParameters || Arguments[Used].Kind != Spec.Kind)
                    return null;

                Argument Value = Used < MaxParameters - 1 ? Arguments[Used] : default;
                Used++;
                Output.Append(Render(Spec, Value));
            }

            return Output.Length > FormattedCharacters ? Output.ToString(0, FormattedCharacters) : Output.ToString();
        }

        private struct Conversion
        {
            public ArgumentKind Kind;
            public char Type;
            public bool LeftAlign;
            public bool ZeroPad;
            public bool Plus;
            public bool Space;
            public bool Alternate;
            public int Width;
            public int Precision;
            public bool Wide64;
        }

        private static bool TryParseConversion(string Format, ref int i, out Conversion Spec)
        {
            Spec = new Conversion { Precision = -1 };

            for (; i < Format.Length; i++)
            {
                char Flag = Format[i];
                if (Flag == '-') Spec.LeftAlign = true;
                else if (Flag == '0') Spec.ZeroPad = true;
                else if (Flag == '+') Spec.Plus = true;
                else if (Flag == ' ') Spec.Space = true;
                else if (Flag == '#') Spec.Alternate = true;
                else break;
            }

            if (i < Format.Length && Format[i] == '*')
                return false;

            while (i < Format.Length && char.IsAsciiDigit(Format[i]))
                Spec.Width = Math.Min(Spec.Width * 10 + (Format[i++] - '0'), FormattedCharacters);

            if (i < Format.Length && Format[i] == '.')
            {
                i++;
                if (i < Format.Length && Format[i] == '*')
                    return false;

                Spec.Precision = 0;
                while (i < Format.Length && char.IsAsciiDigit(Format[i]))
                    Spec.Precision = Math.Min(Spec.Precision * 10 + (Format[i++] - '0'), FormattedCharacters);
            }

            bool Short = false;
            bool Long = false;
            while (i < Format.Length)
            {
                char Size = Format[i];
                if (Size == 'h')
                {
                    Short = true;
                    i++;
                }
                else if (Size == 'w')
                {
                    Long = true;
                    i++;
                }
                else if (Size == 'l')
                {
                    i++;
                    if (i < Format.Length && Format[i] == 'l')
                    {
                        Spec.Wide64 = true;
                        i++;
                    }
                    else
                    {
                        Long = true;
                    }
                }
                else if (Size == 'I')
                {
                    i++;
                    if (string.CompareOrdinal(Format, i, "64", 0, 2) == 0)
                        i += 2;
                    else if (string.CompareOrdinal(Format, i, "32", 0, 2) == 0)
                    {
                        i += 2;
                        continue;
                    }

                    Spec.Wide64 = true;
                }
                else
                {
                    break;
                }
            }

            if (i >= Format.Length)
                return false;

            Spec.Type = Format[i++];
            Spec.Kind = Spec.Type switch
            {
                's' => Short ? ArgumentKind.Ansi : ArgumentKind.Wide,
                'S' => Long ? ArgumentKind.Wide : ArgumentKind.Ansi,
                'c' or 'C' or 'd' or 'i' or 'o' or 'u' or 'x' or 'X' or 'p' => ArgumentKind.Number,
                _ => ArgumentKind.None,
            };

            return Spec.Kind != ArgumentKind.None;
        }

        private static string Render(in Conversion Spec, in Argument Value)
        {
            string Body;
            string Prefix = string.Empty;

            switch (Spec.Type)
            {
                case 's':
                case 'S':
                    Body = Value.Text ?? "(null)";
                    if (Spec.Precision >= 0 && Body.Length > Spec.Precision)
                        Body = Body.Substring(0, Spec.Precision);
                    return Pad(Body, string.Empty, Spec, false);

                case 'c':
                case 'C':
                    return Pad(((char)(ushort)Value.Number).ToString(), string.Empty, Spec, false);

                case 'd':
                case 'i':
                {
                    long Signed = Spec.Wide64 ? (long)Value.Number : (int)Value.Number;
                    Body = Digits((ulong)Math.Abs(Signed), 10, false, Spec.Precision);
                    Prefix = Signed < 0 ? "-" : Spec.Plus ? "+" : Spec.Space ? " " : string.Empty;
                    break;
                }

                case 'p':
                    Body = Value.Number.ToString("X16", CultureInfo.InvariantCulture);
                    break;

                default:
                {
                    ulong Unsigned = Spec.Wide64 ? Value.Number : (uint)Value.Number;
                    int Radix = Spec.Type == 'o' ? 8 : Spec.Type == 'u' ? 10 : 16;
                    Body = Digits(Unsigned, Radix, Spec.Type == 'X', Spec.Precision);
                    if (Spec.Alternate && Unsigned != 0)
                        Prefix = Radix == 16 ? (Spec.Type == 'X' ? "0X" : "0x") : Radix == 8 ? "0" : string.Empty;
                    break;
                }
            }

            return Pad(Body, Prefix, Spec, Spec.ZeroPad && !Spec.LeftAlign && Spec.Precision < 0);
        }

        private static string Digits(ulong Value, int Radix, bool Upper, int Precision)
        {
            if (Precision == 0 && Value == 0)
                return string.Empty;

            string Text = Radix switch
            {
                16 => Value.ToString(Upper ? "X" : "x", CultureInfo.InvariantCulture),
                8 => Convert.ToString((long)Value, 8),
                _ => Value.ToString(CultureInfo.InvariantCulture),
            };

            return Precision > Text.Length ? Text.PadLeft(Precision, '0') : Text;
        }

        private static string Pad(string Body, string Prefix, in Conversion Spec, bool Zeros)
        {
            int Fill = Spec.Width - Body.Length - Prefix.Length;
            if (Fill <= 0)
                return Prefix + Body;

            if (Spec.LeftAlign)
                return Prefix + Body + new string(' ', Fill);

            return Zeros ? Prefix + new string('0', Fill) + Body : new string(' ', Fill) + Prefix + Body;
        }
    }
}
