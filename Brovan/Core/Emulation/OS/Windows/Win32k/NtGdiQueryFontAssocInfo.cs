using Microsoft.Win32;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiQueryFontAssocInfo : IWinSyscall
    {
        private const string FontAssocKeyPath = @"SYSTEM\CurrentControlSet\Control\FontAssoc\Associated Charset";

        private static int _cachedFlags = -1;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            Instance.WinHelper.GetArg(0);

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn((ulong)(uint)ResolveAssociationFlags());
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static int ResolveAssociationFlags()
        {
            int Cached = _cachedFlags;
            if (Cached >= 0)
                return Cached;

            int Flags = 0;

            if (GeneralHelper.IsWindows)
            {
                try
                {
                    using RegistryKey Key = Registry.LocalMachine.OpenSubKey(FontAssocKeyPath, false);
                    if (Key != null)
                    {
                        foreach (string Name in Key.GetValueNames())
                        {
                            string Value = Key.GetValue(Name) as string;
                            if (Value != null && Value.Equals("YES", System.StringComparison.OrdinalIgnoreCase))
                                Flags |= MapCharsetNameToBit(Name);
                        }
                    }
                }
                catch
                {
                }
            }

            _cachedFlags = Flags;
            return Flags;
        }

        private static int MapCharsetNameToBit(string CharsetName)
        {
            switch ((CharsetName ?? string.Empty).ToUpperInvariant())
            {
                case "ANSI":
                    return 0x0001;
                case "GB2312":
                    return 0x0002;
                case "BIG5":
                    return 0x0004;
                case "SHIFTJIS":
                    return 0x0008;
                case "HANGEUL":
                case "HANGUL":
                    return 0x0010;
                case "JOHAB":
                    return 0x0020;
                default:
                    return 0x0001;
            }
        }
    }
}
