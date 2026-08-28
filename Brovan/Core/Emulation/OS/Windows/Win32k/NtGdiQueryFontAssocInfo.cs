using System;
using System.Text;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiQueryFontAssocInfo : IWinSyscall
    {
        private const string FontAssocKeyPath = @"\Registry\Machine\SYSTEM\CurrentControlSet\Control\FontAssoc\Associated Charset";

        private int _cachedFlags = -1;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            Instance.WinHelper.GetArg(0);

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn((ulong)(uint)ResolveAssociationFlags(Instance));
            return NTSTATUS.STATUS_SUCCESS;
        }

        private int ResolveAssociationFlags(BinaryEmulator Instance)
        {
            int Cached = _cachedFlags;
            if (Cached >= 0)
                return Cached;

            int Flags = 0;

            if (Instance.WinHelper.RegistryKeyExists(FontAssocKeyPath, out Hive Hive, out RegistryHiveReader.HiveKey Key, out bool TempOnly))
            {
                WinRegKey RegKey = new WinRegKey
                {
                    FullPath = FontAssocKeyPath,
                    Hive = Hive,
                    ParsedKey = Key,
                    HasParsedKey = !TempOnly && Hive != null && Hive.Reader != null
                };

                for (int Index = 0; Instance.WinHelper.TryEnumerateRegistryValueFull(RegKey, Index, out string Name, out _, out byte[] Data); Index++)
                {
                    if (Data == null || Data.Length < 2)
                        continue;

                    string Value = Encoding.Unicode.GetString(Data).TrimEnd('\0').Trim();
                    if (Value.Equals("YES", StringComparison.OrdinalIgnoreCase))
                        Flags |= MapCharsetNameToBit(Name);
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
