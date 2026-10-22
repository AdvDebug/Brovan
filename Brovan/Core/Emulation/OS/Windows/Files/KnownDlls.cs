using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    // NT: smss adds every static import of the listed DLLs, with api-set names resolved for the importing module.
    internal sealed class KnownDlls
    {
        private const string KnownDllsKey = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs";
        private const string SessionManagerKey = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager";
        private const string ExcludeValue = "ExcludeFromKnownDlls";
        private const string SystemDll = "ntdll.dll";

        internal const string NativeDirectory = @"C:\Windows\System32";
        internal const string Wow64Directory = @"C:\Windows\SysWOW64";

        private HashSet<string> Native;
        private HashSet<string> Wow64;

        public bool Contains(WinSysHelper WinHelper, bool Wow64Set, string FileName)
        {
            HashSet<string> Names = Wow64Set
                ? Wow64 ??= Build(WinHelper, Wow64Directory)
                : Native ??= Build(WinHelper, NativeDirectory);

            return Names.Contains(FileName);
        }

        private static HashSet<string> Build(WinSysHelper WinHelper, string Directory)
        {
            HashSet<string> Excluded = ReadStrings(WinHelper, SessionManagerKey, ExcludeValue);
            HashSet<string> Names = new(StringComparer.OrdinalIgnoreCase);
            HashSet<string> Seen = new(StringComparer.OrdinalIgnoreCase) { SystemDll };
            Queue<string> Pending = new();
            List<string> Imports = new();

            foreach (string Listed in ReadListed(WinHelper))
            {
                if (Seen.Add(Listed))
                    Pending.Enqueue(Listed);
            }

            // NT: ntdll.dll is in both directories, though smss never walks it as an import.
            if (TryResolveImage(Directory, SystemDll, out _))
                Names.Add(SystemDll);

            while (Pending.TryDequeue(out string Name))
            {
                if (Excluded.Count != 0 && (Excluded.Contains(Name) || Excluded.Contains(Path.GetFileNameWithoutExtension(Name))))
                    continue;

                if (!TryResolveImage(Directory, Name, out string HostPath))
                    continue;

                Names.Add(Name);
                Imports.Clear();
                if (!BinaryFile.TryReadImportNames(HostPath, Imports))
                    continue;

                foreach (string Import in Imports)
                {
                    string Module = Import;
                    if (BinaryEmulator.TryResolveApiSetHost(Import, Name, out string Host))
                        Module = Host;

                    if (Module.Length != 0 && Seen.Add(Module))
                        Pending.Enqueue(Module);
                }
            }

            return Names;
        }

        private static bool TryResolveImage(string Directory, string Name, out string HostPath)
        {
            HostPath = null;
            if (Name.Length == 0 || Name.AsSpan().IndexOfAny("\\/:\0") >= 0)
                return false;

            HostPath = GeneralHelper.IO.ResolveHostPath(Directory + "\\" + Name, BinaryFormat.PE, NativeSystemView: true);
            return !string.IsNullOrEmpty(HostPath) && GeneralHelper.IO.HostPathExists(HostPath);
        }

        private static List<string> ReadListed(WinSysHelper WinHelper)
        {
            List<string> Listed = new();
            WinRegKey Key = WinHelper.ResolveRegistryKey(KnownDllsKey);
            if (Key == null)
                return Listed;

            for (int Index = 0; WinHelper.TryEnumerateRegistryValueFull(Key, Index, out _, out int Type, out byte[] Data); Index++)
            {
                if (Type != WinSysHelper.RegSz && Type != WinSysHelper.RegExpandSz)
                    continue;

                string FileName = WinSysHelper.DecodeRegistryString(Data);
                if (FileName.Length != 0)
                    Listed.Add(FileName);
            }

            return Listed;
        }

        private static HashSet<string> ReadStrings(WinSysHelper WinHelper, string KeyPath, string ValueName)
        {
            HashSet<string> Strings = new(StringComparer.OrdinalIgnoreCase);
            if (!WinHelper.TryReadRegistryValue(KeyPath, ValueName, out ValueNode Value) || Value.Type != WinSysHelper.RegMultiSz || Value.Data == null)
                return Strings;

            string Text = MemoryMarshal.Cast<byte, char>(Value.Data.AsSpan(0, Value.Data.Length & ~1)).ToString();
            foreach (string Entry in Text.Split('\0', StringSplitOptions.RemoveEmptyEntries))
                Strings.Add(Entry);

            return Strings;
        }
    }
}
