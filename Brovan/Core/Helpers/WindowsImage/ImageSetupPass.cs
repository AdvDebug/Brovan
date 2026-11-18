using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using static Brovan.Core.Emulation.OS.Windows.WinSysHelper;

namespace Brovan.Core.Helpers.WindowsImage
{
    internal static class ImageSetupPass
    {
        private const string CurrentVersionPath = "\\Microsoft\\Windows NT\\CurrentVersion";

        private readonly record struct Rewrite(string KeyPath, string OldName, string NewName, int Type, byte[] Data);

        public static bool Run(string HiveDirectory, IReadOnlyList<string> HiveNames, Action<string> Report)
        {
            if (!TryReadSystemDrive(Path.Combine(HiveDirectory, "SOFTWARE"), out char Drive))
            {
                Report("[-] The image's SOFTWARE hive has no SystemRoot to take its drive from.");
                return false;
            }

            if (char.ToUpperInvariant(Drive) != 'C')
            {
                foreach (string Name in HiveNames)
                {
                    if (!RewriteDrive(Path.Combine(HiveDirectory, Name), Drive, Report))
                        return false;
                }
            }

            return SetInstalledState(HiveDirectory, Report);
        }

        private static bool TryReadSystemDrive(string SoftwarePath, out char Drive)
        {
            Drive = '\0';
            using Hive Software = RegistryManager.OpenOffline(SoftwarePath);
            if (Software == null || !Software.TryGetValue(CurrentVersionPath, "SystemRoot", out ValueNode Value) || Value.Data == null)
                return false;

            string Root = Encoding.Unicode.GetString(Value.Data, 0, Value.Data.Length & ~1);
            if (Root.Length < 3 || !char.IsAsciiLetter(Root[0]) || Root[1] != ':' || Root[2] != '\\')
                return false;

            Drive = Root[0];
            return true;
        }

        private static Hive OpenForSetup(string HivePath, Action<string> Report)
        {
            Hive Target = RegistryManager.OpenOffline(HivePath);
            if (Target == null)
                Report($"[-] Could not open {Path.GetFileName(HivePath)} to finish its setup.");
            return Target;
        }

        private static bool RewriteDrive(string HivePath, char Drive, Action<string> Report)
        {
            if (!File.Exists(HivePath))
                return true;

            using Hive Target = OpenForSetup(HivePath, Report);
            if (Target == null)
                return false;

            List<Rewrite> Rewrites = CollectRewrites(Target.Reader, Drive);
            if (Rewrites.Count == 0)
                return true;

            bool Applied = Target.TryUpdate(Update =>
            {
                foreach (Rewrite Item in Rewrites)
                {
                    if (!string.Equals(Item.OldName, Item.NewName, StringComparison.Ordinal)
                        && !Update.TryDeleteValue(Item.KeyPath, Item.OldName))
                        return false;

                    if (!Update.TrySetValue(Item.KeyPath, Item.NewName, Item.Type, Item.Data))
                        return false;
                }

                return true;
            }, new List<HiveChange>(Rewrites.Count));

            if (!Applied)
                Report($"[-] Could not rewrite the {Drive}: paths in {Path.GetFileName(HivePath)}.");

            return Applied;
        }

        private static List<Rewrite> CollectRewrites(RegistryHiveReader Reader, char Drive)
        {
            List<Rewrite> Rewrites = new List<Rewrite>();
            Stack<(RegistryHiveReader.HiveKey Key, string Path)> Pending = new Stack<(RegistryHiveReader.HiveKey, string)>();
            HashSet<int> Visited = new HashSet<int>();
            Pending.Push((Reader.GetRootKey(), string.Empty));

            while (Pending.Count != 0)
            {
                (RegistryHiveReader.HiveKey Key, string KeyPath) = Pending.Pop();

                // The hive comes from the media, so a subkey list that names an ancestor must not loop.
                if (!Visited.Add(Key.KeyBlockAbs))
                    continue;

                if (Reader.TryQueryKeyHeader(Key, out _, out int ValueCount, out _))
                {
                    string WritePath = KeyPath.Length == 0 ? "\\" : KeyPath;
                    for (int Index = 0; Index < ValueCount; Index++)
                    {
                        if (!Reader.TryEnumerateValueFull(Key, Index, out string Name, out int Type, out byte[] Data))
                            continue;

                        Name ??= string.Empty;
                        string NewName = ReplaceDrive(Name, Drive);
                        byte[] NewData = IsStringType(Type) && Data != null ? ReplaceDrive(Data, Drive) : Data;

                        if (!ReferenceEquals(NewName, Name) || !ReferenceEquals(NewData, Data))
                            Rewrites.Add(new Rewrite(WritePath, Name, NewName, Type, NewData ?? Array.Empty<byte>()));
                    }
                }

                if (!Reader.TryGetSubKeyNames(ref Key, out Dictionary<string, int> Names))
                    continue;

                foreach (string SubKeyName in Names.Keys)
                {
                    if (Reader.TryGetSubKey(Key, SubKeyName, out RegistryHiveReader.HiveKey Child))
                        Pending.Push((Child, KeyPath + "\\" + SubKeyName));
                }
            }

            return Rewrites;
        }

        private static bool IsStringType(int Type) => Type == RegSz || Type == RegExpandSz || Type == RegMultiSz;

        private static bool IsDriveAt(ReadOnlySpan<char> Text, int Index, char Drive)
        {
            return char.ToUpperInvariant(Text[Index]) == char.ToUpperInvariant(Drive)
                && Index + 2 < Text.Length
                && Text[Index + 1] == ':'
                && Text[Index + 2] == '\\'
                && (Index == 0 || !char.IsLetterOrDigit(Text[Index - 1]));
        }

        private static string ReplaceDrive(string Text, char Drive)
        {
            char[] Copy = null;
            for (int Index = 0; Index < Text.Length; Index++)
            {
                if (!IsDriveAt(Text, Index, Drive))
                    continue;

                Copy ??= Text.ToCharArray();
                Copy[Index] = 'C';
            }

            return Copy == null ? Text : new string(Copy);
        }

        // Patches the UTF-16 code units, so terminators and an odd trailing byte stay as they are.
        private static byte[] ReplaceDrive(byte[] Data, char Drive)
        {
            ReadOnlySpan<char> Text = MemoryMarshal.Cast<byte, char>(Data.AsSpan(0, Data.Length & ~1));
            byte[] Copy = null;
            for (int Index = 0; Index < Text.Length; Index++)
            {
                if (!IsDriveAt(Text, Index, Drive))
                    continue;

                Copy ??= (byte[])Data.Clone();
                Copy[Index * 2] = (byte)'C';
                Copy[(Index * 2) + 1] = 0;
            }

            return Copy ?? Data;
        }

        private static bool SetInstalledState(string HiveDirectory, Action<string> Report)
        {
            DateTimeOffset Now = DateTimeOffset.UtcNow;
            byte[] Zero = BitConverter.GetBytes(0u);

            return SetValues(Path.Combine(HiveDirectory, "SYSTEM"), Report, Update =>
                SetExisting(Update, Report, "\\Setup", "SystemSetupInProgress", RegDword, Zero)
                && SetExisting(Update, Report, "\\Setup", "OOBEInProgress", RegDword, Zero)
                && SetExisting(Update, Report, "\\Setup", "SetupPhase", RegDword, Zero)
                && SetExisting(Update, Report, "\\Setup", "SetupType", RegDword, Zero)
                && SetExisting(Update, Report, "\\Setup", "CmdLine", RegSz, Encoding.Unicode.GetBytes("\0"))
                && SetExisting(Update, Report, "\\Setup\\Status\\SysprepStatus", "GeneralizationState", RegDword, BitConverter.GetBytes(7u)))
            && SetValues(Path.Combine(HiveDirectory, "SOFTWARE"), Report, Update =>
            {
                byte[] Complete = Encoding.Unicode.GetBytes("IMAGE_STATE_COMPLETE\0");
                return SetExisting(Update, Report, "\\Microsoft\\Windows\\CurrentVersion\\Setup\\State", "ImageState", RegSz, Complete)
                    && SetExisting(Update, Report, "\\Microsoft\\Windows\\CurrentVersion\\Setup\\ImageServicingData", "ImageState", RegSz, Complete)
                    && SetExisting(Update, Report, CurrentVersionPath, "PendingInstall", RegDword, Zero)
                    && SetExisting(Update, Report, CurrentVersionPath, "InstallDate", RegDword, BitConverter.GetBytes((uint)Now.ToUnixTimeSeconds()))
                    && Update.TrySetValue(CurrentVersionPath, "InstallTime", RegQword, BitConverter.GetBytes(Now.ToFileTime()));
            });
        }

        private static bool SetValues(string HivePath, Action<string> Report, Func<HiveUpdate, bool> Apply)
        {
            using Hive Target = OpenForSetup(HivePath, Report);
            if (Target == null)
                return false;

            if (Target.TryUpdate(Apply, new List<HiveChange>()))
                return true;

            Report($"[-] Could not set the installed state in {Path.GetFileName(HivePath)}.");
            return false;
        }

        private static bool SetExisting(HiveUpdate Update, Action<string> Report, string KeyPath, string Name, int Type, byte[] Data)
        {
            if (!Update.TryGetValue(KeyPath, Name, out _))
            {
                Report($"[!] The image has no {KeyPath}\\{Name} to set.");
                return true;
            }

            return Update.TrySetValue(KeyPath, Name, Type, Data);
        }
    }
}
