using System;
using System.IO;
using System.Text.RegularExpressions;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class SteamAppContext
    {
        public const string GuestDirectory = "C:\\Program Files (x86)\\Steam";
        public const string GuestExe = GuestDirectory + "\\steam.exe";
        public const string GuestClientDll64 = GuestDirectory + "\\steamclient64.dll";

        public uint AppId;
        public uint ClientPid;
        public ulong SteamId;
        public bool Enabled;

        public static SteamAppContext Resolve(BinaryEmulator Instance, uint ClientPid)
        {
            SteamAppContext Context = new SteamAppContext { ClientPid = ClientPid };

            string ImagePath = Instance?._binary?.Location;
            if (string.IsNullOrEmpty(ImagePath))
                return Context;

            uint AppId = ReadAppIdFile(ImagePath);
            if (AppId == 0)
                AppId = ReadLibraryManifest(ImagePath);

            if (AppId == 0)
                return Context;

            Context.AppId = AppId;

            if (!NativeSteamClient.TryStart(AppId, out string Error))
            {
                Instance.TriggerEventMessage($"[BrovSteam] app {AppId} runs without Steam, {Error}.", LogFlags.Issues);
                return Context;
            }

            Context.SteamId = NativeSteamClient.AccountSteamId;
            Context.Enabled = true;
            Instance.TriggerEventMessage($"[BrovSteam] app {AppId} on account {Context.SteamId}.", LogFlags.General);
            return Context;
        }

        private static uint ReadAppIdFile(string ImagePath)
        {
            try
            {
                string Directory = Path.GetDirectoryName(ImagePath);
                if (string.IsNullOrEmpty(Directory))
                    return 0;

                string File = Path.Combine(Directory, "steam_appid.txt");
                if (!System.IO.File.Exists(File))
                    return 0;

                return uint.TryParse(System.IO.File.ReadAllText(File).Trim(), out uint Value) ? Value : 0;
            }
            catch
            {
                return 0;
            }
        }

        private static uint ReadLibraryManifest(string ImagePath)
        {
            try
            {
                DirectoryInfo Current = new DirectoryInfo(Path.GetDirectoryName(Path.GetFullPath(ImagePath)));
                while (Current != null)
                {
                    DirectoryInfo Parent = Current.Parent;
                    if (Parent != null &&
                        string.Equals(Parent.Name, "common", StringComparison.OrdinalIgnoreCase) &&
                        Parent.Parent != null &&
                        string.Equals(Parent.Parent.Name, "steamapps", StringComparison.OrdinalIgnoreCase))
                    {
                        return MatchManifest(Parent.Parent.FullName, Current.Name);
                    }

                    Current = Parent;
                }
            }
            catch
            {
            }

            return 0;
        }

        private static uint MatchManifest(string SteamApps, string InstallDirectory)
        {
            foreach (string File in Directory.GetFiles(SteamApps, "appmanifest_*.acf"))
            {
                string Text;
                try
                {
                    Text = System.IO.File.ReadAllText(File);
                }
                catch
                {
                    continue;
                }

                Match Install = Regex.Match(Text, "\"installdir\"\\s+\"([^\"]*)\"");
                if (!Install.Success || !string.Equals(Install.Groups[1].Value, InstallDirectory, StringComparison.OrdinalIgnoreCase))
                    continue;

                Match AppId = Regex.Match(Text, "\"appid\"\\s+\"(\\d+)\"");
                if (AppId.Success && uint.TryParse(AppId.Groups[1].Value, out uint Value))
                    return Value;
            }

            return 0;
        }
    }
}
