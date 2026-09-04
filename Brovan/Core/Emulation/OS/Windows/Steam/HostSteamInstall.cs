using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static class HostSteamInstall
    {
        public static string ClientLibrary => GeneralHelper.IsWindows ? "steamclient64.dll" : "steamclient.so";

        public static string[] SupportLibraries => GeneralHelper.IsWindows
            ? new[] { "tier0_s64.dll", "vstdlib_s64.dll" }
            : Array.Empty<string>();

        public static bool TryLocate(out string Directory, out string Error)
        {
            Directory = null;
            Error = null;

            // Valve publishes the client for x86-64 only, and the bridge calls it in process.
            if (RuntimeInformation.ProcessArchitecture != Architecture.X64)
            {
                Error = $"the Steam client is not published for {RuntimeInformation.ProcessArchitecture}";
                return false;
            }

            foreach (string Candidate in Candidates())
            {
                if (string.IsNullOrEmpty(Candidate))
                    continue;

                if (File.Exists(Path.Combine(Candidate, ClientLibrary)))
                {
                    Directory = Candidate;
                    return true;
                }
            }

            Error = "no Steam client library was found on this host";
            return false;
        }

        private static IEnumerable<string> Candidates()
        {
            string Override = Environment.GetEnvironmentVariable("BROVAN_STEAM_PATH");
            if (!string.IsNullOrEmpty(Override))
                yield return Override;

            if (GeneralHelper.IsWindows)
            {
                yield return Path.Combine(Environment.GetEnvironmentVariable("ProgramFiles(x86)") ?? "C:\\Program Files (x86)", "Steam");
                yield return Path.Combine(Environment.GetEnvironmentVariable("ProgramFiles") ?? "C:\\Program Files", "Steam");
                yield break;
            }

            string Compat = Environment.GetEnvironmentVariable("STEAM_COMPAT_CLIENT_INSTALL_PATH");
            if (!string.IsNullOrEmpty(Compat))
            {
                yield return Path.Combine(Compat, "linux64");
                yield return Compat;
            }

            string Home = Environment.GetEnvironmentVariable("HOME");
            if (string.IsNullOrEmpty(Home))
                yield break;

            yield return Path.Combine(Home, ".steam", "sdk64");
            yield return Path.Combine(Home, ".steam", "steam", "linux64");
            yield return Path.Combine(Home, ".local", "share", "Steam", "linux64");
        }
    }
}
