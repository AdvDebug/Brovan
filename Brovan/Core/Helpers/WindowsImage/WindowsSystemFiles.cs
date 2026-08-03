using System;
using System.Collections.Generic;
using System.IO;
using Brovan.Core.Helpers;

namespace Brovan.Core.Helpers.WindowsImage
{
    internal static class WindowsSystemFiles
    {
        public const string PackPrefix = @"\\?\brovanpack\";
        public const string PackFileName = "WindowsLibs.pack";
        public const string RegistryDirectory = "WinReg";

        private static WindowsPackReader? Pack;

        public static bool UsingPack => Pack != null;

        public static void Initialize(string BaseDirectory)
        {
            if (Pack != null)
                return;

            string Path = System.IO.Path.Combine(BaseDirectory, PackFileName);
            if (!File.Exists(Path))
                return;

            try
            {
                Pack = new WindowsPackReader(Path);
            }
            catch (Exception Error)
            {
                Pack = null;
                Utils.LogError($"[WindowsSystemFiles] Ignoring '{Path}': {Error.Message}");
            }
        }

        public static bool IsPackPath(string? Path)
        {
            return Path != null && Path.StartsWith(PackPrefix, StringComparison.OrdinalIgnoreCase);
        }

        public static string MakePackPath(string Relative)
        {
            return PackPrefix + Relative.Replace('/', '\\');
        }

        private static string ToEntryName(string PackPath)
        {
            return PackPath.Substring(PackPrefix.Length).Replace('\\', '/');
        }

        /// <summary>
        /// Maps a path relative to the WindowsLibs root onto a pack path, or null when the pack has no such entry.
        /// </summary>
        public static string? TryResolveRelative(string Relative)
        {
            if (Pack == null || string.IsNullOrEmpty(Relative))
                return null;

            string Name = Relative.Replace('\\', '/').TrimStart('/');
            return Pack.TryGetEntry(Name, out _) ? MakePackPath(Name) : null;
        }

        public static string? TryResolveRegistryHive(string HiveName)
        {
            return TryResolveRelative(RegistryDirectory + "/" + HiveName);
        }

        public static IReadOnlyList<string> ListRegistryHives()
        {
            if (Pack == null)
                return Array.Empty<string>();

            IReadOnlyList<string> Names = Pack.ListDirectory(RegistryDirectory);
            string[] Result = new string[Names.Count];

            for (int i = 0; i < Names.Count; i++)
                Result[i] = Names[i].Substring(RegistryDirectory.Length + 1);

            return Result;
        }

        public static void AddIndexEntries(Dictionary<string, string> Index)
        {
            if (Pack == null)
                return;

            foreach (string Name in Pack.ListDirectory(string.Empty))
                Index.TryAdd(System.IO.Path.GetFileName(Name), MakePackPath(Name));

            foreach (string Name in Pack.ListDirectory("SysWOW64"))
                Index.TryAdd(System.IO.Path.GetFileName(Name), MakePackPath(Name));
        }

        public static bool FileExists(string PackPath)
        {
            return Pack != null && Pack.TryGetEntry(ToEntryName(PackPath), out _);
        }

        public static bool DirectoryExists(string PackPath)
        {
            return Pack != null && Pack.DirectoryExists(ToEntryName(PackPath));
        }

        public static long GetLength(string PackPath)
        {
            if (Pack == null || !Pack.TryGetEntry(ToEntryName(PackPath), out WindowsPackEntry Entry))
                return 0;

            return Entry.Length;
        }

        public static byte[] ReadAll(string PackPath)
        {
            if (Pack == null || !Pack.TryGetEntry(ToEntryName(PackPath), out WindowsPackEntry Entry))
                throw new FileNotFoundException($"The pack has no entry for '{PackPath}'.");

            return Pack.ReadAll(Entry);
        }

        public static int Read(string PackPath, long Offset, Span<byte> Buffer)
        {
            if (Pack == null || !Pack.TryGetEntry(ToEntryName(PackPath), out WindowsPackEntry Entry))
                return 0;

            return Pack.Read(Entry, Offset, Buffer);
        }
    }
}
