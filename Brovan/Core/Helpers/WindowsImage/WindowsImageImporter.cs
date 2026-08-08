using System;
using System.Collections.Generic;
using System.IO;
using Brovan.Core;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Helpers.WindowsImage
{
    /// <summary>
    /// Pulls the Windows system files Brovan needs out of installation media. The media is read through
    /// <see cref="ImageDataSource"/>, so a remote ISO is fetched a block at a time and the parts that are not
    /// extracted are never transferred at all.
    /// </summary>
    internal static class WindowsImageImporter
    {
        public const string RegistryDirectory = "WinReg";

        private const string System32Path = "Windows/System32";
        private const string SysWow64Path = "Windows/SysWOW64";
        private const string ConfigPath = "Windows/System32/config";
        private const string DefaultUserHive = "Users/Default/NTUSER.DAT";

        private static readonly string[] RegistryHives = { "SOFTWARE", "SYSTEM", "DEFAULT", "SAM", "SECURITY" };

        private const string ApiSetSchemaName = "apisetschema.dll";
        private const string ApiSetSectionName = ".apiset";

        public static bool TryReadApiSetMap(string LibrariesDirectory, out byte[] Map)
        {
            Map = Array.Empty<byte>();

            string SchemaPath = Path.Combine(LibrariesDirectory, ApiSetSchemaName);
            if (!File.Exists(SchemaPath))
                return false;

            using BinaryFile Schema = new BinaryFile(SchemaPath, true);
            if (Schema.FileFormat != BinaryFormat.PE || Schema.PE.Sections == null)
                return false;

            foreach (PortableBinarySection Section in Schema.PE.Sections)
            {
                if (!string.Equals(Section.SectionName, ApiSetSectionName, StringComparison.Ordinal))
                    continue;

                byte[] Data = Schema.GetBinaryData().ToArray();
                long End = (long)Section.RawOffset + Section.RawSize;
                if (Section.RawSize == 0 || End > Data.Length)
                    return false;

                // VirtualSize is the meaningful length; RawSize is padded to file alignment.
                int Length = Section.VirtualSize != 0 && Section.VirtualSize < Section.RawSize
                    ? (int)Section.VirtualSize
                    : (int)Section.RawSize;

                Map = new byte[Length];
                Array.Copy(Data, (int)Section.RawOffset, Map, 0, Length);
                return true;
            }

            return false;
        }

        /// <summary>
        /// Writes apisetmap.bin from the imported apisetschema.dll. Returns false when the
        /// image had no schema to read, leaving the caller's existing map alone.
        /// </summary>
        public static bool TryWriteApiSetMap(string BaseDirectory, Action<string> Report)
        {
            if (!TryReadApiSetMap(Path.Combine(BaseDirectory, "WindowsLibs"), out byte[] Map))
                return false;

            File.WriteAllBytes(Path.Combine(BaseDirectory, "apisetmap.bin"), Map);
            Report?.Invoke($"[+] Wrote apisetmap.bin from the image's apisetschema.dll ({Map.Length} bytes).");
            return true;
        }

        private readonly struct PendingFile
        {
            public readonly string Name;
            public readonly WimBlob Blob;

            public PendingFile(string Name, WimBlob Blob)
            {
                this.Name = Name;
                this.Blob = Blob;
            }
        }

        public static void Import(ImageDataSource Media, string BaseDirectory, int ImageIndex, Action<string> Report, Action<long, long, long, long>? Progress = null)
        {
            using ImageDataSource Image = OpenWindowsImage(Media, Report);
            using WimReader Reader = new WimReader(Image);

            if (ImageIndex < 1)
                ImageIndex = 1;

            Report($"[*] {Reader.Compression} image, {Reader.ImageCount} edition(s), reading edition {ImageIndex}.");

            List<PendingFile> Files = new List<PendingFile>();

            using (WimImage Contents = Reader.OpenImage(ImageIndex))
            {
                CollectDirectory(Contents, System32Path, string.Empty, Files, Report);
                CollectDirectory(Contents, SysWow64Path, "SysWOW64/", Files, Report);

                foreach (string Hive in RegistryHives)
                    CollectFile(Contents, ConfigPath + "/" + Hive, RegistryDirectory + "/" + Hive, Files, Report);

                CollectFile(Contents, DefaultUserHive, RegistryDirectory + "/NTUSER.DAT", Files, Report);
            }

            Files.Sort(static (Left, Right) =>
            {
                int Order = Left.Blob.Resource.Offset.CompareTo(Right.Blob.Resource.Offset);
                return Order != 0 ? Order : Left.Blob.OffsetInResource.CompareTo(Right.Blob.OffsetInResource);
            });

            WimResource? Current = null;
            long Bytes = 0;
            long Total = 0;

            for (int i = 0; i < Files.Count; i++)
                Total += Files[i].Blob.Size;

            for (int i = 0; i < Files.Count; i++)
            {
                PendingFile File = Files[i];

                if (!ReferenceEquals(File.Blob.Resource, Current))
                {
                    Reader.ReleaseDecoders();
                    Current = File.Blob.Resource;
                }

                using (ImageDataSource Data = Reader.OpenBlob(File.Blob))
                {
                    Extract(BaseDirectory, File.Name, Data);
                    Bytes += Data.Length;
                }

                if (((i + 1) % 250) == 0)
                    Report($"[*] {i + 1} of {Files.Count} files, {Bytes / (1024 * 1024)} MB.");

                if (Progress != null && (((i + 1) % 16) == 0 || i + 1 == Files.Count))
                    Progress(i + 1, Files.Count, Bytes, Total);
            }

            Report($"[+] Imported {Files.Count} files ({Bytes / (1024 * 1024)} MB).");
        }

        /// <summary>
        /// Accepts either an ISO holding sources/install.wim (or install.esd) or a bare WIM.
        /// </summary>
        private static ImageDataSource OpenWindowsImage(ImageDataSource Media, Action<string> Report)
        {
            Span<byte> Magic = stackalloc byte[8];
            Media.ReadExact(0, Magic);

            if (Magic.SequenceEqual("MSWIM\0\0\0"u8))
                return new WindowImageDataSource(Media, 0, Media.Length);

            IsoReader Iso = IsoReader.Open(Media);

            if (Iso.TryOpenFile("sources/install.wim", out ImageDataSource Wim))
            {
                Report($"[*] Found sources/install.wim ({Wim.Length / (1024 * 1024)} MB).");
                return Wim;
            }

            if (Iso.TryOpenFile("sources/install.esd", out ImageDataSource Esd))
            {
                Report($"[*] Found sources/install.esd ({Esd.Length / (1024 * 1024)} MB).");
                return Esd;
            }

            throw new FileNotFoundException("The media contains neither sources/install.wim nor sources/install.esd.");
        }

        private static void CollectDirectory(WimImage Contents, string SourcePath, string Prefix, List<PendingFile> Files, Action<string> Report)
        {
            if (!Contents.TryFindFile(SourcePath, out WimDirectoryEntry Directory) || !Directory.IsDirectory)
            {
                Report($"[-] The image has no {SourcePath} directory.");
                return;
            }

            List<WimDirectoryEntry> Entries = new List<WimDirectoryEntry>();
            Contents.ListDirectory(Directory.SubdirectoryOffset, Entries);

            for (int i = 0; i < Entries.Count; i++)
            {
                WimDirectoryEntry Entry = Entries[i];

                if (Entry.IsDirectory || Entry.IsReparsePoint || Entry.Hash.IsZero || !IsWanted(Entry.Name))
                    continue;

                WimBlob? Blob = Contents.FindBlob(Entry);

                if (Blob == null)
                    Report($"[-] {SourcePath}/{Entry.Name} has no data in the image.");
                else
                    Files.Add(new PendingFile(Prefix + Entry.Name, Blob));
            }
        }

        private static void CollectFile(WimImage Contents, string SourcePath, string Name, List<PendingFile> Files, Action<string> Report)
        {
            if (!Contents.TryFindFile(SourcePath, out WimDirectoryEntry Entry) || Entry.Hash.IsZero)
            {
                Report($"[-] The image has no {SourcePath}.");
                return;
            }

            WimBlob? Blob = Contents.FindBlob(Entry);

            if (Blob == null)
                Report($"[-] {SourcePath} has no data in the image.");
            else
                Files.Add(new PendingFile(Name, Blob));
        }

        private static bool IsWanted(string Name)
        {
            return Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                   Name.EndsWith(".nls", StringComparison.OrdinalIgnoreCase);
        }

        private static void Extract(string BaseDirectory, string Name, ImageDataSource Data)
        {
            string Relative = Name.StartsWith(RegistryDirectory + "/", StringComparison.OrdinalIgnoreCase)
                ? Name
                : "WindowsLibs/" + Name;

            string Target = Path.Combine(BaseDirectory, Relative.Replace('/', Path.DirectorySeparatorChar));
            string? Parent = Path.GetDirectoryName(Target);

            if (!string.IsNullOrEmpty(Parent))
                Directory.CreateDirectory(Parent);

            using FileStream Output = new FileStream(Target, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);

            byte[] Buffer = System.Buffers.ArrayPool<byte>.Shared.Rent(1 << 20);

            try
            {
                long Position = 0;

                while (Position < Data.Length)
                {
                    int Count = Data.Read(Position, Buffer.AsSpan(0, (int)Math.Min(Buffer.Length, Data.Length - Position)));
                    if (Count <= 0)
                        throw new EndOfStreamException($"'{Name}' ended before its declared length.");

                    Output.Write(Buffer, 0, Count);
                    Position += Count;
                }
            }
            finally
            {
                System.Buffers.ArrayPool<byte>.Shared.Return(Buffer);
            }
        }
    }
}
