using System;
using System.Collections.Generic;
using System.IO;

namespace Brovan.Core.Helpers.WindowsImage
{
    /// <summary>
    /// Pulls the Windows system files Brovan needs out of installation media. The media is read through
    /// <see cref="ImageDataSource"/>, so a remote ISO is fetched a block at a time and the parts that are not
    /// extracted are never transferred at all.
    /// </summary>
    internal static class WindowsImageImporter
    {
        private const string System32Path = "Windows/System32";
        private const string SysWow64Path = "Windows/SysWOW64";
        private const string ConfigPath = "Windows/System32/config";
        private const string DefaultUserHive = "Users/Default/NTUSER.DAT";

        private static readonly string[] RegistryHives = { "SOFTWARE", "SYSTEM", "DEFAULT", "SAM", "SECURITY" };

        private interface IImportSink
        {
            void Write(string Name, Sha1Hash Hash, ImageDataSource Data);

            void Complete();
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

        public static void Import(ImageDataSource Media, string BaseDirectory, int ImageIndex, bool BuildPack, Action<string> Report, Action<long, long, long, long>? Progress = null)
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
                    CollectFile(Contents, ConfigPath + "/" + Hive, WindowsSystemFiles.RegistryDirectory + "/" + Hive, Files, Report);

                CollectFile(Contents, DefaultUserHive, WindowsSystemFiles.RegistryDirectory + "/NTUSER.DAT", Files, Report);
            }

            Files.Sort(static (Left, Right) =>
            {
                int Order = Left.Blob.Resource.Offset.CompareTo(Right.Blob.Resource.Offset);
                return Order != 0 ? Order : Left.Blob.OffsetInResource.CompareTo(Right.Blob.OffsetInResource);
            });

            IImportSink Sink = BuildPack
                ? new PackSink(Path.Combine(BaseDirectory, WindowsSystemFiles.PackFileName))
                : new DirectorySink(BaseDirectory);

            try
            {
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
                        Sink.Write(File.Name, File.Blob.Hash, Data);
                        Bytes += Data.Length;
                    }

                    if (((i + 1) % 250) == 0)
                        Report($"[*] {i + 1} of {Files.Count} files, {Bytes / (1024 * 1024)} MB.");

                    if (Progress != null && (((i + 1) % 16) == 0 || i + 1 == Files.Count))
                        Progress(i + 1, Files.Count, Bytes, Total);
                }

                Sink.Complete();
                Report($"[+] Imported {Files.Count} files ({Bytes / (1024 * 1024)} MB uncompressed).");
            }
            finally
            {
                (Sink as IDisposable)?.Dispose();
            }
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

        private sealed class DirectorySink : IImportSink
        {
            private readonly string BaseDirectory;

            public DirectorySink(string BaseDirectory)
            {
                this.BaseDirectory = BaseDirectory;
            }

            public void Write(string Name, Sha1Hash Hash, ImageDataSource Data)
            {
                string Relative = Name.StartsWith(WindowsSystemFiles.RegistryDirectory + "/", StringComparison.OrdinalIgnoreCase)
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

            public void Complete()
            {
            }
        }

        private sealed class PackSink : IImportSink, IDisposable
        {
            private readonly WindowsPackWriter Writer;

            public PackSink(string Path)
            {
                Writer = new WindowsPackWriter(Path);
            }

            public void Write(string Name, Sha1Hash Hash, ImageDataSource Data)
            {
                if (Writer.TryAddDeduplicated(Name, Hash))
                    return;

                Writer.Add(Name, Hash, Data);
            }

            public void Complete()
            {
                Writer.Complete();
            }

            public void Dispose()
            {
                Writer.Dispose();
            }
        }
    }
}
