using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;
using Brovan.Core;
using Brovan.Core.Emulation.OS.Windows.Win32k;
using Microsoft.Win32.SafeHandles;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Helpers.WindowsImage
{
    /// <summary>
    /// Pulls the Windows system files Brovan needs out of installation media. The media is read in place through
    /// <see cref="ImageDataSource"/>, and the parts that are not extracted are never read.
    /// </summary>
    internal static class WindowsImageImporter
    {
        public const string RegistryDirectory = "WinReg";
        public const string SystemRootDirectory = "SystemRoot";
        public const string LibrariesDirectory = "WindowsLibs";

        // The C:\Windows folders that WindowsLibs holds. SystemRoot holds the rest.
        public static readonly string[] LibraryFolders = { "System32", "SysWOW64" };

        private const string WindowsPath = "Windows";
        private const string System32Path = "Windows/System32";
        private const string SysWow64Path = "Windows/SysWOW64";
        private const string ConfigPath = "Windows/System32/config";

        // SystemRoot/owned lists the WindowsLibs folders an import wrote, for the next import to remove. A rule that
        // adds files raises CurrentLayout, and imports from OldestServedLayout on still load.
        private const string LayoutFileName = "layout";
        private const string OwnedListFileName = "owned";
        private const int CurrentLayout = 1;
        private const int OldestServedLayout = 1;

        private enum Subdirectories
        {
            None,
            Language,
            Assembly,
        }

        private readonly record struct ImportRule(string Directory, Subdirectories Level, Func<string, bool> Takes);

        private static readonly ImportRule[] Rules =
        {
            new ImportRule(System32Path, Subdirectories.None, IsLibraryFile),
            new ImportRule(System32Path, Subdirectories.Language, static Name => HasExtension(Name, ".mui")),
            new ImportRule(SysWow64Path, Subdirectories.None, IsLibraryFile),
            new ImportRule(SysWow64Path, Subdirectories.Language, static Name => HasExtension(Name, ".mui")),
            new ImportRule("Windows/Globalization/Sorting", Subdirectories.None, static Name => HasExtension(Name, ".nls")),
            new ImportRule("Windows/SystemResources", Subdirectories.None, static Name => HasExtension(Name, ".mun")),
            new ImportRule("Windows/WinSxS", Subdirectories.Assembly, static Name => true),
            new ImportRule("Windows/WinSxS/Manifests", Subdirectories.None, IsAssemblyManifest),
            new ImportRule(WindowsPath, Subdirectories.None, static Name => string.Equals(Name, "WindowsShell.Manifest", StringComparison.OrdinalIgnoreCase)),
        };
        private const string DefaultUserHive = "Users/Default/NTUSER.DAT";

        private static readonly string[] RegistryHives = { "SOFTWARE", "SYSTEM", "DEFAULT", "SAM", "SECURITY" };

        private static readonly string[] VersionKeyFiles = { CompositionTableSet.KeyFile };

        private const int CopyBufferSize = 1 << 20;

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
            if (!TryReadApiSetMap(Path.Combine(BaseDirectory, LibrariesDirectory), out byte[] Map))
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

        /// <summary>
        /// One blob and the run of sorted files that hold it. Identical files share a blob, so it is decoded once.
        /// </summary>
        private readonly struct PendingBlob
        {
            public readonly WimBlob Blob;
            public readonly int First;
            public readonly int Count;

            public PendingBlob(WimBlob Blob, int First, int Count)
            {
                this.Blob = Blob;
                this.First = First;
                this.Count = Count;
            }
        }

        private sealed class OutputFile
        {
            public readonly string Path;
            public readonly long Length;
            public SafeFileHandle? Handle;
            public int PendingSlices;

            public OutputFile(string Path, long Length, int PendingSlices)
            {
                this.Path = Path;
                this.Length = Length;
                this.PendingSlices = PendingSlices;
            }
        }

        private readonly struct ChunkSlice
        {
            public readonly OutputFile Output;
            public readonly long FileOffset;
            public readonly int ChunkOffset;
            public readonly int Length;

            public ChunkSlice(OutputFile Output, long FileOffset, int ChunkOffset, int Length)
            {
                this.Output = Output;
                this.FileOffset = FileOffset;
                this.ChunkOffset = ChunkOffset;
                this.Length = Length;
            }
        }

        private sealed class ChunkJob
        {
            public readonly WimResourceSource Resource;
            public readonly long Index;
            public readonly List<ChunkSlice> Slices = new List<ChunkSlice>();

            public ChunkJob(WimResourceSource Resource, long Index)
            {
                this.Resource = Resource;
                this.Index = Index;
            }
        }

        /// <summary>
        /// Counts finished files for the extraction workers and calls Report and Progress one caller at a time.
        /// </summary>
        private sealed class ExtractionProgress
        {
            private readonly object Gate = new object();
            private readonly int TotalFiles;
            private readonly long TotalBytes;
            private readonly Action<string> Report;
            private readonly Action<long, long, long, long>? Progress;
            private int Files;

            public ExtractionProgress(int TotalFiles, long TotalBytes, Action<string> Report, Action<long, long, long, long>? Progress)
            {
                this.TotalFiles = TotalFiles;
                this.TotalBytes = TotalBytes;
                this.Report = Report;
                this.Progress = Progress;
            }

            public long Bytes { get; private set; }

            public void FileDone(long Length)
            {
                lock (Gate)
                {
                    Files++;
                    Bytes += Length;

                    if ((Files % 250) == 0)
                        Report($"[*] {Files} of {TotalFiles} files, {Bytes / (1024 * 1024)} MB.");

                    if (Progress != null && ((Files % 16) == 0 || Files == TotalFiles))
                        Progress(Files, TotalFiles, Bytes, TotalBytes);
                }
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
                foreach (ImportRule Rule in Rules)
                    CollectRule(Contents, Rule, Files, Report);

                foreach (string Name in VersionKeyFiles)
                {
                    string ImagePath = System32Path + "/" + Name;
                    CollectFile(Contents, ImagePath, TargetOf(ImagePath), Files, Report);
                }

                foreach (string Hive in RegistryHives)
                    CollectFile(Contents, ConfigPath + "/" + Hive, RegistryDirectory + "/" + Hive, Files, Report);

                CollectFile(Contents, DefaultUserHive, RegistryDirectory + "/NTUSER.DAT", Files, Report);
            }

            ReplaceOwnedContent(BaseDirectory, OwnedDirectories(Files));

            Files.Sort(static (Left, Right) =>
            {
                int Order = Left.Blob.Resource.Offset.CompareTo(Right.Blob.Resource.Offset);
                return Order != 0 ? Order : Left.Blob.OffsetInResource.CompareTo(Right.Blob.OffsetInResource);
            });

            long Total = 0;
            string[] Targets = new string[Files.Count];
            HashSet<string> Directories = new HashSet<string>(StringComparer.Ordinal);

            for (int i = 0; i < Files.Count; i++)
            {
                Total += Files[i].Blob.Size;
                Targets[i] = ResolveTarget(BaseDirectory, Files[i].Name);

                string? Parent = Path.GetDirectoryName(Targets[i]);
                if (!string.IsNullOrEmpty(Parent) && Directories.Add(Parent))
                    Directory.CreateDirectory(Parent);
            }

            List<PendingBlob> Loose = new List<PendingBlob>();
            List<PendingBlob> Packed = new List<PendingBlob>();

            for (int i = 0; i < Files.Count;)
            {
                WimBlob Blob = Files[i].Blob;
                int End = i + 1;

                while (End < Files.Count && ReferenceEquals(Files[End].Blob, Blob))
                    End++;

                PendingBlob Pending = new PendingBlob(Blob, i, End - i);

                if (Blob.Resource.IsSolid && Blob.Size != 0)
                    Packed.Add(Pending);
                else
                    Loose.Add(Pending);

                i = End;
            }

            ExtractionProgress Tracker = new ExtractionProgress(Files.Count, Total, Report, Progress);

            ExtractLoose(Reader, Loose, Targets, Tracker);
            ExtractPacked(Reader, Packed, Targets, Tracker);

            File.WriteAllText(Path.Combine(BaseDirectory, SystemRootDirectory, LayoutFileName), CurrentLayout.ToString(CultureInfo.InvariantCulture));
            Report($"[+] Imported {Files.Count} files ({Tracker.Bytes / (1024 * 1024)} MB).");
        }

        public static string? FindSystemRoot(string BaseDirectory, out bool Current)
        {
            Current = false;
            string Root = Path.Combine(BaseDirectory, SystemRootDirectory);
            string LayoutPath = Path.Combine(Root, LayoutFileName);
            if (!File.Exists(LayoutPath))
                return null;

            string Text;
            try
            {
                Text = File.ReadAllText(LayoutPath);
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException)
            {
                return null;
            }

            if (!int.TryParse(Text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out int Layout) || Layout < OldestServedLayout)
                return null;

            Current = Layout >= CurrentLayout;
            return Root;
        }

        private static string TargetOf(string ImagePath)
        {
            if (IsUnder(ImagePath, System32Path))
                return LibrariesDirectory + ImagePath.Substring(System32Path.Length);

            if (IsUnder(ImagePath, SysWow64Path))
                return LibrariesDirectory + "/SysWOW64" + ImagePath.Substring(SysWow64Path.Length);

            return SystemRootDirectory + ImagePath.Substring(WindowsPath.Length);
        }

        private static bool IsUnder(string ImagePath, string Directory)
            => ImagePath.Length > Directory.Length && ImagePath[Directory.Length] == '/'
               && ImagePath.StartsWith(Directory, StringComparison.OrdinalIgnoreCase);

        private static SortedSet<string> OwnedDirectories(List<PendingFile> Files)
        {
            SortedSet<string> Owned = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            string Wow64Prefix = LibrariesDirectory + "/SysWOW64/";

            foreach (PendingFile Pending in Files)
            {
                string Name = Pending.Name;
                if (!Name.StartsWith(LibrariesDirectory + "/", StringComparison.Ordinal))
                    continue;

                int Start = Name.StartsWith(Wow64Prefix, StringComparison.Ordinal) ? Wow64Prefix.Length : LibrariesDirectory.Length + 1;
                int Separator = Name.IndexOf('/', Start);
                if (Separator > 0)
                    Owned.Add(Name.Substring(0, Separator));
            }

            return Owned;
        }

        // The old owned content goes before extraction and the stamp comes last, so a killed import reads as none.
        private static void ReplaceOwnedContent(string BaseDirectory, SortedSet<string> Owned)
        {
            string Root = Path.Combine(BaseDirectory, SystemRootDirectory);
            string OwnedList = Path.Combine(Root, OwnedListFileName);

            if (System.IO.Directory.Exists(Root))
                File.Delete(Path.Combine(Root, LayoutFileName));

            if (File.Exists(OwnedList))
            {
                foreach (string Previous in File.ReadAllLines(OwnedList))
                {
                    if (TryResolveOwnedDirectory(BaseDirectory, Previous, out string Directory) && System.IO.Directory.Exists(Directory))
                        System.IO.Directory.Delete(Directory, true);
                }
            }

            if (System.IO.Directory.Exists(Root))
                System.IO.Directory.Delete(Root, true);

            System.IO.Directory.CreateDirectory(Root);
            File.WriteAllLines(OwnedList, Owned);
        }

        private static bool TryResolveOwnedDirectory(string BaseDirectory, string Line, out string Directory)
        {
            Directory = string.Empty;
            string[] Parts = Line.Trim().Split('/');

            bool Wow64 = Parts.Length == 3 && Parts[1] == "SysWOW64";
            if (Parts[0] != LibrariesDirectory || (Parts.Length != 2 && !Wow64))
                return false;

            string Name = Parts[Parts.Length - 1];
            if (!IsPlainName(Name) || (!Wow64 && string.Equals(Name, "SysWOW64", StringComparison.OrdinalIgnoreCase)))
                return false;

            Directory = Wow64
                ? Path.Combine(BaseDirectory, LibrariesDirectory, "SysWOW64", Name)
                : Path.Combine(BaseDirectory, LibrariesDirectory, Name);
            return true;
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

        private static void CollectRule(WimImage Contents, in ImportRule Rule, List<PendingFile> Files, Action<string> Report)
        {
            if (!Contents.TryFindFile(Rule.Directory, out WimDirectoryEntry Directory) || !Directory.IsDirectory)
            {
                Report($"[-] The image has no {Rule.Directory} directory.");
                return;
            }

            List<WimDirectoryEntry> Entries = new List<WimDirectoryEntry>();
            Contents.ListDirectory(Directory.SubdirectoryOffset, Entries);

            if (Rule.Level == Subdirectories.None)
            {
                CollectFiles(Contents, Rule.Directory, Entries, Rule.Takes, Files, Report);
                return;
            }

            List<WimDirectoryEntry> Children = new List<WimDirectoryEntry>();
            for (int i = 0; i < Entries.Count; i++)
            {
                WimDirectoryEntry Entry = Entries[i];
                if (!Entry.IsDirectory || Entry.IsReparsePoint || !IsPlainName(Entry.Name))
                    continue;

                bool Wanted = Rule.Level == Subdirectories.Language ? IsLanguageDirectory(Entry.Name) : IsSideBySideAssembly(Entry.Name);
                if (!Wanted)
                    continue;

                Children.Clear();
                Contents.ListDirectory(Entry.SubdirectoryOffset, Children);
                CollectFiles(Contents, Rule.Directory + "/" + Entry.Name, Children, Rule.Takes, Files, Report);
            }
        }

        private static void CollectFiles(WimImage Contents, string SourcePath, List<WimDirectoryEntry> Entries, Func<string, bool> Takes, List<PendingFile> Files, Action<string> Report)
        {
            for (int i = 0; i < Entries.Count; i++)
            {
                WimDirectoryEntry Entry = Entries[i];

                if (Entry.IsDirectory || Entry.IsReparsePoint || Entry.Hash.IsZero || !Takes(Entry.Name))
                    continue;

                if (!IsPlainName(Entry.Name))
                {
                    Report($"[-] {SourcePath} holds an entry named '{Entry.Name}', which is not a plain file name.");
                    continue;
                }

                WimBlob? Blob = Contents.FindBlob(Entry);

                if (Blob == null)
                    Report($"[-] {SourcePath}/{Entry.Name} has no data in the image.");
                else
                    Files.Add(new PendingFile(TargetOf(SourcePath + "/" + Entry.Name), Blob));
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

        private static readonly char[] NameSeparators = { '/', '\\', ':', '\0' };

        private static bool IsPlainName(string Name)
            => Name.Length != 0 && Name != "." && Name != ".." && Name.IndexOfAny(NameSeparators) < 0;

        private static bool HasExtension(string Name, string Extension)
            => Name.EndsWith(Extension, StringComparison.OrdinalIgnoreCase);

        private static bool IsLibraryFile(string Name)
            => HasExtension(Name, ".dll") || HasExtension(Name, ".nls");

        // A culture tag such as en-US, sr-Latn-RS or qps-ploc.
        private static bool IsLanguageDirectory(string Name)
        {
            string[] Tags = Name.Split('-');
            if (Tags.Length < 2 || Tags[0].Length < 2 || Tags[0].Length > 3)
                return false;

            for (int i = 0; i < Tags.Length; i++)
            {
                if (Tags[i].Length == 0 || Tags[i].Length > 8)
                    return false;

                foreach (char Character in Tags[i])
                {
                    if (!char.IsAsciiLetterOrDigit(Character) || (i == 0 && !char.IsAsciiLetter(Character)))
                        return false;
                }
            }

            return true;
        }

        // Activation contexts bind to public Win32 assemblies (key 6595b64144ccf1df). Nothing reads publisher policies.
        private static bool IsSideBySideAssembly(string Name)
            => (Name.StartsWith("amd64_", StringComparison.OrdinalIgnoreCase) || Name.StartsWith("x86_", StringComparison.OrdinalIgnoreCase))
               && Name.Contains("_6595b64144ccf1df_", StringComparison.OrdinalIgnoreCase)
               && !Name.Contains("_policy.", StringComparison.OrdinalIgnoreCase);

        private static bool IsAssemblyManifest(string Name)
            => HasExtension(Name, ".manifest") && IsSideBySideAssembly(Name.Substring(0, Name.Length - ".manifest".Length));

        private static string ResolveTarget(string BaseDirectory, string Name)
            => Path.Combine(BaseDirectory, Name.Replace('/', Path.DirectorySeparatorChar));

        private static SafeFileHandle OpenTarget(string Target, long Length)
        {
            return File.OpenHandle(Target, FileMode.Create, FileAccess.Write, FileShare.None, FileOptions.None, Length);
        }

        /// <summary>
        /// Runs <paramref name="Body"/> on up to <paramref name="Workers"/> threads, the calling thread included.
        /// Each body pulls its own work items and must stop once the loop state reports a failure in another worker.
        /// </summary>
        private static void RunWorkers(int Workers, Action<ParallelLoopState> Body)
        {
            try
            {
                Parallel.For(0, Workers, new ParallelOptions { MaxDegreeOfParallelism = Workers }, (Worker, State) => Body(State));
            }
            catch (AggregateException Error)
            {
                ExceptionDispatchInfo.Throw(Error.InnerExceptions[0]);
            }
        }

        /// <summary>
        /// Extracts blobs that own their resource, one blob per worker. Blobs are taken in image order, so reads
        /// still move forward through slow media.
        /// </summary>
        private static void ExtractLoose(WimReader Reader, List<PendingBlob> Blobs, string[] Targets, ExtractionProgress Tracker)
        {
            if (Blobs.Count == 0)
                return;

            int BufferSize = Math.Max(CopyBufferSize, Reader.ChunkSize);
            int Workers = (int)Math.Clamp(WimResourceSource.DecodeBudget / BufferSize, 1, Environment.ProcessorCount);
            int Next = -1;

            RunWorkers(Workers, State =>
            {
                byte[] Buffer = GC.AllocateUninitializedArray<byte>(BufferSize);
                int Index;

                while (!State.ShouldExitCurrentIteration && (Index = Interlocked.Increment(ref Next)) < Blobs.Count)
                    ExtractBlob(Reader, Blobs[Index], Targets, Buffer, Tracker);
            });
        }

        private static void ExtractBlob(WimReader Reader, PendingBlob Pending, string[] Targets, byte[] Buffer, ExtractionProgress Tracker)
        {
            WimBlob Blob = Pending.Blob;
            SafeFileHandle[] Outputs = new SafeFileHandle[Pending.Count];

            try
            {
                for (int i = 0; i < Outputs.Length; i++)
                    Outputs[i] = OpenTarget(Targets[Pending.First + i], Blob.Size);

                if (Blob.Size != 0)
                {
                    using ImageDataSource Data = Reader.OpenResource(Blob.Resource);

                    if (Data is WimResourceSource Chunks)
                        DecodeResource(Reader, Chunks, Outputs, Buffer);
                    else
                        CopyResource(Data, Outputs, Buffer);
                }
            }
            finally
            {
                for (int i = 0; i < Outputs.Length; i++)
                    Outputs[i]?.Dispose();
            }

            for (int i = 0; i < Outputs.Length; i++)
                Tracker.FileDone(Blob.Size);
        }

        private static void DecodeResource(WimReader Reader, WimResourceSource Chunks, SafeFileHandle[] Outputs, byte[] Buffer)
        {
            if (Chunks.ChunkSize > Buffer.Length)
                throw new InvalidDataException($"A resource declares a chunk size of {Chunks.ChunkSize} bytes against the image's {Reader.ChunkSize}.");

            int ChunksPerWrite = Buffer.Length / Chunks.ChunkSize;
            WimDecompressor Decompressor = Reader.RentDecompressor(Chunks.Resource);

            try
            {
                long Position = 0;

                for (long Chunk = 0; Chunk < Chunks.ChunkCount; Chunk += ChunksPerWrite)
                {
                    int Count = (int)Math.Min(ChunksPerWrite, Chunks.ChunkCount - Chunk);
                    int Length = (int)Math.Min((long)Count * Chunks.ChunkSize, Chunks.Length - Position);

                    Chunks.DecodeChunks(Chunk, Count, Buffer.AsSpan(0, Length), Decompressor);
                    Write(Outputs, Buffer.AsSpan(0, Length), Position);
                    Position += Length;
                }
            }
            finally
            {
                Reader.ReturnDecompressor(Decompressor);
            }
        }

        private static void CopyResource(ImageDataSource Data, SafeFileHandle[] Outputs, byte[] Buffer)
        {
            long Position = 0;

            while (Position < Data.Length)
            {
                int Count = (int)Math.Min(Buffer.Length, Data.Length - Position);
                Data.ReadExact(Position, Buffer.AsSpan(0, Count));
                Write(Outputs, Buffer.AsSpan(0, Count), Position);
                Position += Count;
            }
        }

        private static void Write(SafeFileHandle[] Outputs, ReadOnlySpan<byte> Data, long Position)
        {
            for (int i = 0; i < Outputs.Length; i++)
                RandomAccess.Write(Outputs[i], Data, Position);
        }

        /// <summary>
        /// Extracts blobs packed into solid resources. Each needed chunk is decoded once, by one worker, which writes
        /// every slice of every file the chunk holds. Chunks that hold no wanted file are never read.
        /// </summary>
        private static void ExtractPacked(WimReader Reader, List<PendingBlob> Blobs, string[] Targets, ExtractionProgress Tracker)
        {
            if (Blobs.Count == 0)
                return;

            List<WimResourceSource> Resources = new List<WimResourceSource>();
            List<OutputFile> Outputs = new List<OutputFile>();
            List<ChunkJob> Jobs = new List<ChunkJob>();

            try
            {
                WimResourceSource? Current = null;
                int LargestChunk = 0;

                foreach (PendingBlob Pending in Blobs)
                {
                    WimBlob Blob = Pending.Blob;

                    if (Current == null || !ReferenceEquals(Current.Resource, Blob.Resource))
                    {
                        Current = (WimResourceSource)Reader.OpenResource(Blob.Resource);
                        Resources.Add(Current);
                        LargestChunk = Math.Max(LargestChunk, Current.ChunkSize);
                    }

                    if (Blob.OffsetInResource < 0 || Blob.Size > Current.Length - Blob.OffsetInResource)
                        throw new InvalidDataException($"A packed blob at offset {Blob.OffsetInResource} runs past the end of its solid resource.");

                    long First = Blob.OffsetInResource / Current.ChunkSize;
                    long Last = (Blob.OffsetInResource + Blob.Size - 1) / Current.ChunkSize;
                    int FirstOutput = Outputs.Count;

                    for (int i = 0; i < Pending.Count; i++)
                        Outputs.Add(new OutputFile(Targets[Pending.First + i], Blob.Size, (int)(Last - First + 1)));

                    for (long Chunk = First; Chunk <= Last; Chunk++)
                    {
                        ChunkJob? Job = Jobs.Count != 0 ? Jobs[Jobs.Count - 1] : null;

                        if (Job == null || Job.Resource != Current || Job.Index != Chunk)
                        {
                            Job = new ChunkJob(Current, Chunk);
                            Jobs.Add(Job);
                        }

                        long ChunkStart = Chunk * Current.ChunkSize;
                        long From = Math.Max(Blob.OffsetInResource, ChunkStart);
                        long To = Math.Min(Blob.OffsetInResource + Blob.Size, ChunkStart + Current.ChunkLength(Chunk));

                        for (int i = 0; i < Pending.Count; i++)
                            Job.Slices.Add(new ChunkSlice(Outputs[FirstOutput + i], From - Blob.OffsetInResource, (int)(From - ChunkStart), (int)(To - From)));
                    }
                }

                int Workers = (int)Math.Clamp(WimResourceSource.DecodeBudget / LargestChunk, 1, Environment.ProcessorCount);
                int Next = -1;

                RunWorkers(Workers, State =>
                {
                    byte[] Buffer = GC.AllocateUninitializedArray<byte>(LargestChunk);
                    int Index;

                    while (!State.ShouldExitCurrentIteration && (Index = Interlocked.Increment(ref Next)) < Jobs.Count)
                        ExtractChunk(Reader, Jobs[Index], Buffer, Tracker);
                });
            }
            finally
            {
                for (int i = 0; i < Outputs.Count; i++)
                    Outputs[i].Handle?.Dispose();

                for (int i = 0; i < Resources.Count; i++)
                    Resources[i].Dispose();
            }
        }

        private static void ExtractChunk(WimReader Reader, ChunkJob Job, byte[] Buffer, ExtractionProgress Tracker)
        {
            Span<byte> Chunk = Buffer.AsSpan(0, Job.Resource.ChunkLength(Job.Index));
            WimDecompressor Decompressor = Reader.RentDecompressor(Job.Resource.Resource);

            try
            {
                Job.Resource.DecodeChunks(Job.Index, 1, Chunk, Decompressor);
            }
            finally
            {
                Reader.ReturnDecompressor(Decompressor);
            }

            for (int i = 0; i < Job.Slices.Count; i++)
            {
                ChunkSlice Slice = Job.Slices[i];
                OutputFile Output = Slice.Output;
                SafeFileHandle Handle;

                lock (Output)
                    Handle = Output.Handle ??= OpenTarget(Output.Path, Output.Length);

                RandomAccess.Write(Handle, Chunk.Slice(Slice.ChunkOffset, Slice.Length), Slice.FileOffset);

                if (Interlocked.Decrement(ref Output.PendingSlices) == 0)
                {
                    Handle.Dispose();
                    Tracker.FileDone(Output.Length);
                }
            }
        }
    }
}
