using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Threading;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// On-disk copies of PE images in memory layout, mapped copy-on-write so image views share pages as on NT.
    /// </summary>
    internal static class WinImageLayoutCache
    {
        private const ulong LayoutVersion = 2;
        private const int TrimGraceSeconds = 60;
        private const ulong MaxImageBytes = 1UL << 30;

        // Copying a small image costs less than mapping it and faulting in most of its pages.
        private const ulong MinImageBytes = 1UL << 20;
        private static readonly TimeSpan RefreshAge = TimeSpan.FromDays(1);

        private const int CopyChunkBytes = 1 << 20;

        private static readonly bool Disabled = Environment.GetEnvironmentVariable("BROVAN_NO_IMAGE_CACHE") == "1";
        private static string CacheDirectory;
        private static int FailureReported;

        private sealed class PendingBuild
        {
            public string Location;
            public GeneralHelper.IO.HostFileStamp Stamp;
            public ulong ImageSize;
            public BinaryEmulator.PeImageExtent[] Extents;
            public string ImagePath;
        }

        private static readonly Queue<PendingBuild> Pending = new Queue<PendingBuild>();
        private static readonly HashSet<string> PendingPaths = new HashSet<string>(StringComparer.Ordinal);
        private static Thread Builder;

        internal sealed unsafe class View : IDisposable
        {
            private MemoryMappedFile Mapping;
            private MemoryMappedViewAccessor Accessor;

            public IntPtr Pointer { get; private set; }

            public View(MemoryMappedFile Mapping, MemoryMappedViewAccessor Accessor)
            {
                byte* Base = null;
                Accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref Base);
                this.Mapping = Mapping;
                this.Accessor = Accessor;
                Pointer = (IntPtr)(Base + Accessor.PointerOffset);
            }

            public void Dispose()
            {
                if (Accessor == null)
                    return;

                Accessor.SafeMemoryMappedViewHandle.ReleasePointer();
                Accessor.Dispose();
                Mapping.Dispose();
                Accessor = null;
                Mapping = null;
                Pointer = IntPtr.Zero;
            }
        }

        public static View TryOpen(BinaryFile Library, ulong ImageSize, List<BinaryEmulator.PeImageExtent> Extents)
        {
            if (Disabled || string.IsNullOrEmpty(Library.Location) || ImageSize < MinImageBytes || ImageSize > MaxImageBytes
                || ImageSize > (ulong)MemoryBudget.ImageCacheDirectoryBytes / 4)
                return null;

            foreach (BinaryEmulator.PeImageExtent Extent in Extents)
            {
                if (Extent.Rva > ImageSize || Extent.Size > ImageSize - Extent.Rva)
                    return null;
            }

            string Location = Path.GetFullPath(Library.Location);
            if (!GeneralHelper.IO.TryGetHostFileStamp(Location, out GeneralHelper.IO.HostFileStamp Stamp))
                return null;

            try
            {
                string Directory = ResolveDirectory();
                string ImagePath = Path.Combine(Directory, ComputeKey(Library, Location, Stamp, ImageSize) + ".img");
                FileInfo Info = new FileInfo(ImagePath);

                if (!Info.Exists || Info.Length != (long)ImageSize)
                {
                    QueueBuild(new PendingBuild { Location = Location, Stamp = Stamp, ImageSize = ImageSize, Extents = Extents.ToArray(), ImagePath = ImagePath });
                    return null;
                }

                if (DateTime.UtcNow - Info.LastWriteTimeUtc > RefreshAge)
                    Info.LastWriteTimeUtc = DateTime.UtcNow;

                return Open(ImagePath, ImageSize);
            }
            catch (Exception Ex) when (Ex is IOException || Ex is UnauthorizedAccessException)
            {
                ReportFailure(Library.Location, Ex);
                return null;
            }
        }

        private static void ReportFailure(string Location, Exception Ex)
        {
            if (Interlocked.Exchange(ref FailureReported, 1) == 0)
                Utils.LogError($"[ImageCache] {Location}: {Ex.Message}. Images are copied instead.");
        }

        private static void QueueBuild(PendingBuild Build)
        {
            lock (Pending)
            {
                if (!PendingPaths.Add(Build.ImagePath))
                    return;

                Pending.Enqueue(Build);
                if (Builder != null)
                {
                    Monitor.Pulse(Pending);
                    return;
                }

                Builder = new Thread(BuildLoop) { IsBackground = true, Name = "BrovanImageCache", Priority = ThreadPriority.BelowNormal };
                Builder.Start();
            }
        }

        private static void BuildLoop()
        {
            while (true)
            {
                PendingBuild Next;
                lock (Pending)
                {
                    while (Pending.Count == 0)
                        Monitor.Wait(Pending);
                    Next = Pending.Dequeue();
                }

                try
                {
                    if (Build(Next))
                        TrimDirectory(Path.GetDirectoryName(Next.ImagePath));
                }
                catch (Exception Ex)
                {
                    ReportFailure(Next.Location, Ex);
                }
                finally
                {
                    lock (Pending)
                        PendingPaths.Remove(Next.ImagePath);
                }
            }
        }

        private static string ResolveDirectory()
        {
            if (CacheDirectory != null)
                return CacheDirectory;

            string Directory = Path.Combine(AppContext.BaseDirectory, ".imagecache");
            System.IO.Directory.CreateDirectory(Directory);
            CacheDirectory = Directory;
            return Directory;
        }

        private static bool Build(PendingBuild Job)
        {
            string TempPath = Job.ImagePath + "." + Environment.ProcessId.ToString(CultureInfo.InvariantCulture) + ".tmp";
            byte[] Buffer = ArrayPool<byte>.Shared.Rent(CopyChunkBytes);
            try
            {
                using FileStream Source = new FileStream(Job.Location, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.SequentialScan);
                using FileStream Target = new FileStream(TempPath, FileMode.Create, FileAccess.Write, FileShare.None);
                Target.SetLength((long)Job.ImageSize);

                foreach (BinaryEmulator.PeImageExtent Extent in Job.Extents)
                {
                    Source.Position = Extent.RawOffset;
                    Target.Position = (long)Extent.Rva;
                    for (ulong Done = 0; Done < Extent.Size;)
                    {
                        int Wanted = (int)Math.Min((ulong)CopyChunkBytes, Extent.Size - Done);
                        int Read = Source.Read(Buffer, 0, Wanted);
                        if (Read <= 0)
                            throw new IOException("The image file ended inside a section.");

                        Target.Write(Buffer, 0, Read);
                        Done += (ulong)Read;
                    }
                }
            }
            catch
            {
                File.Delete(TempPath);
                throw;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Buffer);
            }

            if (!GeneralHelper.IO.TryGetHostFileStamp(Job.Location, out GeneralHelper.IO.HostFileStamp After) || After != Job.Stamp)
            {
                File.Delete(TempPath);
                return false;
            }

            try
            {
                File.Move(TempPath, Job.ImagePath, true);
            }
            catch (Exception Ex) when (Ex is IOException || Ex is UnauthorizedAccessException)
            {
                // Another Brovan may have the layout mapped.
                File.Delete(TempPath);
                if (new FileInfo(Job.ImagePath).Length != (long)Job.ImageSize)
                    throw;
            }

            return true;
        }

        private static View Open(string ImagePath, ulong ImageSize)
        {
            FileStream Stream = new FileStream(ImagePath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            MemoryMappedFile Mapping = null;
            MemoryMappedViewAccessor Accessor = null;
            try
            {
                Mapping = MemoryMappedFile.CreateFromFile(Stream, null, 0, MemoryMappedFileAccess.CopyOnWrite, HandleInheritability.None, false);
                Stream = null;
                Accessor = Mapping.CreateViewAccessor(0, (long)ImageSize, MemoryMappedFileAccess.CopyOnWrite);
                return new View(Mapping, Accessor);
            }
            catch
            {
                Accessor?.Dispose();
                Mapping?.Dispose();
                Stream?.Dispose();
                throw;
            }
        }

        private static void TrimDirectory(string Directory)
        {
            DirectoryInfo Info = new DirectoryInfo(Directory);
            DateTime Grace = DateTime.UtcNow.AddSeconds(-TrimGraceSeconds);

            foreach (FileInfo Temp in Info.GetFiles("*.tmp"))
            {
                if (Temp.LastWriteTimeUtc <= Grace)
                    TryDelete(Temp);
            }

            FileInfo[] Images = Info.GetFiles("*.img");
            long Budget = MemoryBudget.ImageCacheDirectoryBytes;
            long Total = 0;
            foreach (FileInfo Image in Images)
                Total += Image.Length;

            if (Total <= Budget)
                return;

            Array.Sort(Images, (a, b) => a.LastWriteTimeUtc.CompareTo(b.LastWriteTimeUtc));
            foreach (FileInfo Image in Images)
            {
                if (Total <= Budget)
                    break;

                if (Image.LastWriteTimeUtc > Grace)
                    continue;

                long Size = Image.Length;
                if (TryDelete(Image))
                    Total -= Size;
            }
        }

        private static bool TryDelete(FileInfo File)
        {
            try
            {
                File.Delete();
                return true;
            }
            catch (Exception Ex) when (Ex is IOException || Ex is UnauthorizedAccessException)
            {
                return false;
            }
        }

        private static string ComputeKey(BinaryFile Library, string Location, GeneralHelper.IO.HostFileStamp Stamp, ulong ImageSize)
        {
            ulong Hash = BinaryHelpers.FnvOffsetBasis;

            BinaryHelpers.FnvMixPath(ref Hash, Location);
            BinaryHelpers.FnvMixNumber(ref Hash, LayoutVersion);
            BinaryHelpers.FnvMixNumber(ref Hash, Stamp.Volume);
            BinaryHelpers.FnvMixNumber(ref Hash, Stamp.IdLow);
            BinaryHelpers.FnvMixNumber(ref Hash, Stamp.IdHigh);
            BinaryHelpers.FnvMixNumber(ref Hash, (ulong)Stamp.ChangeTime);
            BinaryHelpers.FnvMixNumber(ref Hash, (ulong)Stamp.WriteTime);
            BinaryHelpers.FnvMixNumber(ref Hash, (ulong)Stamp.Size);
            BinaryHelpers.FnvMixNumber(ref Hash, (ulong)Library.BinarySize);
            BinaryHelpers.FnvMixNumber(ref Hash, ImageSize);

            ReadOnlySpan<byte> Data = Library.GetBinaryData();
            BinaryHelpers.FnvMixBytes(ref Hash, Data.Slice(0, Math.Min(Data.Length, 4096)));

            return Hash.ToString("x16", CultureInfo.InvariantCulture);
        }
    }
}
