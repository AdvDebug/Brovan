using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using Brovan.Core.Helpers;
using static Brovan.Core.Emulation.Native;

namespace Brovan.Core.Emulation
{
    /// <summary>
    /// Persists Unicorn's TCG code cache between runs so a guest does not have to be
    /// re-translated from scratch on every launch.
    /// </summary>
    public static class UnicornCodeCache
    {
        // Must match BROV_RESERVE_HEADER_SIZE and BROV_BLOB_MAGIC in
        // Brovan/native/unicorn/brovan_uc.h.
        private const ulong ReserveHeaderSize = 128 * 1024;
        private const uint BlobMagic = 0x4356524B;
        private const ulong DefaultCodeBufferSize = 2UL * 1024 * 1024 * 1024;
        private const long CacheDirectoryBudget = 512L * 1024 * 1024;
        private const int TrimGraceSeconds = 60;

        private static readonly object Gate = new object();

        private static readonly string[] ReasonNames =
        {
            // Order must match brov_reason in Brovan/native/unicorn/brovan_uc.h.
            "ok", "no-reservation", "unsupported-target", "truncated", "bad-magic",
            "abi-mismatch", "layout-mismatch", "host-mismatch", "target-mismatch",
            "reservation-mismatch", "prologue-mismatch", "arena-mismatch",
            "code-hash-mismatch", "slot-table-full", "audit-failed",
            "too-many-stale-blocks", "empty", "mostly-dead-code", "slot-unresolved",
        };

        private static byte[] PendingBlob;
        private static string BlobPath;
        private static string MarkerPath;
        private static bool Configured;
        private static bool Loaded;
        private static bool PendingResolves;
        private static int IdleResolves;
        private const int MaxIdleResolves = 8;
        private static ulong SavedUsedBytes = ulong.MaxValue;

        public static bool Enabled { get; set; } = true;

        public static bool PrintStats { get; set; }

        public static string CacheDirectory { get; set; }

        public static string ReasonName(uint Reason)
        {
            return Reason < ReasonNames.Length ? ReasonNames[Reason] : "reason-" + Reason.ToString(CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Reserve the address range the code cache needs. Must run before the first
        /// <see cref="Unicorn"/> instance is created, because the reservation is what
        /// pins the uc struct and the code buffer at reproducible addresses.
        /// </summary>
        public static void Configure(string GuestImagePath, string HostImagePath)
        {
            lock (Gate)
            {
                if (Configured)
                    return;

                Configured = true;

                if (!Enabled)
                    return;

                try
                {
                    string Directory = ResolveCacheDirectory();
                    string Key = ComputeKey(GuestImagePath, HostImagePath);

                    BlobPath = Path.Combine(Directory, Key + ".bjc");
                    MarkerPath = BlobPath + ".inflight";

                    DiscardIfPreviousRunDied();

                    ulong ReserveBase = 0;
                    ulong ReserveSize = ReserveHeaderSize + DefaultCodeBufferSize;

                    if (File.Exists(BlobPath))
                    {
                        PendingBlob = File.ReadAllBytes(BlobPath);

                        if (Unicorn.GetBlobReservation(PendingBlob, out ulong BlobBase, out ulong BlobSize))
                        {
                            ReserveBase = BlobBase;
                            ReserveSize = BlobSize;
                        }
                        else
                        {
                            PendingBlob = null;
                        }
                    }

                    if (!Unicorn.ConfigureCodeCache(ReserveBase, ReserveSize, true))
                    {
                        Utils.LogError("[jit-cache] address reservation failed; running without a code cache.");
                        PendingBlob = null;
                        return;
                    }

                    if (PendingBlob != null && Unicorn.GetCodeCacheReservation(out ulong GotBase, out _) && GotBase != ReserveBase)
                    {
                        // The recorded range was taken by something else. This run still
                        // records a fresh base for next time, it just cannot load today.
                        Utils.LogError($"[jit-cache] wanted reservation 0x{ReserveBase:X} but got 0x{GotBase:X}; running cold.");
                        PendingBlob = null;
                    }
                }
                catch (Exception Error)
                {
                    Utils.LogError("[jit-cache] configure failed: " + Error.Message);
                    PendingBlob = null;
                }
            }
        }

        /// <summary>
        /// Restore the saved cache. Call once the guest image is mapped: every restored
        /// block is verified against the guest bytes it was translated from.
        /// </summary>
        public static void TryLoad(Unicorn Engine)
        {
            lock (Gate)
            {
                if (!Enabled || Loaded || PendingBlob == null || Engine == null)
                    return;

                Loaded = true;

                byte[] Blob = PendingBlob;
                PendingBlob = null;

                if (!Engine.LoadCodeCache(Blob))
                {
                    Utils.PrintHighlight($"[!] JIT cache not reused ({ReasonName(Engine.GetCodeCacheReason())}).", true);
                    return;
                }

                WriteMarker();
                PendingResolves = true;

                if (Engine.GetCodeCacheInfo(out BrovCacheInfo Info))
                {
                    Utils.PrintHighlight($"[+] JIT cache restored: {Info.LoadedTbs} blocks, {Info.StaleTbs} stale, {Info.CodeGenUsed / 1024} KB.", true);
                }
            }
        }

        /// <summary>
        /// Register restored blocks whose pages had not been mapped yet at load time.
        /// Cheap: their code is already in the buffer, this only verifies and files them.
        /// </summary>
        public static void ResolvePending(Unicorn Engine)
        {
            if (!PendingResolves || Engine == null)
                return;

            PendingResolves = Engine.ResolveCodeCache(out uint Resolved, out _);

            // Some blocks never become verifiable. a page the guest maps once and
            // drops, say. Retrying them for the rest of the run costs a native call
            // and a guest read per pass and recovers nothing.
            IdleResolves = Resolved == 0 ? IdleResolves + 1 : 0;
            if (IdleResolves >= MaxIdleResolves)
                PendingResolves = false;
        }

        /// <summary>
        /// Persist the cache. Only reached on a clean shutdown, which is deliberate: the
        /// marker left behind by a crashed run is what invalidates a suspect blob.
        /// </summary>
        public static void TrySave(Unicorn Engine)
        {
            lock (Gate)
            {
                if (!Enabled || Engine == null || BlobPath == null)
                    return;

                try
                {
                    if (Engine.GetCodeCacheInfo(out BrovCacheInfo Before))
                    {
                        if (PrintStats)
                            Utils.PrintHighlight(Describe(Before), true, false, true);

                        // Start() and Dispose() can both land here; the audit is a full
                        // scan of the buffer, so do not repeat it for nothing.
                        if (Before.CodeGenUsed == SavedUsedBytes)
                            return;

                        SavedUsedBytes = Before.CodeGenUsed;
                    }

                    byte[] Blob = Engine.SaveCodeCache();
                    if (Blob == null)
                    {
                        Utils.LogError($"[jit-cache] not saved ({ReasonName(Engine.GetCodeCacheReason())}).");

                        if (!Engine.ValidateCodeCache(out BrovAuditResult Audit) && Audit.HitCount != 0)
                            Utils.LogError($"[jit-cache] audit hit {Audit.HitCount} site(s); first at +0x{Audit.FirstOffset:X} = 0x{Audit.FirstValue:X} ({Audit.FirstObject}).");

                        return;
                    }

                    string Temporary = BlobPath + "." + Environment.ProcessId.ToString(CultureInfo.InvariantCulture) + ".tmp";
                    File.WriteAllBytes(Temporary, Blob);
                    File.Move(Temporary, BlobPath, true);
                    TrimCacheDirectory(Path.GetDirectoryName(BlobPath));
                }
                catch (Exception Error)
                {
                    Utils.LogError("[jit-cache] save failed: " + Error.Message);
                }
                finally
                {
                    ClearMarker();
                }
            }
        }

        internal static string Describe(BrovCacheInfo Info)
        {
            return $"[#] JIT cache: {Info.TbCount} blocks, {Info.CodeGenUsed / 1024} KB of {Info.CodeGenBufferSize / (1024 * 1024)} MB, " +
                   $"{Info.SlotsUsed}/{Info.SlotCount} helper slots, {Info.FlushCount} flush(es), last: {ReasonName(Info.LastReason)}.";
        }

        private static string ResolveCacheDirectory()
        {
            string Directory = CacheDirectory;

            if (string.IsNullOrWhiteSpace(Directory))
                Directory = Path.Combine(AppContext.BaseDirectory, ".jitcache");

            System.IO.Directory.CreateDirectory(Directory);
            DiscardForeignBlobs(Directory);
            return Directory;
        }

        /// <summary>
        /// Drop blobs an older Brovan wrote in a format this one can no longer read.
        /// They would otherwise sit there until the size trim evicted them: their key
        /// covers the unicorn build, so a newer Brovan never looks at them again.
        /// </summary>
        private static void DiscardForeignBlobs(string Directory)
        {
            Span<byte> Header = stackalloc byte[8];

            if (brov_abi_version(out uint CurrentAbi) != UCErrors.UC_ERR_OK)
                return;

            foreach (string Path in System.IO.Directory.EnumerateFiles(Directory, "*.bjc"))
            {
                try
                {
                    uint Magic;
                    uint Abi;

                    using (FileStream Stream = File.OpenRead(Path))
                    {
                        if (Stream.Read(Header) != Header.Length)
                            continue;

                        Magic = BitConverter.ToUInt32(Header.Slice(0, 4));
                        Abi = BitConverter.ToUInt32(Header.Slice(4, 4));
                    }

                    if (Magic == BlobMagic && Abi == CurrentAbi)
                        continue;

                    File.Delete(Path);
                    File.Delete(Path + ".inflight");
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }
        }

        /// <summary>
        /// A blob is only trusted when the run that last used it exited cleanly. A bad
        /// block can be reached minutes in, so clearing the marker on a timer would turn
        /// one crash into a boot loop.
        /// </summary>
        private static void DiscardIfPreviousRunDied()
        {
            if (!File.Exists(MarkerPath))
                return;

            if (IsMarkerOwnerAlive())
                return;

            try
            {
                File.Delete(MarkerPath);
                File.Delete(BlobPath);
            }
            catch (IOException)
            {
            }

            Utils.LogError("[jit-cache] previous run did not exit cleanly; discarded the blob.");
        }

        private static bool IsMarkerOwnerAlive()
        {
            try
            {
                string[] Parts = File.ReadAllText(MarkerPath).Split('|');
                if (Parts.Length != 2)
                    return false;

                int Pid = int.Parse(Parts[0], CultureInfo.InvariantCulture);
                long StartTicks = long.Parse(Parts[1], CultureInfo.InvariantCulture);

                using Process Owner = Process.GetProcessById(Pid);
                return Owner.StartTime.Ticks == StartTicks;
            }
            catch (Exception)
            {
                // No such process, or it is a different one that reused the pid.
                return false;
            }
        }

        private static void WriteMarker()
        {
            try
            {
                using Process Self = Process.GetCurrentProcess();
                File.WriteAllText(MarkerPath, Self.Id.ToString(CultureInfo.InvariantCulture) + "|" + Self.StartTime.Ticks.ToString(CultureInfo.InvariantCulture));
            }
            catch (Exception Error)
            {
                Utils.LogError("[jit-cache] could not write the in-flight marker: " + Error.Message);
            }
        }

        private static void ClearMarker()
        {
            try
            {
                if (MarkerPath != null && File.Exists(MarkerPath))
                    File.Delete(MarkerPath);
            }
            catch (IOException)
            {
            }
        }

        private static void TrimCacheDirectory(string Directory)
        {
            DirectoryInfo Info = new DirectoryInfo(Directory);
            FileInfo[] Blobs = Info.GetFiles("*.bjc");
            long Total = 0;

            foreach (FileInfo Blob in Blobs)
                Total += Blob.Length;

            if (Total <= CacheDirectoryBudget)
                return;

            Array.Sort(Blobs, (a, b) => a.LastWriteTimeUtc.CompareTo(b.LastWriteTimeUtc));
            DateTime Grace = DateTime.UtcNow.AddSeconds(-TrimGraceSeconds);

            foreach (FileInfo Blob in Blobs)
            {
                if (Total <= CacheDirectoryBudget)
                    break;

                // Another Brovan may be mid-load on a blob it just wrote.
                if (Blob.LastWriteTimeUtc > Grace)
                    continue;

                try
                {
                    long Size = Blob.Length;
                    Blob.Delete();
                    Total -= Size;
                }
                catch (IOException)
                {
                }
            }
        }

        private static string ComputeKey(string GuestImagePath, string HostImagePath)
        {
            ulong Hash = 0xcbf29ce484222325;

            // GuestImagePath is in the guest namespace and usually does not exist on the
            // host, so the content has to be read through the path Brovan actually opened.
            MixText(ref Hash, GuestImagePath ?? string.Empty);
            MixFile(ref Hash, HostImagePath);
            MixFile(ref Hash, Path.Combine(AppContext.BaseDirectory, GeneralHelper.IsWindows ? "unicorn.dll" : "libunicorn.so"));
            MixNumber(ref Hash, (ulong)IntPtr.Size);

            return Hash.ToString("x16", CultureInfo.InvariantCulture);
        }

        private static void MixFile(ref ulong Hash, string Path)
        {
            if (string.IsNullOrEmpty(Path) || !File.Exists(Path))
            {
                MixNumber(ref Hash, 0);
                return;
            }

            FileInfo Info = new FileInfo(Path);
            MixNumber(ref Hash, (ulong)Info.Length);
            MixNumber(ref Hash, (ulong)Info.LastWriteTimeUtc.Ticks);

            // mtime alone has one-second resolution on some filesystems, so take a slice
            // of the content too.
            try
            {
                byte[] Head = new byte[4096];
                using FileStream Stream = File.OpenRead(Path);
                int Read = Stream.Read(Head, 0, Head.Length);
                for (int i = 0; i < Read; i++)
                {
                    Hash ^= Head[i];
                    Hash *= 0x100000001b3;
                }
            }
            catch (IOException)
            {
            }
        }

        private static void MixText(ref ulong Hash, string Text)
        {
            string Normalized = GeneralHelper.IsWindows ? Text.ToLowerInvariant() : Text;

            foreach (char Character in Normalized)
            {
                Hash ^= Character;
                Hash *= 0x100000001b3;
            }
        }

        private static void MixNumber(ref ulong Hash, ulong Value)
        {
            for (int i = 0; i < 8; i++)
            {
                Hash ^= (Value >> (i * 8)) & 0xFF;
                Hash *= 0x100000001b3;
            }
        }
    }
}
