using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Brovan.Core.Helpers;
using Microsoft.Win32.SafeHandles;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// Guest processes of one emulation session, published in a file every member maps.
    /// </summary>
    internal static class GuestSession
    {
        internal const int SlotCount = 16;

        private const string SessionVariable = "BROVAN_SESSION_ID";
        private const string SpawnTokenVariable = "BROVAN_SPAWN_TOKEN";
        private const string DirectoryName = "Sessions";
        private const string TableFileName = "processes.bin";

        private const int SlotSize = 256;
        private const int TableSize = SlotCount * SlotSize;

        private const int StateOffset = 0x00;
        private const int HostProcessIdOffset = 0x04;
        private const int GuestProcessIdOffset = 0x08;
        private const int ArchitectureOffset = 0x0C;
        private const int StartTimeOffset = 0x10;
        private const int ControlOffset = 0x18;
        private const int ControlExitCodeOffset = 0x1C;
        private const int ReadyOffset = 0x20;
        private const int ImageLengthOffset = 0x24;
        private const int PebAddressOffset = 0x28;
        private const int ProcessParametersOffset = 0x30;
        private const int ExitCodeOffset = 0x38;
        private const int SpawnTokenOffset = 0x3C;
        private const int MainThreadIdOffset = 0x40;
        private const int ImageOffset = 0x44;
        private const int MaxImageBytes = SlotSize - ImageOffset - 2;

        private const uint SlotFree = 0;
        private const uint SlotLive = 1;
        private const uint SlotExited = 2;

        private const uint ControlNone = 0;
        private const uint ControlTerminate = 1;

        private const int LockTimeoutMilliseconds = 2000;
        private const int ControlPollMilliseconds = 150;

        private static readonly object Sync = new();

        private static string _sessionId;
        private static string _directory;
        private static FileStream _stream;
        private static MemoryMappedFile _map;
        private static MemoryMappedViewAccessor _view;
        private static Mutex _mutex;
        private static Thread _watcher;
        private static int _ownSlot = -1;
        private static bool _unavailable;
        private static bool _exitPublished;
        private static uint _spawnToken;
        private static Action<uint> _terminateCallback;

        /// <summary>
        /// A spawned emulator inherits this through the environment, which is what puts it in the same table.
        /// </summary>
        internal static string SessionId
        {
            get
            {
                lock (Sync)
                {
                    if (_sessionId != null)
                        return _sessionId;

                    string Inherited = Environment.GetEnvironmentVariable(SessionVariable);
                    if (!string.IsNullOrWhiteSpace(Inherited))
                        return _sessionId = Sanitize(Inherited);

                    _sessionId = Environment.ProcessId.ToString("X") + "-" + DateTime.UtcNow.Ticks.ToString("X");
                    Environment.SetEnvironmentVariable(SessionVariable, _sessionId);
                    return _sessionId;
                }
            }
        }

        /// <summary>
        /// Kept next to the emulator rather than in the temporary directory so the files are the user's to delete.
        /// </summary>
        internal static string Directory => _directory ??= Path.Combine(AppContext.BaseDirectory, DirectoryName, SessionId);

        internal static void CreatePrivateDirectory(string Location)
        {
            System.IO.Directory.CreateDirectory(Location);

            if (!GeneralHelper.IsWindows)
            {
                try
                {
                    File.SetUnixFileMode(Location, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                }
                catch (Exception Error)
                {
                    Utils.LogError($"[GuestSession] Cannot restrict {Location}: {Error.Message}");
                }
            }
        }

        // A creator that hands the launch to the system never learns a process id, so it picks this instead
        // and the child publishes it.
        internal static uint SpawnToken
        {
            get
            {
                lock (Sync)
                {
                    if (_spawnToken == 0)
                        uint.TryParse(Environment.GetEnvironmentVariable(SpawnTokenVariable), out _spawnToken);

                    return _spawnToken;
                }
            }

            set
            {
                lock (Sync)
                    _spawnToken = value;
            }
        }

        internal static int OwnSlot => _ownSlot;

        internal static void Join(uint GuestProcessId, uint Architecture, string ImageName, Action<uint> OnTerminateRequested)
        {
            lock (Sync)
            {
                if (_ownSlot >= 0 || !TryOpen())
                    return;

                _terminateCallback = OnTerminateRequested;

                using (SessionLock Lock = Acquire())
                {
                    if (!Lock.Held)
                        return;

                    for (int Index = 0; Index < SlotCount; Index++)
                    {
                        int Offset = SlotOffset(Index);
                        if (_view.ReadUInt32(Offset + StateOffset) == SlotLive && IsHostAlive(_view.ReadUInt32(Offset + HostProcessIdOffset)))
                            continue;

                        GuestSessionMailbox.Reset(Index);
                        ClaimSlot(Offset, GuestProcessId, Architecture, ImageName);
                        _ownSlot = Index;
                        break;
                    }
                }

                if (_ownSlot < 0)
                {
                    Utils.LogError($"[GuestSession] No free slot for guest process {GuestProcessId}; the session is full.");
                    return;
                }

                AppDomain.CurrentDomain.ProcessExit += static (_, _) => Leave();

                _watcher = new Thread(WatchControlRequests)
                {
                    IsBackground = true,
                    Name = "BrovanSessionWatcher",
                };

                _watcher.Start();
            }
        }

        internal static void Leave()
        {
            lock (Sync)
            {
                if (_ownSlot < 0 || _view == null)
                    return;

                bool LastMember = false;

                using (SessionLock Lock = Acquire())
                {
                    if (Lock.Held)
                    {
                        // The slot outlives the process, since its creator reads the exit code from here.
                        _view.Write(SlotOffset(_ownSlot) + StateOffset, _exitPublished ? SlotExited : SlotFree);
                        _view.Flush();
                        LastMember = CountLiveLocked() == 0;
                    }
                }

                _ownSlot = -1;

                if (LastMember)
                    Discard();
            }
        }

        /// <summary>
        /// Only published once this process can serve mailbox requests, since a creator acts on these immediately.
        /// </summary>
        internal static void PublishStartup(ulong PebAddress, ulong ProcessParameters, uint MainThreadId)
        {
            lock (Sync)
            {
                if (_ownSlot < 0 || _view == null)
                    return;

                using SessionLock Lock = Acquire();
                if (!Lock.Held)
                    return;

                int Offset = SlotOffset(_ownSlot);
                _view.Write(Offset + PebAddressOffset, PebAddress);
                _view.Write(Offset + ProcessParametersOffset, ProcessParameters);
                _view.Write(Offset + MainThreadIdOffset, MainThreadId);
                _view.Write(Offset + ReadyOffset, 1u);
                _view.Flush();
            }
        }

        internal static void PublishExit(uint ExitCode)
        {
            lock (Sync)
            {
                if (_ownSlot < 0 || _view == null)
                    return;

                using SessionLock Lock = Acquire();
                if (!Lock.Held)
                    return;

                // Not at process exit: the host can kill the emulator before it unwinds.
                int Offset = SlotOffset(_ownSlot);
                _view.Write(Offset + ExitCodeOffset, ExitCode);
                _view.Write(Offset + StateOffset, SlotExited);
                _view.Flush();
                _exitPublished = true;
            }
        }

        internal static bool TryReadExit(uint GuestProcessId, out uint ExitCode)
        {
            ExitCode = 0;

            lock (Sync)
            {
                if (!TryOpen())
                    return false;

                using SessionLock Lock = Acquire();
                if (!Lock.Held)
                    return false;

                for (int Index = 0; Index < SlotCount; Index++)
                {
                    int Offset = SlotOffset(Index);
                    if (_view.ReadUInt32(Offset + StateOffset) != SlotExited || _view.ReadUInt32(Offset + GuestProcessIdOffset) != GuestProcessId)
                        continue;

                    ExitCode = _view.ReadUInt32(Offset + ExitCodeOffset);
                    return true;
                }

                return false;
            }
        }

        internal static bool TryResolveSpawn(uint SpawnToken, out uint GuestProcessId, out uint HostProcessId, out ulong PebAddress, out ulong ProcessParameters, out uint MainThreadId)
        {
            GuestProcessId = 0;
            HostProcessId = 0;
            PebAddress = 0;
            ProcessParameters = 0;
            MainThreadId = 0;

            if (SpawnToken == 0)
                return false;

            lock (Sync)
            {
                if (!TryOpen())
                    return false;

                using SessionLock Lock = Acquire();
                if (!Lock.Held)
                    return false;

                for (int Index = 0; Index < SlotCount; Index++)
                {
                    int Offset = SlotOffset(Index);
                    if (_view.ReadUInt32(Offset + StateOffset) != SlotLive || _view.ReadUInt32(Offset + SpawnTokenOffset) != SpawnToken)
                        continue;

                    if (_view.ReadUInt32(Offset + ReadyOffset) == 0)
                        return false;

                    GuestProcessId = _view.ReadUInt32(Offset + GuestProcessIdOffset);
                    HostProcessId = _view.ReadUInt32(Offset + HostProcessIdOffset);
                    PebAddress = _view.ReadUInt64(Offset + PebAddressOffset);
                    ProcessParameters = _view.ReadUInt64(Offset + ProcessParametersOffset);
                    MainThreadId = _view.ReadUInt32(Offset + MainThreadIdOffset);
                    return PebAddress != 0;
                }

                return false;
            }
        }

        internal static bool TryReadStartup(uint GuestProcessId, out ulong PebAddress, out ulong ProcessParameters)
        {
            PebAddress = 0;
            ProcessParameters = 0;

            lock (Sync)
            {
                if (!TryOpen())
                    return false;

                using SessionLock Lock = Acquire();
                if (!Lock.Held || !TryFindLiveSlotLocked(GuestProcessId, out int Slot))
                    return false;

                int Offset = SlotOffset(Slot);
                if (_view.ReadUInt32(Offset + ReadyOffset) == 0)
                    return false;

                PebAddress = _view.ReadUInt64(Offset + PebAddressOffset);
                ProcessParameters = _view.ReadUInt64(Offset + ProcessParametersOffset);
                return true;
            }
        }

        /// <summary>
        /// Everything needed to open a handle to a sibling guest process of the session.
        /// </summary>
        /// <param name="GuestProcessId">Guest process id to resolve.</param>
        /// <param name="HostProcessId">Receives the emulator instance hosting it.</param>
        /// <param name="ImageName">Receives the image name the member published.</param>
        /// <param name="PebAddress">Receives the guest PEB, zero until the member published startup.</param>
        /// <param name="ProcessParameters">Receives the guest process parameters.</param>
        internal static bool TryResolveMember(uint GuestProcessId, out uint HostProcessId, out string ImageName, out ulong PebAddress, out ulong ProcessParameters, out uint Architecture, out uint MainThreadId)
        {
            HostProcessId = 0;
            ImageName = string.Empty;
            PebAddress = 0;
            ProcessParameters = 0;
            Architecture = 0;
            MainThreadId = 0;

            lock (Sync)
            {
                if (!TryOpen())
                    return false;

                using SessionLock Lock = Acquire();
                if (!Lock.Held || !TryFindLiveSlotLocked(GuestProcessId, out int Slot))
                    return false;

                int Offset = SlotOffset(Slot);
                HostProcessId = _view.ReadUInt32(Offset + HostProcessIdOffset);
                if (HostProcessId == 0)
                    return false;

                Architecture = _view.ReadUInt32(Offset + ArchitectureOffset);
                MainThreadId = _view.ReadUInt32(Offset + MainThreadIdOffset);

                int NameLength = (int)Math.Min(_view.ReadUInt32(Offset + ImageLengthOffset), (uint)MaxImageBytes);
                if (NameLength > 0)
                {
                    byte[] Name = new byte[NameLength];
                    _view.ReadArray(Offset + ImageOffset, Name, 0, NameLength);
                    ImageName = Encoding.Unicode.GetString(Name);
                }

                if (_view.ReadUInt32(Offset + ReadyOffset) != 0)
                {
                    PebAddress = _view.ReadUInt64(Offset + PebAddressOffset);
                    ProcessParameters = _view.ReadUInt64(Offset + ProcessParametersOffset);
                }

                return true;
            }
        }

        internal static bool TryFindLiveSlot(uint GuestProcessId, out int Slot)
        {
            Slot = -1;

            lock (Sync)
            {
                if (!TryOpen())
                    return false;

                using SessionLock Lock = Acquire();
                return Lock.Held && TryFindLiveSlotLocked(GuestProcessId, out Slot);
            }
        }

        internal static bool IsLiveMemberHost(uint HostProcessId)
        {
            lock (Sync)
            {
                if (!TryOpen())
                    return false;

                using SessionLock Lock = Acquire();
                if (!Lock.Held)
                    return false;

                for (int Index = 0; Index < SlotCount; Index++)
                {
                    int Offset = SlotOffset(Index);
                    if (_view.ReadUInt32(Offset + StateOffset) == SlotLive && _view.ReadUInt32(Offset + HostProcessIdOffset) == HostProcessId)
                        return IsHostAlive(HostProcessId);
                }

                return false;
            }
        }

        internal static int CountLive()
        {
            lock (Sync)
            {
                if (!TryOpen())
                    return 0;

                using SessionLock Lock = Acquire();
                return Lock.Held ? CountLiveLocked() : 0;
            }
        }

        /// <summary>
        /// Live guest processes of the session, each of which runs in its own emulator instance.
        /// </summary>
        /// <param name="Members">Receives the guest process id, initial thread id and image name of every live member.</param>
        internal static void ListLive(List<(uint ProcessId, uint MainThreadId, string ImageName)> Members)
        {
            lock (Sync)
            {
                if (!TryOpen())
                    return;

                using SessionLock Lock = Acquire();
                if (!Lock.Held)
                    return;

                for (int Index = 0; Index < SlotCount; Index++)
                {
                    int Offset = SlotOffset(Index);
                    if (_view.ReadUInt32(Offset + StateOffset) != SlotLive)
                        continue;

                    if (!IsHostAlive(_view.ReadUInt32(Offset + HostProcessIdOffset)))
                    {
                        _view.Write(Offset + StateOffset, SlotFree);
                        continue;
                    }

                    int NameLength = (int)Math.Min(_view.ReadUInt32(Offset + ImageLengthOffset), (uint)MaxImageBytes);
                    string ImageName = string.Empty;

                    if (NameLength > 0)
                    {
                        byte[] Name = new byte[NameLength];
                        _view.ReadArray(Offset + ImageOffset, Name, 0, NameLength);
                        ImageName = Encoding.Unicode.GetString(Name);
                    }

                    Members.Add((_view.ReadUInt32(Offset + GuestProcessIdOffset), _view.ReadUInt32(Offset + MainThreadIdOffset), ImageName));
                }
            }
        }

        /// <summary>
        /// Left in the target's slot for its owner to act on, the only orderly way to stop a guest elsewhere.
        /// </summary>
        internal static bool RequestTerminate(uint GuestProcessId, uint ExitCode)
        {
            lock (Sync)
            {
                if (!TryOpen())
                    return false;

                using SessionLock Lock = Acquire();
                if (!Lock.Held || !TryFindLiveSlotLocked(GuestProcessId, out int Slot))
                    return false;

                int Offset = SlotOffset(Slot);
                _view.Write(Offset + ControlExitCodeOffset, ExitCode);
                _view.Write(Offset + ControlOffset, ControlTerminate);
                _view.Flush();
                return true;
            }
        }

        internal static SessionLock Acquire()
        {
            if (_mutex == null)
                return default;

            try
            {
                return _mutex.WaitOne(LockTimeoutMilliseconds) ? new SessionLock(_mutex) : default;
            }
            catch (AbandonedMutexException)
            {
                return new SessionLock(_mutex);
            }
            catch (Exception)
            {
                return default;
            }
        }

        private static bool TryOpen()
        {
            if (_view != null)
                return true;

            if (_unavailable)
                return false;

            try
            {
                System.IO.Directory.CreateDirectory(Directory);

                _mutex = new Mutex(false, "BrovanSession_" + SessionId);

                // CreateFromFile(path, ...) opens the file exclusively and locks every other member out.
                _stream = new FileStream(
                    Path.Combine(Directory, TableFileName),
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.ReadWrite | FileShare.Delete);

                if (_stream.Length < TableSize)
                    _stream.SetLength(TableSize);

                _map = MemoryMappedFile.CreateFromFile(_stream, null, TableSize, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, true);
                _view = _map.CreateViewAccessor(0, TableSize);

                PurgeAbandonedSessions();
                GuestPipeChannel.PurgeAbandoned();
                return true;
            }
            catch (Exception Ex)
            {
                Utils.LogError($"[GuestSession] Unavailable: {Ex.Message}");
                _unavailable = true;
                _view = null;
                return false;
            }
        }

        private static void Discard()
        {
            GuestSessionMailbox.Close();

            _view?.Dispose();
            _map?.Dispose();
            _stream?.Dispose();

            _view = null;
            _map = null;
            _stream = null;

            try
            {
                System.IO.Directory.Delete(Directory, true);
            }
            catch (Exception)
            {
            }
        }

        /// <summary>
        /// Drops the files of sessions whose members all died. Only ones with no live host process are removed.
        /// </summary>
        private static void PurgeAbandonedSessions()
        {
            string Root = Path.Combine(AppContext.BaseDirectory, DirectoryName);

            try
            {
                foreach (string Candidate in System.IO.Directory.GetDirectories(Root))
                {
                    if (string.Equals(Path.GetFileName(Candidate), SessionId, StringComparison.Ordinal) || HasLiveMember(Candidate))
                        continue;

                    try
                    {
                        System.IO.Directory.Delete(Candidate, true);
                    }
                    catch (Exception)
                    {
                    }
                }
            }
            catch (Exception)
            {
            }
        }

        private static bool HasLiveMember(string SessionDirectory)
        {
            try
            {
                using FileStream Table = new FileStream(
                    Path.Combine(SessionDirectory, TableFileName),
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);

                if (Table.Length < TableSize)
                    return false;

                byte[] Slots = new byte[TableSize];
                if (Table.ReadAtLeast(Slots, Slots.Length, false) < Slots.Length)
                    return false;

                for (int Index = 0; Index < SlotCount; Index++)
                {
                    int Offset = Index * SlotSize;
                    if (BitConverter.ToUInt32(Slots, Offset + StateOffset) == SlotLive &&
                        IsHostAlive(BitConverter.ToUInt32(Slots, Offset + HostProcessIdOffset)))
                        return true;
                }

                return false;
            }
            catch (Exception)
            {
                // Unreadable is not proof of abandonment, and deleting a running session is worse than keeping it.
                return true;
            }
        }

        private static void WatchControlRequests()
        {
            // Named events and semaphores do not exist on Unix, only named mutexes, hence polling.
            while (true)
            {
                Thread.Sleep(ControlPollMilliseconds);

                RemoteGuestProcess.PollLive();

                uint Request;
                uint ExitCode;

                lock (Sync)
                {
                    if (_ownSlot < 0 || _view == null)
                        return;

                    using SessionLock Lock = Acquire();
                    if (!Lock.Held)
                        continue;

                    int Offset = SlotOffset(_ownSlot);
                    Request = _view.ReadUInt32(Offset + ControlOffset);
                    ExitCode = _view.ReadUInt32(Offset + ControlExitCodeOffset);

                    if (Request != ControlNone)
                        _view.Write(Offset + ControlOffset, ControlNone);
                }

                if (Request != ControlTerminate)
                    continue;

                try
                {
                    _terminateCallback?.Invoke(ExitCode);
                }
                catch (Exception Ex)
                {
                    Utils.LogError($"[GuestSession] Terminate request failed: {Ex.Message}");
                }

                return;
            }
        }

        private static bool TryFindLiveSlotLocked(uint GuestProcessId, out int Slot)
        {
            Slot = -1;

            for (int Index = 0; Index < SlotCount; Index++)
            {
                int Offset = SlotOffset(Index);
                if (_view.ReadUInt32(Offset + StateOffset) != SlotLive || _view.ReadUInt32(Offset + GuestProcessIdOffset) != GuestProcessId)
                    continue;

                if (!IsHostAlive(_view.ReadUInt32(Offset + HostProcessIdOffset)))
                {
                    _view.Write(Offset + StateOffset, SlotFree);
                    return false;
                }

                Slot = Index;
                return true;
            }

            return false;
        }

        private static int CountLiveLocked()
        {
            int Count = 0;

            for (int Index = 0; Index < SlotCount; Index++)
            {
                int Offset = SlotOffset(Index);
                if (_view.ReadUInt32(Offset + StateOffset) != SlotLive)
                    continue;

                if (IsHostAlive(_view.ReadUInt32(Offset + HostProcessIdOffset)))
                    Count++;
                else
                    _view.Write(Offset + StateOffset, SlotFree);
            }

            return Count;
        }

        private static void ClaimSlot(int Offset, uint GuestProcessId, uint Architecture, string ImageName)
        {
            for (int Cursor = 0; Cursor < SlotSize; Cursor += 8)
                _view.Write(Offset + Cursor, 0UL);

            byte[] Name = Encoding.Unicode.GetBytes(ImageName ?? string.Empty);
            int NameLength = Math.Min(Name.Length, MaxImageBytes);

            _view.Write(Offset + HostProcessIdOffset, (uint)Environment.ProcessId);
            _view.Write(Offset + GuestProcessIdOffset, GuestProcessId);
            _view.Write(Offset + SpawnTokenOffset, SpawnToken);
            _view.Write(Offset + ArchitectureOffset, Architecture);
            _view.Write(Offset + StartTimeOffset, DateTime.UtcNow.Ticks);
            _view.Write(Offset + ImageLengthOffset, (uint)NameLength);

            if (NameLength > 0)
                _view.WriteArray(Offset + ImageOffset, Name, 0, NameLength);

            _view.Write(Offset + StateOffset, SlotLive);
            _view.Flush();
        }

        private static int SlotOffset(int Slot) => Slot * SlotSize;

        internal static bool IsHostAlive(uint HostProcessId)
        {
            if (HostProcessId == 0)
                return false;

            if (HostProcessId == (uint)Environment.ProcessId)
                return true;

            try
            {
                using System.Diagnostics.Process Existing = System.Diagnostics.Process.GetProcessById((int)HostProcessId);
                return !Existing.HasExited;
            }
            catch (ArgumentException)
            {
                return false;
            }
            catch (InvalidOperationException)
            {
                return false;
            }
        }

        private const int LivenessCacheMilliseconds = 100;
        private const int LivenessCacheLimit = 64;
        private static readonly Dictionary<ulong, long> AliveCheckedAt = new();

        // A holder is a host process id and, in the high half, its start time, so a reused process id is another holder.
        internal static readonly ulong OwnHolder = CurrentHolder();

        private static ulong CurrentHolder()
        {
            uint Self = (uint)Environment.ProcessId;
            TryGetStartStamp(Self, out uint Stamp);
            return ((ulong)Stamp << 32) | Self;
        }

        // On Linux Process.StartTime uses each process's own wall clock, so two processes disagree by milliseconds.
        private static bool TryGetStartStamp(uint HostProcessId, out uint Stamp)
        {
            Stamp = 0;

            try
            {
                if (GeneralHelper.IsLinux)
                {
                    // proc(5). The command name is in parentheses and may hold spaces, so fields count from the last ')'.
                    string Stat = File.ReadAllText($"/proc/{HostProcessId}/stat");
                    int NameEnd = Stat.LastIndexOf(')');
                    if (NameEnd < 0 || NameEnd + 2 >= Stat.Length)
                        return false;

                    string[] Fields = Stat.Substring(NameEnd + 2).Split(' ');
                    if (Fields.Length < 20 || Fields[0] == "Z" || Fields[0] == "X" ||
                        !ulong.TryParse(Fields[19], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out ulong StartTicks))
                        return false;

                    Stamp = (uint)StartTicks;
                    return true;
                }

                using System.Diagnostics.Process Existing = System.Diagnostics.Process.GetProcessById((int)HostProcessId);
                if (Existing.HasExited)
                    return false;

                Stamp = (uint)(Existing.StartTime.ToUniversalTime().Ticks / TimeSpan.TicksPerMillisecond);
                return true;
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException || Error is ArgumentException ||
                                          Error is InvalidOperationException || Error is System.ComponentModel.Win32Exception ||
                                          Error is NotSupportedException)
            {
                return false;
            }
        }

        private static bool IsHolderAlive(ulong Holder)
            => TryGetStartStamp((uint)Holder, out uint Stamp) && (((ulong)Stamp << 32) | (uint)Holder) == Holder;

        internal static bool IsHolderAliveCached(ulong Holder)
        {
            if (Holder == 0)
                return false;

            if (Holder == OwnHolder)
                return true;

            if ((uint)Holder == (uint)Environment.ProcessId)
                return false;

            long Now = Environment.TickCount64;
            lock (AliveCheckedAt)
            {
                if (AliveCheckedAt.TryGetValue(Holder, out long CheckedAt) && Now - CheckedAt < LivenessCacheMilliseconds)
                    return true;
            }

            bool Alive = IsHolderAlive(Holder);

            lock (AliveCheckedAt)
            {
                if (!Alive)
                {
                    AliveCheckedAt.Remove(Holder);
                    return false;
                }

                if (AliveCheckedAt.Count >= LivenessCacheLimit)
                {
                    List<ulong> Stale = new List<ulong>();
                    foreach (KeyValuePair<ulong, long> Entry in AliveCheckedAt)
                    {
                        if (Now - Entry.Value >= LivenessCacheMilliseconds)
                            Stale.Add(Entry.Key);
                    }

                    foreach (ulong Key in Stale)
                        AliveCheckedAt.Remove(Key);
                }

                if (AliveCheckedAt.Count < LivenessCacheLimit)
                    AliveCheckedAt[Holder] = Now;
            }

            return true;
        }

        private static string Sanitize(string Value)
        {
            StringBuilder Builder = new StringBuilder(Value.Length);
            foreach (char Character in Value)
            {
                if (char.IsAsciiLetterOrDigit(Character) || Character == '-' || Character == '_')
                    Builder.Append(Character);
            }

            return Builder.Length == 0 ? "default" : Builder.ToString();
        }
    }

    internal static unsafe class SessionHolders
    {
        internal const int EntryBytes = 8;

        private static ref ulong Entry(byte* Table, int Slot) => ref *(ulong*)(Table + Slot * EntryBytes);

        // -1 when every slot has a live holder.
        internal static int Register(byte* Table, int Slots)
        {
            for (int i = 0; i < Slots; i++)
            {
                ref ulong Holder = ref Entry(Table, i);
                ulong Current = Volatile.Read(ref Holder);
                if (Current != 0 && !GuestSession.IsHolderAliveCached(Current))
                    Interlocked.CompareExchange(ref Holder, 0, Current);

                if (Interlocked.CompareExchange(ref Holder, GuestSession.OwnHolder, 0) == 0)
                    return i;
            }

            return -1;
        }

        internal static void Release(byte* Table, int Slot)
        {
            if (Slot >= 0)
                Interlocked.CompareExchange(ref Entry(Table, Slot), 0, GuestSession.OwnHolder);
        }

        internal static void Claim(byte* Table, int Slot) => Volatile.Write(ref Entry(Table, Slot), GuestSession.OwnHolder);

        internal static void Clear(byte* Table, int Slots)
        {
            for (int i = 0; i < Slots; i++)
                Volatile.Write(ref Entry(Table, i), 0);
        }

        internal static bool HasLive(byte* Table, int Slots, bool ClearDead)
        {
            for (int i = 0; i < Slots; i++)
            {
                ref ulong Holder = ref Entry(Table, i);
                ulong Current = Volatile.Read(ref Holder);
                if (Current == 0)
                    continue;

                if (GuestSession.IsHolderAliveCached(Current))
                    return true;

                if (ClearDead)
                    Interlocked.CompareExchange(ref Holder, 0, Current);
            }

            return false;
        }

        internal static bool HasLiveProcess(byte* Table, int Slots, uint HostProcessId)
        {
            for (int i = 0; i < Slots; i++)
            {
                ulong Current = Volatile.Read(ref Entry(Table, i));
                if ((uint)Current == HostProcessId && GuestSession.IsHolderAliveCached(Current))
                    return true;
            }

            return false;
        }
    }

    // NT keeps one position per file object, so a child that writes an inherited file moves its creator's position.
    internal sealed unsafe class SharedFilePosition : IDisposable
    {
        private const uint Magic = 0x50465642;
        private const int MagicOffset = 0x00;
        private const int PositionOffset = 0x08;
        private const int HoldersOffset = 0x10;
        private const int HolderSlots = 64;
        private const int CellBytes = HoldersOffset + HolderSlots * SessionHolders.EntryBytes;
        private const string CellDirectoryName = "files";
        private const string CellExtension = ".pos";

        private FileStream Stream;
        private MemoryMappedFile Map;
        private MemoryMappedViewAccessor View;
        private byte* Base;
        private int Slot = -1;

        internal string CellPath { get; }

        private SharedFilePosition(string CellPath, FileStream Stream, MemoryMappedFile Map, MemoryMappedViewAccessor View, byte* Base)
        {
            this.CellPath = CellPath;
            this.Stream = Stream;
            this.Map = Map;
            this.View = View;
            this.Base = Base;
        }

        private static string CellDirectory => Path.Combine(GuestSession.Directory, CellDirectoryName);

        internal long Value
        {
            get => Volatile.Read(ref *(long*)(Base + PositionOffset));
            set => Volatile.Write(ref *(long*)(Base + PositionOffset), value);
        }

        internal static SharedFilePosition Create(long Position)
        {
            try
            {
                System.IO.Directory.CreateDirectory(CellDirectory);
                string CellPath = Path.Combine(CellDirectory, Guid.NewGuid().ToString("N") + CellExtension);
                SharedFilePosition Cell = MapCell(CellPath, FileMode.CreateNew);
                if (Cell == null)
                    return null;

                Cell.Value = Position;
                Volatile.Write(ref *(uint*)(Cell.Base + MagicOffset), Magic);
                if (!Cell.TryRegister())
                {
                    Cell.Dispose();
                    return null;
                }

                return Cell;
            }
            catch (IOException Error)
            {
                Utils.LogError($"[SharedFilePosition] Cannot create a shared position: {Error.Message}");
                return null;
            }
        }

        // Null for a path outside this session's cells.
        internal static SharedFilePosition Open(string CellPath)
        {
            if (string.IsNullOrEmpty(CellPath) || !CellPath.EndsWith(CellExtension, StringComparison.Ordinal))
                return null;

            string Full = Path.GetFullPath(CellPath);
            string Root = Path.GetFullPath(CellDirectory) + Path.DirectorySeparatorChar;
            if (!Full.StartsWith(Root, GeneralHelper.IsWindows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                return null;

            SharedFilePosition Cell = MapCell(Full, FileMode.Open);
            if (Cell == null)
                return null;

            if (Volatile.Read(ref *(uint*)(Cell.Base + MagicOffset)) != Magic || !Cell.TryRegister())
            {
                Cell.Dispose();
                return null;
            }

            return Cell;
        }

        private static SharedFilePosition MapCell(string CellPath, FileMode Mode)
        {
            FileStream CellStream = null;
            MemoryMappedFile Mapping = null;
            MemoryMappedViewAccessor CellView = null;

            try
            {
                CellStream = new FileStream(CellPath, Mode, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);
                if (CellStream.Length < CellBytes)
                    CellStream.SetLength(CellBytes);

                Mapping = MemoryMappedFile.CreateFromFile(CellStream, null, CellBytes, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, true);
                CellView = Mapping.CreateViewAccessor(0, CellBytes, MemoryMappedFileAccess.ReadWrite);

                byte* Pointer = null;
                CellView.SafeMemoryMappedViewHandle.AcquirePointer(ref Pointer);
                if (Pointer != null)
                    return new SharedFilePosition(CellPath, CellStream, Mapping, CellView, Pointer);
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException)
            {
                Utils.LogError($"[SharedFilePosition] Cannot map {CellPath}: {Error.Message}");
            }

            CellView?.Dispose();
            Mapping?.Dispose();
            CellStream?.Dispose();
            return null;
        }

        private bool TryRegister()
        {
            Slot = SessionHolders.Register(Base + HoldersOffset, HolderSlots);
            return Slot >= 0;
        }

        public void Dispose()
        {
            if (Base == null)
                return;

            SessionHolders.Release(Base + HoldersOffset, Slot);

            bool Last = !SessionHolders.HasLive(Base + HoldersOffset, HolderSlots, false);

            View.SafeMemoryMappedViewHandle.ReleasePointer();
            View.Dispose();
            Map.Dispose();
            Stream.Dispose();
            Base = null;

            if (!Last)
                return;

            try
            {
                File.Delete(CellPath);
            }
            catch (IOException Error)
            {
                Utils.LogError($"[SharedFilePosition] Cannot remove {CellPath}: {Error.Message}");
            }
        }
    }

    // On Android a session file backs the memory, so the header page counts its holders.
    internal sealed unsafe class GuestSharedMemory : IDisposable
    {
        private const uint Magic = 0x4D535642;
        private const int MagicOffset = 0x00;
        private const int SizeOffset = 0x08;
        private const int HoldersOffset = 0x10;
        private const int HolderSlots = 64;
        private const string SectionDirectoryName = "sections";
        private const string SectionExtension = ".section";
        private const uint MfdCloexec = 0x1;

        private static readonly long HeaderBytes = Math.Max(Environment.SystemPageSize, 0x1000);

        private FileStream Stream;
        private MemoryMappedFile Map;
        private MemoryMappedViewAccessor View;
        private byte* Base;
        private int Slot = -1;
        private readonly bool InSessionFile;

        // A mapping name on Windows, a /proc descriptor path on Linux, a session file on Android.
        internal string Location { get; }

        internal IntPtr Pointer => (IntPtr)(Base + HeaderBytes);

        private GuestSharedMemory(string Location, FileStream Stream, MemoryMappedFile Map, MemoryMappedViewAccessor View, byte* Base, bool InSessionFile)
        {
            this.Location = Location;
            this.Stream = Stream;
            this.Map = Map;
            this.View = View;
            this.Base = Base;
            this.InSessionFile = InSessionFile;
        }

        private static string SectionDirectory => Path.Combine(GuestSession.Directory, SectionDirectoryName);

        private static string MappingNamePrefix => $"Local\\brovan-{GuestSession.SessionId}-";

        private static bool IsValidSize(ulong Size) => Size != 0 && Size <= (ulong)(long.MaxValue - HeaderBytes);

        internal static GuestSharedMemory Create(ulong Size)
        {
            if (!IsValidSize(Size))
                return null;

            long Length = HeaderBytes + (long)Size;
            GuestSharedMemory Memory;
            if (GeneralHelper.IsWindows)
                Memory = CreateNamedMapping(Length);
            else if (Brovan.Android.AndroidHost.IsActive)
                Memory = CreateSessionFile(Length);
            else
                Memory = CreateAnonymousFile(Length);

            if (Memory == null)
                return null;

            *(ulong*)(Memory.Base + SizeOffset) = Size;
            Volatile.Write(ref *(uint*)(Memory.Base + MagicOffset), Magic);
            if (!Memory.InSessionFile || Memory.TryRegister())
                return Memory;

            Memory.Dispose();
            return null;
        }

        // The location comes from another process, so it may only name memory of this session.
        internal static GuestSharedMemory Open(string Location, ulong Size)
        {
            if (string.IsNullOrEmpty(Location) || !IsValidSize(Size))
                return null;

            long Length = HeaderBytes + (long)Size;
            GuestSharedMemory Memory;
            if (GeneralHelper.IsWindows)
                Memory = OpenNamedMapping(Location, Length);
            else if (Brovan.Android.AndroidHost.IsActive)
                Memory = OpenSessionFile(Location, Length);
            else
                Memory = OpenAnonymousFile(Location, Length);

            if (Memory == null)
                return null;

            if (Volatile.Read(ref *(uint*)(Memory.Base + MagicOffset)) != Magic || *(ulong*)(Memory.Base + SizeOffset) != Size
                || (Memory.InSessionFile && !Memory.TryRegister()))
            {
                Memory.Dispose();
                return null;
            }

            return Memory;
        }

        [SupportedOSPlatform("windows")]
        private static GuestSharedMemory CreateNamedMapping(long Length)
        {
            string Name = MappingNamePrefix + Guid.NewGuid().ToString("N");
            try
            {
                return Wrap(Name, null, MemoryMappedFile.CreateNew(Name, Length, MemoryMappedFileAccess.ReadWrite), Length, false);
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException)
            {
                Utils.LogError($"[GuestSharedMemory] Cannot create mapping {Name}: {Error.Message}");
                return null;
            }
        }

        [SupportedOSPlatform("windows")]
        private static GuestSharedMemory OpenNamedMapping(string Name, long Length)
        {
            string Prefix = MappingNamePrefix;
            if (!Name.StartsWith(Prefix, StringComparison.Ordinal) || Name.Length != Prefix.Length + 32 || !Guid.TryParseExact(Name.AsSpan(Prefix.Length), "N", out _))
                return null;

            try
            {
                return Wrap(Name, null, MemoryMappedFile.OpenExisting(Name, MemoryMappedFileRights.ReadWrite), Length, false);
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException)
            {
                Utils.LogError($"[GuestSharedMemory] Cannot open mapping {Name}: {Error.Message}");
                return null;
            }
        }

        private static GuestSharedMemory CreateAnonymousFile(long Length)
        {
            int Descriptor;
            try
            {
                Descriptor = NativeUnixImports.MemfdCreate("brovan-section", MfdCloexec);
            }
            catch (EntryPointNotFoundException Error)
            {
                Utils.LogError($"[GuestSharedMemory] The host C library has no memfd_create: {Error.Message}");
                return null;
            }

            if (Descriptor < 0)
            {
                Utils.LogError($"[GuestSharedMemory] memfd_create failed with errno {Marshal.GetLastWin32Error()}.");
                return null;
            }

            SafeFileHandle Handle = new SafeFileHandle((IntPtr)Descriptor, true);
            FileStream FileStream = null;
            try
            {
                FileStream = new FileStream(Handle, FileAccess.ReadWrite);
                FileStream.SetLength(Length);
                MemoryMappedFile Mapping = MemoryMappedFile.CreateFromFile(FileStream, null, Length, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, true);
                return Wrap(ProcDescriptorPath(Descriptor), FileStream, Mapping, Length, false);
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException)
            {
                Utils.LogError($"[GuestSharedMemory] Cannot map an anonymous file: {Error.Message}");
                FileStream?.Dispose();
                Handle.Dispose();
                return null;
            }
        }

        private static GuestSharedMemory OpenAnonymousFile(string Location, long Length)
        {
            string[] Parts = Location.Split('/');
            if (Parts.Length != 5 || Parts[0].Length != 0 || Parts[1] != "proc" || Parts[3] != "fd"
                || !uint.TryParse(Parts[2], out uint HostProcessId) || !uint.TryParse(Parts[4], out _)
                || !GuestSession.IsLiveMemberHost(HostProcessId))
                return null;

            FileStream FileStream = null;
            try
            {
                FileStream = new FileStream(Location, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
                if (FileStream.Length != Length)
                {
                    FileStream.Dispose();
                    return null;
                }

                MemoryMappedFile Mapping = MemoryMappedFile.CreateFromFile(FileStream, null, Length, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, true);
                return Wrap(ProcDescriptorPath((int)FileStream.SafeFileHandle.DangerousGetHandle()), FileStream, Mapping, Length, false);
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException)
            {
                Utils.LogError($"[GuestSharedMemory] Cannot open {Location}: {Error.Message}");
                FileStream?.Dispose();
                return null;
            }
        }

        private static string ProcDescriptorPath(int Descriptor) => $"/proc/{Environment.ProcessId}/fd/{Descriptor}";

        private static GuestSharedMemory CreateSessionFile(long Length)
        {
            string Location = null;
            try
            {
                GuestSession.CreatePrivateDirectory(SectionDirectory);
                Location = Path.Combine(SectionDirectory, Guid.NewGuid().ToString("N") + SectionExtension);

                using (FileStream Initial = new FileStream(Location, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
                    Initial.SetLength(Length);

                GuestSharedMemory Memory = MapSessionFile(Location, Length);
                if (Memory != null)
                    return Memory;
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException)
            {
                Utils.LogError($"[GuestSharedMemory] Cannot create section memory: {Error.Message}");
            }

            if (Location != null)
                Remove(Location);

            return null;
        }

        private static GuestSharedMemory OpenSessionFile(string Location, long Length)
        {
            if (!Location.EndsWith(SectionExtension, StringComparison.Ordinal))
                return null;

            string Full = Path.GetFullPath(Location);
            string Root = Path.GetFullPath(SectionDirectory) + Path.DirectorySeparatorChar;
            if (!Full.StartsWith(Root, StringComparison.Ordinal))
                return null;

            return MapSessionFile(Full, Length);
        }

        private static GuestSharedMemory MapSessionFile(string Location, long Length)
        {
            FileStream FileStream = null;
            try
            {
                FileStream = new FileStream(Location, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);
                if (FileStream.Length != Length)
                {
                    FileStream.Dispose();
                    return null;
                }

                MemoryMappedFile Mapping = MemoryMappedFile.CreateFromFile(FileStream, null, Length, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, true);
                return Wrap(Location, FileStream, Mapping, Length, true);
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException)
            {
                Utils.LogError($"[GuestSharedMemory] Cannot map {Location}: {Error.Message}");
                FileStream?.Dispose();
                return null;
            }
        }

        // Owns Stream and Mapping, even when it fails.
        private static GuestSharedMemory Wrap(string Location, FileStream Stream, MemoryMappedFile Mapping, long Length, bool InSessionFile)
        {
            MemoryMappedViewAccessor Accessor = null;
            try
            {
                Accessor = Mapping.CreateViewAccessor(0, Length, MemoryMappedFileAccess.ReadWrite);

                byte* Pointer = null;
                Accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref Pointer);
                if (Pointer != null)
                    return new GuestSharedMemory(Location, Stream, Mapping, Accessor, Pointer + Accessor.PointerOffset, InSessionFile);
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException || Error is ArgumentException)
            {
                Utils.LogError($"[GuestSharedMemory] Cannot map a view of {Location}: {Error.Message}");
            }

            Accessor?.Dispose();
            Mapping.Dispose();
            Stream?.Dispose();
            return null;
        }

        private static void Remove(string Location)
        {
            try
            {
                File.Delete(Location);
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException)
            {
                Utils.LogError($"[GuestSharedMemory] Cannot remove {Location}: {Error.Message}");
            }
        }

        private bool TryRegister()
        {
            Slot = SessionHolders.Register(Base + HoldersOffset, HolderSlots);
            return Slot >= 0;
        }

        public void Dispose()
        {
            if (Base == null)
                return;

            bool Last = false;
            if (InSessionFile)
            {
                SessionHolders.Release(Base + HoldersOffset, Slot);
                Last = !SessionHolders.HasLive(Base + HoldersOffset, HolderSlots, false);
            }

            View.SafeMemoryMappedViewHandle.ReleasePointer();
            View.Dispose();
            Map.Dispose();
            Stream?.Dispose();
            Base = null;

            if (Last)
                Remove(Location);
        }
    }

    internal readonly struct SessionLock : IDisposable
    {
        private readonly Mutex Owner;

        internal SessionLock(Mutex Owner) => this.Owner = Owner;

        internal bool Held => Owner != null;

        public void Dispose()
        {
            if (Owner == null)
                return;

            try
            {
                Owner.ReleaseMutex();
            }
            catch (Exception)
            {
            }
        }
    }
}
