using System.IO.MemoryMappedFiles;
using System.Text;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// Guest processes of one emulation session, published in a file every member maps.
    /// </summary>
    internal static class GuestSession
    {
        internal const int SlotCount = 16;

        private const string SessionVariable = "BROVAN_SESSION_ID";
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
        private const int ImageOffset = 0x40;
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
        internal static void PublishStartup(ulong PebAddress, ulong ProcessParameters)
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

                int Offset = SlotOffset(_ownSlot);
                _view.Write(Offset + ExitCodeOffset, ExitCode);
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
        internal static bool TryResolveMember(uint GuestProcessId, out uint HostProcessId, out string ImageName, out ulong PebAddress, out ulong ProcessParameters)
        {
            HostProcessId = 0;
            ImageName = string.Empty;
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
                HostProcessId = _view.ReadUInt32(Offset + HostProcessIdOffset);
                if (HostProcessId == 0)
                    return false;

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
        /// <param name="Members">Receives the guest process id and image name of every live member.</param>
        internal static void ListLive(List<(uint ProcessId, string ImageName)> Members)
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

                    Members.Add((_view.ReadUInt32(Offset + GuestProcessIdOffset), ImageName));
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
