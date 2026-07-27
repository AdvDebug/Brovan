using System.Buffers.Binary;
using System.IO.MemoryMappedFiles;
using System.Text;
using System.Threading;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static class GuestSessionRegistry
    {
        internal const uint ControlNone = 0;
        internal const uint ControlTerminate = 1;

        private const string SessionVariable = "BROVAN_SESSION_ID";
        private const uint Magic = 0x5652424E;
        private const uint Version = 1;
        private const int SlotCount = 64;
        private const int SlotSize = 512;
        private const int HeaderSize = 64;
        private const int MapSize = HeaderSize + (SlotCount * SlotSize);
        private const int MaxImageBytes = SlotSize - SlotImageOffset - 2;
        private const int WatcherIntervalMilliseconds = 150;

        internal const uint OpcodeReadMemory = 1;
        internal const uint OpcodeWriteMemory = 2;
        internal const uint OpcodeQueryPeb = 3;
        internal const uint OpcodeCreateThread = 4;

        private const int MailboxSize = 0x10000;
        private const int MailboxPayloadOffset = 0x40;
        internal const int MaxPayloadBytes = MailboxSize - MailboxPayloadOffset;
        private const int RequestTimeoutMilliseconds = 5000;

        private const int MailboxRequestSeqOffset = 0x00;
        private const int MailboxResponseSeqOffset = 0x04;
        private const int MailboxOpcodeOffset = 0x08;
        private const int MailboxStatusOffset = 0x0C;
        private const int MailboxAddressOffset = 0x10;
        private const int MailboxLengthOffset = 0x18;
        private const int MailboxResultLengthOffset = 0x1C;
        private const int MailboxExtraOffset = 0x20;
        private const int MailboxResultOffset = 0x28;

        private const int SlotStateOffset = 0x00;
        private const int SlotHostPidOffset = 0x04;
        private const int SlotGuestPidOffset = 0x08;
        private const int SlotArchOffset = 0x0C;
        private const int SlotStartTimeOffset = 0x10;
        private const int SlotControlOffset = 0x18;
        private const int SlotControlExitOffset = 0x1C;
        private const int SlotImageLengthOffset = 0x20;
        private const int SlotImageOffset = 0x28;

        private const uint SlotFree = 0;
        private const uint SlotLive = 1;

        private static readonly object Sync = new();

        private static FileStream _stream;
        private static MemoryMappedFile _map;
        private static MemoryMappedViewAccessor _view;
        private static FileStream _mailboxStream;
        private static MemoryMappedFile _mailboxMap;
        private static MemoryMappedViewAccessor _mailboxView;
        private static uint _lastHandledSequence;
        private static Mutex _mutex;
        private static Thread _watcher;
        private static int _ownSlot = -1;
        private static bool _initialiseFailed;
        private static Action<uint> _terminateCallback;

        internal static string SessionId
        {
            get
            {
                string Existing = Environment.GetEnvironmentVariable(SessionVariable);
                if (!string.IsNullOrWhiteSpace(Existing))
                    return Sanitize(Existing);

                string Created = Environment.ProcessId.ToString("X") + "-" + DateTime.UtcNow.Ticks.ToString("X");
                Environment.SetEnvironmentVariable(SessionVariable, Created);
                return Created;
            }
        }

        internal static void Join(uint GuestProcessId, uint Architecture, string ImageName, Action<uint> OnTerminateRequested)
        {
            lock (Sync)
            {
                if (_ownSlot >= 0 || _initialiseFailed)
                    return;

                if (!TryOpen())
                {
                    _initialiseFailed = true;
                    return;
                }

                _terminateCallback = OnTerminateRequested;

                if (!TryAcquire())
                    return;

                try
                {
                    for (int i = 0; i < SlotCount; i++)
                    {
                        int Offset = HeaderSize + (i * SlotSize);
                        uint State = _view.ReadUInt32(Offset + SlotStateOffset);
                        if (State == SlotLive && IsHostProcessAlive(_view.ReadUInt32(Offset + SlotHostPidOffset)))
                            continue;

                        WriteSlot(Offset, GuestProcessId, Architecture, ImageName);
                        _ownSlot = i;
                        break;
                    }
                }
                finally
                {
                    Release();
                }

                if (_ownSlot < 0)
                    return;

                AppDomain.CurrentDomain.ProcessExit += static (_, _) => Leave();
                StartWatcher();
            }
        }

        internal static void Leave()
        {
            lock (Sync)
            {
                if (_ownSlot < 0 || _view == null)
                    return;

                if (TryAcquire())
                {
                    try
                    {
                        _view.Write(HeaderSize + (_ownSlot * SlotSize) + SlotStateOffset, SlotFree);
                        _view.Flush();
                    }
                    finally
                    {
                        Release();
                    }
                }

                _ownSlot = -1;
            }
        }

        internal static int CountLive()
        {
            int Count = 0;

            lock (Sync)
            {
                if (!TryOpen() || !TryAcquire())
                    return 0;

                try
                {
                    for (int i = 0; i < SlotCount; i++)
                    {
                        int Offset = HeaderSize + (i * SlotSize);
                        if (_view.ReadUInt32(Offset + SlotStateOffset) != SlotLive)
                            continue;

                        if (IsHostProcessAlive(_view.ReadUInt32(Offset + SlotHostPidOffset)))
                            Count++;
                        else
                            _view.Write(Offset + SlotStateOffset, SlotFree);
                    }
                }
                finally
                {
                    Release();
                }
            }

            return Count;
        }

        internal static bool RequestTerminate(uint GuestProcessId, uint ExitCode)
        {
            lock (Sync)
            {
                if (!TryOpen() || !TryAcquire())
                    return false;

                try
                {
                    for (int i = 0; i < SlotCount; i++)
                    {
                        int Offset = HeaderSize + (i * SlotSize);
                        if (_view.ReadUInt32(Offset + SlotStateOffset) != SlotLive)
                            continue;

                        if (_view.ReadUInt32(Offset + SlotGuestPidOffset) != GuestProcessId)
                            continue;

                        if (!IsHostProcessAlive(_view.ReadUInt32(Offset + SlotHostPidOffset)))
                        {
                            _view.Write(Offset + SlotStateOffset, SlotFree);
                            return false;
                        }

                        _view.Write(Offset + SlotControlExitOffset, ExitCode);
                        _view.Write(Offset + SlotControlOffset, ControlTerminate);
                        _view.Flush();
                        return true;
                    }
                }
                finally
                {
                    Release();
                }
            }

            return false;
        }

        internal static NTSTATUS SendRequest(
            uint GuestProcessId,
            uint Opcode,
            ulong Address,
            ulong Extra,
            ReadOnlySpan<byte> Input,
            Span<byte> Output,
            out int OutputLength,
            out ulong Result)
        {
            OutputLength = 0;
            Result = 0;

            if (Input.Length > MaxPayloadBytes || Output.Length > MaxPayloadBytes)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            int Slot;
            uint Sequence;

            lock (Sync)
            {
                if (!TryOpen() || _mailboxView == null || !TryAcquire())
                    return NTSTATUS.STATUS_NOT_SUPPORTED;

                try
                {
                    Slot = FindLiveSlot(GuestProcessId);
                    if (Slot < 0)
                        return NTSTATUS.STATUS_INVALID_CID;

                    long Base = (long)Slot * MailboxSize;
                    uint Pending = _mailboxView.ReadUInt32(Base + MailboxRequestSeqOffset);
                    if (Pending != _mailboxView.ReadUInt32(Base + MailboxResponseSeqOffset))
                        return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

                    _mailboxView.Write(Base + MailboxOpcodeOffset, Opcode);
                    _mailboxView.Write(Base + MailboxAddressOffset, Address);
                    _mailboxView.Write(Base + MailboxExtraOffset, Extra);
                    _mailboxView.Write(Base + MailboxLengthOffset, (uint)(Opcode == OpcodeReadMemory ? Output.Length : Input.Length));
                    _mailboxView.Write(Base + MailboxResultLengthOffset, 0u);
                    _mailboxView.Write(Base + MailboxStatusOffset, 0u);

                    if (Input.Length > 0)
                    {
                        byte[] Buffer = Input.ToArray();
                        _mailboxView.WriteArray(Base + MailboxPayloadOffset, Buffer, 0, Buffer.Length);
                    }

                    Sequence = Pending + 1;
                    _mailboxView.Write(Base + MailboxRequestSeqOffset, Sequence);
                    _mailboxView.Flush();
                }
                finally
                {
                    Release();
                }
            }

            long Deadline = Environment.TickCount64 + RequestTimeoutMilliseconds;
            while (Environment.TickCount64 < Deadline)
            {
                Thread.Sleep(1);

                lock (Sync)
                {
                    if (_mailboxView == null || !TryAcquire())
                        continue;

                    try
                    {
                        long Base = (long)Slot * MailboxSize;
                        if (_mailboxView.ReadUInt32(Base + MailboxResponseSeqOffset) != Sequence)
                            continue;

                        NTSTATUS Status = (NTSTATUS)_mailboxView.ReadUInt32(Base + MailboxStatusOffset);
                        Result = _mailboxView.ReadUInt64(Base + MailboxResultOffset);
                        int Length = (int)Math.Min(_mailboxView.ReadUInt32(Base + MailboxResultLengthOffset), (uint)Output.Length);

                        if (Length > 0)
                        {
                            byte[] Buffer = new byte[Length];
                            _mailboxView.ReadArray(Base + MailboxPayloadOffset, Buffer, 0, Length);
                            Buffer.AsSpan().CopyTo(Output);
                        }

                        OutputLength = Length;
                        return Status;
                    }
                    finally
                    {
                        Release();
                    }
                }
            }

            return NTSTATUS.STATUS_TIMEOUT;
        }

        internal static bool TryTakeRequest(out uint Opcode, out ulong Address, out ulong Extra, out int Length, out byte[] Input)
        {
            Opcode = 0;
            Address = 0;
            Extra = 0;
            Length = 0;
            Input = null;

            lock (Sync)
            {
                if (_ownSlot < 0 || _mailboxView == null)
                    return false;

                long Base = (long)_ownSlot * MailboxSize;
                if (_mailboxView.ReadUInt32(Base + MailboxRequestSeqOffset) == _lastHandledSequence)
                    return false;

                if (!TryAcquire())
                    return false;

                try
                {
                    uint Sequence = _mailboxView.ReadUInt32(Base + MailboxRequestSeqOffset);
                    if (Sequence == _lastHandledSequence)
                        return false;

                    Opcode = _mailboxView.ReadUInt32(Base + MailboxOpcodeOffset);
                    Address = _mailboxView.ReadUInt64(Base + MailboxAddressOffset);
                    Extra = _mailboxView.ReadUInt64(Base + MailboxExtraOffset);
                    Length = (int)Math.Min(_mailboxView.ReadUInt32(Base + MailboxLengthOffset), (uint)MaxPayloadBytes);

                    if (Opcode == OpcodeWriteMemory && Length > 0)
                    {
                        Input = new byte[Length];
                        _mailboxView.ReadArray(Base + MailboxPayloadOffset, Input, 0, Length);
                    }

                    _lastHandledSequence = Sequence;
                    return true;
                }
                finally
                {
                    Release();
                }
            }
        }

        internal static void CompleteRequest(uint Status, ulong Result, ReadOnlySpan<byte> Output)
        {
            lock (Sync)
            {
                if (_ownSlot < 0 || _mailboxView == null || !TryAcquire())
                    return;

                try
                {
                    long Base = (long)_ownSlot * MailboxSize;
                    int Length = Math.Min(Output.Length, MaxPayloadBytes);

                    if (Length > 0)
                    {
                        byte[] Buffer = Output.Slice(0, Length).ToArray();
                        _mailboxView.WriteArray(Base + MailboxPayloadOffset, Buffer, 0, Length);
                    }

                    _mailboxView.Write(Base + MailboxResultLengthOffset, (uint)Length);
                    _mailboxView.Write(Base + MailboxResultOffset, Result);
                    _mailboxView.Write(Base + MailboxStatusOffset, Status);
                    _mailboxView.Write(Base + MailboxResponseSeqOffset, _lastHandledSequence);
                    _mailboxView.Flush();
                }
                finally
                {
                    Release();
                }
            }
        }

        private static int FindLiveSlot(uint GuestProcessId)
        {
            for (int i = 0; i < SlotCount; i++)
            {
                int Offset = HeaderSize + (i * SlotSize);
                if (_view.ReadUInt32(Offset + SlotStateOffset) != SlotLive)
                    continue;

                if (_view.ReadUInt32(Offset + SlotGuestPidOffset) != GuestProcessId)
                    continue;

                return IsHostProcessAlive(_view.ReadUInt32(Offset + SlotHostPidOffset)) ? i : -1;
            }

            return -1;
        }

        private static void StartWatcher()
        {
            _watcher = new Thread(WatchForRequests)
            {
                IsBackground = true,
                Name = "BrovanSessionWatcher",
            };

            _watcher.Start();
        }

        private static void WatchForRequests()
        {
            while (true)
            {
                Thread.Sleep(WatcherIntervalMilliseconds);

                uint Request;
                uint ExitCode;

                lock (Sync)
                {
                    if (_ownSlot < 0 || _view == null)
                        return;

                    if (!TryAcquire())
                        continue;

                    try
                    {
                        int Offset = HeaderSize + (_ownSlot * SlotSize);
                        Request = _view.ReadUInt32(Offset + SlotControlOffset);
                        ExitCode = _view.ReadUInt32(Offset + SlotControlExitOffset);
                        if (Request != ControlNone)
                            _view.Write(Offset + SlotControlOffset, ControlNone);
                    }
                    finally
                    {
                        Release();
                    }
                }

                if (Request == ControlTerminate)
                {
                    try
                    {
                        _terminateCallback?.Invoke(ExitCode);
                    }
                    catch (Exception Ex)
                    {
                        Utils.LogError($"[GuestSessionRegistry] Terminate request failed: {Ex.Message}");
                    }

                    return;
                }
            }
        }

        private static bool TryOpen()
        {
            if (_view != null)
                return true;

            if (_initialiseFailed)
                return false;

            try
            {
                string Directory = Path.Combine(Path.GetTempPath(), "brovan-session-" + SessionId);
                System.IO.Directory.CreateDirectory(Directory);

                _mutex = new Mutex(false, "BrovanSession_" + SessionId);

                _stream = new FileStream(
                    Path.Combine(Directory, "processes.bin"),
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.ReadWrite | FileShare.Delete);

                if (_stream.Length < MapSize)
                    _stream.SetLength(MapSize);

                _map = MemoryMappedFile.CreateFromFile(_stream, null, MapSize, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, true);
                _view = _map.CreateViewAccessor(0, MapSize);

                long MailboxTotal = (long)SlotCount * MailboxSize;
                _mailboxStream = new FileStream(
                    Path.Combine(Directory, "mailboxes.bin"),
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.ReadWrite | FileShare.Delete);

                if (_mailboxStream.Length < MailboxTotal)
                    _mailboxStream.SetLength(MailboxTotal);

                _mailboxMap = MemoryMappedFile.CreateFromFile(_mailboxStream, null, MailboxTotal, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, true);
                _mailboxView = _mailboxMap.CreateViewAccessor(0, MailboxTotal);

                if (TryAcquire())
                {
                    try
                    {
                        if (_view.ReadUInt32(0) != Magic)
                        {
                            _view.Write(0, Magic);
                            _view.Write(4, Version);
                            _view.Write(8, (uint)SlotCount);
                        }
                    }
                    finally
                    {
                        Release();
                    }
                }

                return true;
            }
            catch (Exception Ex)
            {
                Utils.LogError($"[GuestSessionRegistry] Unavailable: {Ex.Message}");
                _initialiseFailed = true;
                _view = null;
                return false;
            }
        }

        private static bool TryAcquire()
        {
            if (_mutex == null)
                return false;

            try
            {
                return _mutex.WaitOne(2000);
            }
            catch (AbandonedMutexException)
            {
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static void Release()
        {
            try
            {
                _mutex?.ReleaseMutex();
            }
            catch (Exception)
            {
            }
        }

        private static void WriteSlot(int Offset, uint GuestProcessId, uint Architecture, string ImageName)
        {
            for (int i = 0; i < SlotSize; i += 8)
                _view.Write(Offset + i, 0UL);

            byte[] Name = Encoding.Unicode.GetBytes(ImageName ?? string.Empty);
            int NameLength = Math.Min(Name.Length, MaxImageBytes);

            _view.Write(Offset + SlotHostPidOffset, (uint)Environment.ProcessId);
            _view.Write(Offset + SlotGuestPidOffset, GuestProcessId);
            _view.Write(Offset + SlotArchOffset, Architecture);
            _view.Write(Offset + SlotStartTimeOffset, DateTime.UtcNow.Ticks);
            _view.Write(Offset + SlotImageLengthOffset, (uint)NameLength);

            if (NameLength > 0)
                _view.WriteArray(Offset + SlotImageOffset, Name, 0, NameLength);

            _view.Write(Offset + SlotStateOffset, SlotLive);
            _view.Flush();
        }

        private static bool IsHostProcessAlive(uint HostProcessId)
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
}
