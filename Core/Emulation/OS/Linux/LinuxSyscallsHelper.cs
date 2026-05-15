using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using HostSocket = System.Net.Sockets.Socket;
using Brovan;
using Brovan.Core.Emulation.Guests;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Linux
{
    public enum LinuxStatVariant
    {
        Native,
        Compat64
    }

    public enum LinuxStatFileKind
    {
        RegularFile,
        Directory,
        CharacterDevice,
        SymbolicLink
    }

    public enum LinuxErrno : int
    {
        ESUCCESS = 0,
        EPERM = 1,
        ENOENT = 2,
        ESRCH = 3,
        EINTR = 4,
        EIO = 5,
        ENXIO = 6,
        E2BIG = 7,
        ENOEXEC = 8,
        EBADF = 9,
        ECHILD = 10,
        EAGAIN = 11,
        EWOULDBLOCK = EAGAIN,
        ENOMEM = 12,
        EACCES = 13,
        EFAULT = 14,
        ENOTBLK = 15,
        EBUSY = 16,
        EEXIST = 17,
        EXDEV = 18,
        ENODEV = 19,
        ENOTDIR = 20,
        EISDIR = 21,
        EINVAL = 22,
        ENFILE = 23,
        EMFILE = 24,
        ENOTTY = 25,
        ETXTBSY = 26,
        EFBIG = 27,
        ENOSPC = 28,
        ESPIPE = 29,
        EROFS = 30,
        EMLINK = 31,
        EPIPE = 32,
        EDOM = 33,
        ERANGE = 34,
        EDEADLK = 35,
        EDEADLOCK = EDEADLK,
        ENAMETOOLONG = 36,
        ENOLCK = 37,
        ENOSYS = 38,
        ENOTEMPTY = 39,
        ELOOP = 40,
        ENOMSG = 42,
        EIDRM = 43,
        ECHRNG = 44,
        EL2NSYNC = 45,
        EL3HLT = 46,
        EL3RST = 47,
        ELNRNG = 48,
        EUNATCH = 49,
        ENOCSI = 50,
        EL2HLT = 51,
        EBADE = 52,
        EBADR = 53,
        EXFULL = 54,
        ENOANO = 55,
        EBADRQC = 56,
        EBADSLT = 57,
        EBFONT = 59,
        ENOSTR = 60,
        ENODATA = 61,
        ETIME = 62,
        ENOSR = 63,
        ENONET = 64,
        ENOPKG = 65,
        EREMOTE = 66,
        ENOLINK = 67,
        EADV = 68,
        ESRMNT = 69,
        ECOMM = 70,
        EPROTO = 71,
        EMULTIHOP = 72,
        EDOTDOT = 73,
        EBADMSG = 74,
        EOVERFLOW = 75,
        ENOTUNIQ = 76,
        EBADFD = 77,
        EREMCHG = 78,
        ELIBACC = 79,
        ELIBBAD = 80,
        ELIBSCN = 81,
        ELIBMAX = 82,
        ELIBEXEC = 83,
        EILSEQ = 84,
        ERESTART = 85,
        ESTRPIPE = 86,
        EUSERS = 87,
        ENOTSOCK = 88,
        EDESTADDRREQ = 89,
        EMSGSIZE = 90,
        EPROTOTYPE = 91,
        ENOPROTOOPT = 92,
        EPROTONOSUPPORT = 93,
        ESOCKTNOSUPPORT = 94,
        EOPNOTSUPP = 95,
        ENOTSUP = EOPNOTSUPP,
        EPFNOSUPPORT = 96,
        EAFNOSUPPORT = 97,
        EADDRINUSE = 98,
        EADDRNOTAVAIL = 99,
        ENETDOWN = 100,
        ENETUNREACH = 101,
        ENETRESET = 102,
        ECONNABORTED = 103,
        ECONNRESET = 104,
        ENOBUFS = 105,
        EISCONN = 106,
        ENOTCONN = 107,
        ESHUTDOWN = 108,
        ETOOMANYREFS = 109,
        ETIMEDOUT = 110,
        ECONNREFUSED = 111,
        EHOSTDOWN = 112,
        EHOSTUNREACH = 113,
        EALREADY = 114,
        EINPROGRESS = 115,
        ESTALE = 116,
        EUCLEAN = 117,
        ENOTNAM = 118,
        ENAVAIL = 119,
        EISNAM = 120,
        EREMOTEIO = 121,
        EDQUOT = 122,
        ENOMEDIUM = 123,
        EMEDIUMTYPE = 124,
        ECANCELED = 125,
        ENOKEY = 126,
        EKEYEXPIRED = 127,
        EKEYREVOKED = 128,
        EKEYREJECTED = 129,
        EOWNERDEAD = 130,
        ENOTRECOVERABLE = 131,
        ERFKILL = 132,
        EHWPOISON = 133
    }

    public enum MEMFLAGS
    {
        MAP_SHARED = 0x00000001,
        MAP_PRIVATE = 0x00000002,
        MAP_SHARED_VALIDATE = 0x00000003,
        MAP_TYPE = 0x0000000F,
        MAP_FIXED = 0x00000010,
        MAP_ANON = 0x00000020,
        MAP_ANONYMOUS = MAP_ANON,
        MAP_GROWSDOWN = 0x00000100,
        MAP_DENYWRITE = 0x00000800,
        MAP_EXECUTABLE = 0x00001000,
        MAP_LOCKED = 0x00002000,
        MAP_NORESERVE = 0x00004000,
        MAP_POPULATE = 0x00008000,
        MAP_NONBLOCK = 0x00010000,
        MAP_STACK = 0x00020000,
        MAP_HUGETLB = 0x00040000,
        MAP_SYNC = 0x00080000,
        MAP_FIXED_NOREPLACE = 0x00100000,
        MAP_NOREPLACE = MAP_FIXED_NOREPLACE
    }

    public class SharedBuffer
    {
        private byte[] _buffer;

        public int Length => _buffer.Length;

        public SharedBuffer()
        {
            _buffer = Array.Empty<byte>();
        }

        public Span<byte> GetSpan(ulong size)
        {
            if (size > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(size));

            EnsureCapacity((int)size);
            return _buffer.AsSpan(0, (int)size);
        }

        public ReadOnlySpan<byte> GetReadOnlySpan(ulong size)
        {
            if (size > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(size));

            EnsureCapacity((int)size);
            return _buffer.AsSpan(0, (int)size);
        }

        public byte[] GetBuffer(ulong size)
        {
            if (size > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(size));

            EnsureCapacity((int)size);
            return _buffer;
        }

        public void Clear(ulong size)
        {
            if (size > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(size));

            int Count = (int)Math.Min(size, (ulong)_buffer.Length);
            _buffer.AsSpan(0, Count).Clear();
        }

        private void EnsureCapacity(int size)
        {
            if (size <= _buffer.Length)
                return;

            int NewSize = _buffer.Length == 0 ? 0x1000 : _buffer.Length;

            while (NewSize < size)
            {
                if (NewSize > int.MaxValue / 2)
                {
                    NewSize = size;
                    break;
                }

                NewSize *= 2;
            }

            Array.Resize(ref _buffer, NewSize);
        }
    }

    public interface IFileDescriptorObject
    {
        int RefCount { get; set; }
    }

    public class FileObject : IFileDescriptorObject
    {
        private string _hostPath = string.Empty;

        public int RefCount { get; set; }
        public ulong Offset { get; set; }
        public int StatusFlags { get; set; }
        public string Path { get; set; } = "";
        public LinuxFileStream FileStream { get; set; }

        public string HostPath
        {
            get => FileStream?.EffectiveReadHostPath ?? _hostPath;
            set => _hostPath = value ?? string.Empty;
        }

        public bool IsSpecialPath { get; set; }
        public bool IsDirectory { get; set; }
        public bool IsReadOnlyMount { get; set; }
    }

    internal enum LinuxDirectoryEntryType : byte
    {
        Unknown = 0,
        Fifo = 1,
        CharacterDevice = 2,
        Directory = 4,
        BlockDevice = 6,
        RegularFile = 8,
        SymbolicLink = 10,
        Socket = 12
    }

    internal sealed class LinuxDirectoryEntry
    {
        public string Name { get; set; } = string.Empty;
        public ulong Inode { get; set; }
        public LinuxDirectoryEntryType Type { get; set; }
    }

    public sealed class FileDescriptorEntry
    {
        public IFileDescriptorObject Object { get; set; }
        public bool CloseOnExec { get; set; }

        public FileDescriptorEntry(IFileDescriptorObject obj, bool closeOnExec = false)
        {
            Object = obj;
            CloseOnExec = closeOnExec;
        }
    }

    public class FileDescriptorTable
    {
        private const int O_RDONLY = 0x0;
        private const int O_WRONLY = 0x1;

        private readonly Dictionary<ulong, FileDescriptorEntry> DescriptorToEntry = new();

        public FileDescriptorTable()
        {
            DescriptorToEntry[0] = new FileDescriptorEntry(new FileObject { RefCount = 1, Path = "/dev/stdin", StatusFlags = O_RDONLY, IsSpecialPath = true });
            DescriptorToEntry[1] = new FileDescriptorEntry(new FileObject { RefCount = 1, Path = "/dev/stdout", StatusFlags = O_WRONLY, IsSpecialPath = true });
            DescriptorToEntry[2] = new FileDescriptorEntry(new FileObject { RefCount = 1, Path = "/dev/stderr", StatusFlags = O_WRONLY, IsSpecialPath = true });
        }

        public bool TryAddHandle(IFileDescriptorObject Object, bool CloseOnExec, ulong Limit, out ulong Descriptor)
        {
            for (ulong Current = 0; Current < Limit; Current++)
            {
                if (DescriptorToEntry.ContainsKey(Current))
                    continue;

                Object.RefCount++;
                DescriptorToEntry[Current] = new FileDescriptorEntry(Object, CloseOnExec);
                Descriptor = Current;
                return true;
            }

            Descriptor = 0;
            return false;
        }

        public ulong AddHandle(IFileDescriptorObject obj, bool CloseOnExec = false, ulong MinimumDescriptor = 300)
        {
            ulong Descriptor = MinimumDescriptor;
            while (DescriptorToEntry.ContainsKey(Descriptor))
                Descriptor++;

            obj.RefCount++;
            DescriptorToEntry[Descriptor] = new FileDescriptorEntry(obj, CloseOnExec);
            return Descriptor;
        }

        public FileDescriptorEntry? GetEntry(ulong Descriptor)
        {
            if (DescriptorToEntry.TryGetValue(Descriptor, out FileDescriptorEntry? entry))
                return entry;

            return null;
        }

        /// <summary>
        /// Enumerates the currently allocated file descriptor numbers.
        /// </summary>
        public IEnumerable<ulong> EnumerateDescriptors()
        {
            return DescriptorToEntry.Keys.OrderBy(Descriptor => Descriptor).ToArray();
        }

        public T? GetObjectByHandle<T>(ulong Descriptor) where T : class, IFileDescriptorObject
        {
            if (DescriptorToEntry.TryGetValue(Descriptor, out FileDescriptorEntry? entry) && entry.Object is T typedObj)
                return typedObj;

            return null;
        }

        public bool CloseHandle(ulong Descriptor)
        {
            if (!DescriptorToEntry.TryGetValue(Descriptor, out FileDescriptorEntry? entry))
                return false;

            DescriptorToEntry.Remove(Descriptor);

            if (entry.Object.RefCount > 0)
                entry.Object.RefCount--;

            if (entry.Object.RefCount == 0 && entry.Object is IDisposable DisposableObject)
                DisposableObject.Dispose();

            return true;
        }

        public bool TryDuplicateHandle(ulong Descriptor, ulong MinimumDescriptor, bool CloseOnExec, ulong Limit, out ulong NewDescriptor)
        {
            NewDescriptor = 0;
            if (!DescriptorToEntry.TryGetValue(Descriptor, out FileDescriptorEntry? entry))
                return false;

            if (MinimumDescriptor >= Limit)
                return false;

            for (ulong Current = MinimumDescriptor; Current < Limit; Current++)
            {
                if (DescriptorToEntry.ContainsKey(Current))
                    continue;

                entry.Object.RefCount++;
                DescriptorToEntry[Current] = new FileDescriptorEntry(entry.Object, CloseOnExec);
                NewDescriptor = Current;
                return true;
            }

            return false;
        }

        public ulong DuplicateHandle(ulong Descriptor)
        {
            if (!DescriptorToEntry.TryGetValue(Descriptor, out FileDescriptorEntry? entry))
                return ulong.MaxValue;

            return AddHandle(entry.Object, entry.CloseOnExec);
        }

        public bool ContainsHandle(ulong Descriptor)
        {
            return DescriptorToEntry.ContainsKey(Descriptor);
        }
    }


    internal sealed class EventfdObject : IFileDescriptorObject
    {
        public const ulong MaxCounterValue = ulong.MaxValue - 1UL;

        public int RefCount { get; set; }
        public ulong Counter { get; set; }
        public bool Semaphore { get; }
        public bool NonBlocking { get; set; }
        public int StatusFlags { get; set; }

        public EventfdObject(ulong InitialValue, bool Semaphore, bool NonBlocking, int StatusFlags)
        {
            Counter = InitialValue;
            this.Semaphore = Semaphore;
            this.NonBlocking = NonBlocking;
            this.StatusFlags = StatusFlags;
        }
    }

    internal sealed class TimerfdObject : IFileDescriptorObject
    {
        public int RefCount { get; set; }
        public int ClockId { get; }
        public bool NonBlocking { get; set; }
        public int StatusFlags { get; set; }
        public bool Armed { get; private set; }
        public bool Absolute { get; private set; }
        public long IntervalNanoseconds { get; private set; }
        public long NextExpirationNanoseconds { get; private set; }
        public ulong PendingExpirations { get; private set; }

        public TimerfdObject(int ClockId, bool NonBlocking, int StatusFlags)
        {
            this.ClockId = ClockId;
            this.NonBlocking = NonBlocking;
            this.StatusFlags = StatusFlags;
        }

        public void Disarm()
        {
            Armed = false;
            Absolute = false;
            IntervalNanoseconds = 0;
            NextExpirationNanoseconds = 0;
            PendingExpirations = 0;
        }

        public void Arm(long NextExpirationNanoseconds, long IntervalNanoseconds, bool Absolute)
        {
            Armed = true;
            this.Absolute = Absolute;
            this.IntervalNanoseconds = IntervalNanoseconds;
            this.NextExpirationNanoseconds = NextExpirationNanoseconds < 0 ? 0 : NextExpirationNanoseconds;
            PendingExpirations = 0;
        }

        public void Update(long NowNanoseconds)
        {
            if (!Armed || NowNanoseconds < NextExpirationNanoseconds)
                return;

            if (IntervalNanoseconds <= 0)
            {
                PendingExpirations = SaturatingAdd(PendingExpirations, 1);
                Armed = false;
                NextExpirationNanoseconds = 0;
                return;
            }

            long Delta = NowNanoseconds - NextExpirationNanoseconds;
            ulong Expirations = (ulong)(Delta / IntervalNanoseconds) + 1UL;
            PendingExpirations = SaturatingAdd(PendingExpirations, Expirations);

            long Advance;
            if (Expirations > (ulong)(long.MaxValue / IntervalNanoseconds))
                Advance = long.MaxValue - NextExpirationNanoseconds;
            else
                Advance = checked((long)Expirations * IntervalNanoseconds);

            if (NextExpirationNanoseconds > long.MaxValue - Advance)
                NextExpirationNanoseconds = long.MaxValue;
            else
                NextExpirationNanoseconds += Advance;
        }

        public ulong ConsumeExpirations(long NowNanoseconds)
        {
            Update(NowNanoseconds);
            ulong Result = PendingExpirations;
            PendingExpirations = 0;
            return Result;
        }

        public long GetRemainingNanoseconds(long NowNanoseconds)
        {
            Update(NowNanoseconds);
            if (!Armed)
                return 0;

            return NextExpirationNanoseconds <= NowNanoseconds ? 0 : NextExpirationNanoseconds - NowNanoseconds;
        }

        private static ulong SaturatingAdd(ulong Left, ulong Right)
        {
            ulong Result = Left + Right;
            return Result < Left ? ulong.MaxValue : Result;
        }
    }

    internal sealed class EpollInterest
    {
        public uint Events { get; set; }
        public ulong Data { get; set; }
        public uint LastReadyEvents { get; set; }
        public bool Disabled { get; set; }
    }

    internal sealed class EpollObject : IFileDescriptorObject
    {
        public int RefCount { get; set; }
        public Dictionary<ulong, EpollInterest> Interests { get; } = new Dictionary<ulong, EpollInterest>();
    }

    internal static class LinuxEventHelpers
    {
        public const int O_NONBLOCK = 0x800;
        public const int O_CLOEXEC = 0x80000;

        public const uint EPOLLIN = 0x00000001;
        public const uint EPOLLPRI = 0x00000002;
        public const uint EPOLLOUT = 0x00000004;
        public const uint EPOLLERR = 0x00000008;
        public const uint EPOLLHUP = 0x00000010;
        public const uint EPOLLNVAL = 0x00000020;
        public const uint EPOLLRDNORM = 0x00000040;
        public const uint EPOLLRDBAND = 0x00000080;
        public const uint EPOLLWRNORM = 0x00000100;
        public const uint EPOLLWRBAND = 0x00000200;
        public const uint EPOLLRDHUP = 0x00002000;
        public const uint EPOLLEXCLUSIVE = 1U << 28;
        public const uint EPOLLWAKEUP = 1U << 29;
        public const uint EPOLLONESHOT = 1U << 30;
        public const uint EPOLLET = 1U << 31;

        public const uint ReadEvents = EPOLLIN | EPOLLRDNORM;
        public const uint PriorityReadEvents = EPOLLPRI | EPOLLRDBAND;
        public const uint WriteEvents = EPOLLOUT | EPOLLWRNORM;
        public const uint PriorityWriteEvents = EPOLLWRBAND;

        private const int CLOCK_REALTIME = 0;
        private const int CLOCK_MONOTONIC = 1;
        private const int CLOCK_MONOTONIC_RAW = 4;
        private const int CLOCK_REALTIME_COARSE = 5;
        private const int CLOCK_MONOTONIC_COARSE = 6;
        private const int CLOCK_BOOTTIME = 7;
        private const int CLOCK_TAI = 11;
        private const long NanosecondsPerSecond = 1000000000L;

        public static bool IsValidEventFlags(int Flags)
        {
            return (Flags & ~(O_CLOEXEC | O_NONBLOCK)) == 0;
        }

        public static bool IsValidClockId(int ClockId)
        {
            return ClockId == CLOCK_REALTIME || ClockId == CLOCK_MONOTONIC || ClockId == CLOCK_BOOTTIME ||
                   ClockId == CLOCK_MONOTONIC_RAW || ClockId == CLOCK_REALTIME_COARSE || ClockId == CLOCK_MONOTONIC_COARSE ||
                   ClockId == CLOCK_TAI;
        }

        public static long GetClockNanoseconds(LinuxSyscallsHelper Helper, int ClockId)
        {
            TimeSpan Value;
            switch (ClockId)
            {
                case CLOCK_REALTIME:
                case CLOCK_REALTIME_COARSE:
                case CLOCK_TAI:
                    DateTimeOffset Realtime = Helper.GetRealtimeNowUtc();
                    long UnixSeconds = Realtime.ToUnixTimeSeconds();
                    long UnixNanos = (Realtime.Ticks % TimeSpan.TicksPerSecond) * 100L;
                    return SaturatingAddNanoseconds(UnixSeconds, UnixNanos);

                case CLOCK_MONOTONIC:
                case CLOCK_MONOTONIC_RAW:
                case CLOCK_MONOTONIC_COARSE:
                case CLOCK_BOOTTIME:
                default:
                    Value = Helper.GetSystemUptime();
                    return TimeSpanToNanoseconds(Value);
            }
        }

        public static long TimeSpanToNanoseconds(TimeSpan Value)
        {
            if (Value <= TimeSpan.Zero)
                return 0;

            if (Value.Ticks > long.MaxValue / 100L)
                return long.MaxValue;

            return Value.Ticks * 100L;
        }

        public static long TimespecToNanoseconds(long Seconds, long Nanoseconds)
        {
            if (Seconds <= 0 && Nanoseconds <= 0)
                return 0;

            if (Seconds > long.MaxValue / NanosecondsPerSecond)
                return long.MaxValue;

            long Result = Seconds * NanosecondsPerSecond;
            if (Nanoseconds > long.MaxValue - Result)
                return long.MaxValue;

            return Result + Nanoseconds;
        }

        public static void NanosecondsToTimespec(long Nanoseconds, out long Seconds, out long RemainderNanoseconds)
        {
            if (Nanoseconds <= 0)
            {
                Seconds = 0;
                RemainderNanoseconds = 0;
                return;
            }

            Seconds = Nanoseconds / NanosecondsPerSecond;
            RemainderNanoseconds = Nanoseconds % NanosecondsPerSecond;
        }

        public static uint GetReadyEvents(BinaryEmulator Instance, LinuxSyscallsHelper Helper, IFileDescriptorObject Object, uint RequestedEvents)
        {
            Helper.SyncEmulatedClock(Instance);
            switch (Object)
            {
                case FileObject:
                    return GetRegularFileEvents(RequestedEvents);
                case SocketObject SocketDescriptor:
                    return GetSocketEvents(SocketDescriptor, RequestedEvents);
                case EventfdObject EventfdDescriptor:
                    return GetEventfdEvents(EventfdDescriptor, RequestedEvents);
                case TimerfdObject TimerfdDescriptor:
                    TimerfdDescriptor.Update(GetClockNanoseconds(Helper, TimerfdDescriptor.ClockId));
                    return GetTimerfdEvents(TimerfdDescriptor, RequestedEvents);
                case EpollObject EpollDescriptor:
                    return GetEpollEvents(Instance, Helper, EpollDescriptor, RequestedEvents);
                default:
                    return EPOLLNVAL;
            }
        }

        public static void ReadEventfd(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, EventfdObject EventfdDescriptor, ulong BufferAddress, ulong Count)
        {
            if (Count < sizeof(ulong))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (!Instance.IsRegionMapped(BufferAddress, sizeof(ulong)))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            if (EventfdDescriptor.Counter == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EAGAIN);
                return;
            }

            ulong Value;
            if (EventfdDescriptor.Semaphore)
            {
                Value = 1;
                EventfdDescriptor.Counter--;
            }
            else
            {
                Value = EventfdDescriptor.Counter;
                EventfdDescriptor.Counter = 0;
            }

            Span<byte> Buffer = stackalloc byte[sizeof(ulong)];
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer, Value);
            if (!Instance.WriteMemory(BufferAddress, Buffer))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Helper.SetReturnValue(Instance, Context, sizeof(ulong));
        }

        public static void WriteEventfd(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, EventfdObject EventfdDescriptor, ulong BufferAddress, ulong Count)
        {
            if (Count < sizeof(ulong))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (!Instance.IsRegionMapped(BufferAddress, sizeof(ulong)))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Span<byte> Buffer = stackalloc byte[sizeof(ulong)];
            if (!Instance.ReadMemory(BufferAddress, Buffer))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            ulong Value = BinaryPrimitives.ReadUInt64LittleEndian(Buffer);
            if (Value == ulong.MaxValue)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (Value > EventfdObject.MaxCounterValue - EventfdDescriptor.Counter)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EAGAIN);
                return;
            }

            EventfdDescriptor.Counter += Value;
            Helper.SetReturnValue(Instance, Context, sizeof(ulong));
        }

        public static void ReadTimerfd(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, TimerfdObject TimerfdDescriptor, ulong BufferAddress, ulong Count)
        {
            if (Count < sizeof(ulong))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (!Instance.IsRegionMapped(BufferAddress, sizeof(ulong)))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            ulong Expirations = TimerfdDescriptor.ConsumeExpirations(GetClockNanoseconds(Helper, TimerfdDescriptor.ClockId));
            if (Expirations == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EAGAIN);
                return;
            }

            Span<byte> Buffer = stackalloc byte[sizeof(ulong)];
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer, Expirations);
            if (!Instance.WriteMemory(BufferAddress, Buffer))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Helper.SetReturnValue(Instance, Context, sizeof(ulong));
        }

        public static int WriteReadyEvents(BinaryEmulator Instance, LinuxSyscallsHelper Helper, EpollObject Epoll, ulong EventsAddress, int MaxEvents)
        {
            int ReadyCount = 0;
            Span<byte> EventBuffer = stackalloc byte[12];

            foreach (KeyValuePair<ulong, EpollInterest> Pair in Epoll.Interests)
            {
                if (ReadyCount >= MaxEvents)
                    break;

                EpollInterest Interest = Pair.Value;
                if (Interest.Disabled)
                    continue;

                FileDescriptorEntry? Entry = Helper.DescriptorTable.GetEntry(Pair.Key);
                if (Entry == null)
                    continue;

                uint CurrentReadyEvents = GetReadyEvents(Instance, Helper, Entry.Object, Interest.Events);
                uint Revents = GetReportableEvents(Interest, CurrentReadyEvents, true);
                if (Revents == 0)
                    continue;

                EventBuffer.Clear();
                BinaryPrimitives.WriteUInt32LittleEndian(EventBuffer.Slice(0, 4), Revents);
                BinaryPrimitives.WriteUInt64LittleEndian(EventBuffer.Slice(4, 8), Interest.Data);
                if (!Instance.WriteMemory(EventsAddress + (ulong)(ReadyCount * 12), EventBuffer))
                    return -1;

                ReadyCount++;
                if ((Interest.Events & EPOLLONESHOT) != 0)
                    Interest.Disabled = true;
            }

            return ReadyCount;
        }

        public static bool HasReadyEpollEvents(BinaryEmulator Instance, LinuxSyscallsHelper Helper, EpollObject Epoll)
        {
            foreach (KeyValuePair<ulong, EpollInterest> Pair in Epoll.Interests)
            {
                EpollInterest Interest = Pair.Value;
                if (Interest.Disabled)
                    continue;

                FileDescriptorEntry? Entry = Helper.DescriptorTable.GetEntry(Pair.Key);
                if (Entry == null)
                    continue;

                uint CurrentReadyEvents = GetReadyEvents(Instance, Helper, Entry.Object, Interest.Events);
                if (GetReportableEvents(Interest, CurrentReadyEvents, false) != 0)
                    return true;
            }

            return false;
        }

        public static long GetNextEpollWakeDelayMilliseconds(LinuxSyscallsHelper Helper, EpollObject Epoll)
        {
            long BestMilliseconds = long.MaxValue;

            foreach (KeyValuePair<ulong, EpollInterest> Pair in Epoll.Interests)
            {
                EpollInterest Interest = Pair.Value;
                if (Interest.Disabled || (Interest.Events & ReadEvents) == 0)
                    continue;

                FileDescriptorEntry? Entry = Helper.DescriptorTable.GetEntry(Pair.Key);
                if (Entry?.Object is not TimerfdObject Timerfd)
                    continue;

                long NowNanoseconds = GetClockNanoseconds(Helper, Timerfd.ClockId);
                long RemainingNanoseconds = Timerfd.GetRemainingNanoseconds(NowNanoseconds);
                if (RemainingNanoseconds <= 0)
                    return 0;

                long RemainingMilliseconds = (RemainingNanoseconds + 999999L) / 1000000L;
                if (RemainingMilliseconds < 1)
                    RemainingMilliseconds = 1;

                if (RemainingMilliseconds < BestMilliseconds)
                    BestMilliseconds = RemainingMilliseconds;
            }

            return BestMilliseconds == long.MaxValue ? -1 : BestMilliseconds;
        }

        private static uint GetReportableEvents(EpollInterest Interest, uint CurrentReadyEvents, bool Commit)
        {
            if ((Interest.Events & EPOLLET) == 0)
                return CurrentReadyEvents;

            uint ReportableEvents = CurrentReadyEvents & ~Interest.LastReadyEvents;
            if (Commit)
                Interest.LastReadyEvents = CurrentReadyEvents;

            return ReportableEvents;
        }

        private static uint GetRegularFileEvents(uint RequestedEvents)
        {
            uint Result = 0;
            if ((RequestedEvents & ReadEvents) != 0)
                Result |= RequestedEvents & ReadEvents;

            if ((RequestedEvents & WriteEvents) != 0)
                Result |= RequestedEvents & WriteEvents;

            return Result;
        }

        private static uint GetSocketEvents(SocketObject SocketDescriptor, uint RequestedEvents)
        {
            uint Result = 0;

            if (SocketDescriptor.PendingConnect != null)
            {
                if (!SocketDescriptor.PendingConnectCompleted)
                    return 0;

                return SocketDescriptor.PendingConnect.SocketError == SocketError.Success
                    ? RequestedEvents & WriteEvents
                    : EPOLLERR;
            }

            if ((RequestedEvents & ReadEvents) != 0 && IsSocketReady(SocketDescriptor, SelectMode.SelectRead))
                Result |= RequestedEvents & ReadEvents;

            if ((RequestedEvents & PriorityReadEvents) != 0 && IsSocketReady(SocketDescriptor, SelectMode.SelectError))
                Result |= RequestedEvents & PriorityReadEvents;

            if ((RequestedEvents & WriteEvents) != 0 && IsSocketReady(SocketDescriptor, SelectMode.SelectWrite))
                Result |= RequestedEvents & WriteEvents;

            if ((RequestedEvents & PriorityWriteEvents) != 0 && IsSocketReady(SocketDescriptor, SelectMode.SelectWrite))
                Result |= RequestedEvents & PriorityWriteEvents;

            if (IsSocketReady(SocketDescriptor, SelectMode.SelectError))
                Result |= EPOLLERR;

            if (IsSocketReady(SocketDescriptor, SelectMode.SelectRead) && IsPeerShutdown(SocketDescriptor))
                Result |= EPOLLHUP | EPOLLRDHUP;

            return Result;
        }

        private static uint GetEventfdEvents(EventfdObject EventfdDescriptor, uint RequestedEvents)
        {
            uint Result = 0;
            if (EventfdDescriptor.Counter > 0 && (RequestedEvents & ReadEvents) != 0)
                Result |= RequestedEvents & ReadEvents;

            if (EventfdDescriptor.Counter < EventfdObject.MaxCounterValue && (RequestedEvents & WriteEvents) != 0)
                Result |= RequestedEvents & WriteEvents;

            return Result;
        }

        private static uint GetTimerfdEvents(TimerfdObject TimerfdDescriptor, uint RequestedEvents)
        {
            if (TimerfdDescriptor.PendingExpirations == 0 || (RequestedEvents & ReadEvents) == 0)
                return 0;

            return RequestedEvents & ReadEvents;
        }

        private static uint GetEpollEvents(BinaryEmulator Instance, LinuxSyscallsHelper Helper, EpollObject EpollDescriptor, uint RequestedEvents)
        {
            if ((RequestedEvents & ReadEvents) == 0)
                return 0;

            foreach (KeyValuePair<ulong, EpollInterest> Item in EpollDescriptor.Interests)
            {
                if (Item.Value.Disabled)
                    continue;

                FileDescriptorEntry? Entry = Helper.DescriptorTable.GetEntry(Item.Key);
                if (Entry == null)
                    continue;

                uint Ready = GetReadyEvents(Instance, Helper, Entry.Object, Item.Value.Events);
                if (Ready != 0)
                    return RequestedEvents & ReadEvents;
            }

            return 0;
        }

        private static bool IsPeerShutdown(SocketObject SocketDescriptor)
        {
            try
            {
                return SocketDescriptor.Handle.Available == 0;
            }
            catch
            {
                return false;
            }
        }

        private static bool IsSocketReady(SocketObject SocketDescriptor, SelectMode Mode)
        {
            try
            {
                return SocketDescriptor.Handle.Poll(0, Mode);
            }
            catch
            {
                return true;
            }
        }

        private static long SaturatingAddNanoseconds(long Seconds, long Nanoseconds)
        {
            if (Seconds > long.MaxValue / NanosecondsPerSecond)
                return long.MaxValue;

            long Result = Seconds * NanosecondsPerSecond;
            if (Nanoseconds > long.MaxValue - Result)
                return long.MaxValue;

            return Result + Nanoseconds;
        }
    }

    internal sealed class SocketObject : IFileDescriptorObject, IDisposable
    {
        public int RefCount { get; set; }
        public HostSocket Handle { get; }
        public int Domain { get; }
        public int Type { get; }
        public int Protocol { get; }
        public int StatusFlags { get; set; }
        public bool NonBlocking { get; set; }
        public bool ReusePortEnabled { get; set; }
        public bool IsListening { get; set; }
        public SocketAsyncEventArgs? PendingConnect { get; set; }
        public bool PendingConnectCompleted { get; set; }

        public SocketObject(HostSocket Handle, int Domain, int Type, int Protocol, int StatusFlags, bool NonBlocking)
        {
            this.Handle = Handle;
            this.Domain = Domain;
            this.Type = Type;
            this.Protocol = Protocol;
            this.StatusFlags = StatusFlags;
            this.NonBlocking = NonBlocking;
        }

        public void Dispose()
        {
            try
            {
                PendingConnect?.Dispose();
                Handle.Dispose();
            }
            catch
            {
            }
        }
    }

    internal static class SocketHelpers
    {
        public const int RLIMIT_NOFILE = 7;

        public const int AF_INET = 2;
        public const int AF_INET6 = 10;

        public const int SOCK_STREAM = 1;
        public const int SOCK_DGRAM = 2;
        public const int SOCK_RAW = 3;
        public const int SOCK_SEQPACKET = 5;
        public const int SOCK_TYPE_MASK = 0xF;
        public const int SOCK_NONBLOCK = 0x800;
        public const int SOCK_CLOEXEC = 0x80000;

        public const int O_RDWR = 0x2;
        public const int O_NONBLOCK = 0x800;
        public const int O_ASYNC = 0x2000;

        public const int MSG_OOB = 0x1;
        public const int MSG_PEEK = 0x2;
        public const int MSG_DONTROUTE = 0x4;
        public const int MSG_TRUNC = 0x20;
        public const int MSG_DONTWAIT = 0x40;
        public const int MSG_WAITALL = 0x100;
        public const int MSG_NOSIGNAL = 0x4000;

        public const int SOL_SOCKET = 1;
        public const int IPPROTO_IP = 0;
        public const int IPPROTO_TCP = 6;
        public const int IPPROTO_UDP = 17;

        public const int SO_REUSEADDR = 2;
        public const int SO_TYPE = 3;
        public const int SO_ERROR = 4;
        public const int SO_DONTROUTE = 5;
        public const int SO_BROADCAST = 6;
        public const int SO_SNDBUF = 7;
        public const int SO_RCVBUF = 8;
        public const int SO_KEEPALIVE = 9;
        public const int SO_OOBINLINE = 10;
        public const int SO_LINGER = 13;
        public const int SO_REUSEPORT = 15;
        public const int SO_RCVLOWAT = 18;
        public const int SO_SNDLOWAT = 19;
        public const int SO_RCVTIMEO_OLD = 20;
        public const int SO_SNDTIMEO_OLD = 21;
        public const int SO_ACCEPTCONN = 30;
        public const int SO_PROTOCOL = 38;
        public const int SO_DOMAIN = 39;
        public const int SO_RCVTIMEO_NEW = 66;
        public const int SO_SNDTIMEO_NEW = 67;

        public const int TCP_NODELAY = 1;

        public static ulong GetDescriptorLimit(LinuxSyscallsHelper Helper)
        {
            if (Helper.ResourceLimits.TryGetValue(RLIMIT_NOFILE, out LinuxResourceLimit Limit) && Limit.Current != 0)
                return Limit.Current;

            return 1024;
        }

        public static bool TryCreateSocket(int Domain, int Type, int Protocol, out SocketObject Socket, out bool CloseOnExec, out LinuxErrno Error)
        {
            Socket = null;
            CloseOnExec = false;
            Error = LinuxErrno.ESUCCESS;

            int UnknownFlags = Type & ~(SOCK_TYPE_MASK | SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (UnknownFlags != 0)
            {
                Error = LinuxErrno.EINVAL;
                return false;
            }

            int BaseType = Type & SOCK_TYPE_MASK;
            bool NonBlocking = (Type & SOCK_NONBLOCK) != 0;
            CloseOnExec = (Type & SOCK_CLOEXEC) != 0;

            AddressFamily Family;
            switch (Domain)
            {
                case AF_INET:
                    Family = AddressFamily.InterNetwork;
                    break;
                case AF_INET6:
                    Family = AddressFamily.InterNetworkV6;
                    break;
                default:
                    Error = LinuxErrno.EAFNOSUPPORT;
                    return false;
            }

            SocketType HostType;
            ProtocolType HostProtocol;
            switch (BaseType)
            {
                case SOCK_STREAM:
                    if (Protocol != 0 && Protocol != IPPROTO_TCP)
                    {
                        Error = LinuxErrno.EPROTONOSUPPORT;
                        return false;
                    }

                    HostType = SocketType.Stream;
                    HostProtocol = ProtocolType.Tcp;
                    break;
                case SOCK_DGRAM:
                    if (Protocol != 0 && Protocol != IPPROTO_UDP)
                    {
                        Error = LinuxErrno.EPROTONOSUPPORT;
                        return false;
                    }

                    HostType = SocketType.Dgram;
                    HostProtocol = ProtocolType.Udp;
                    break;
                case SOCK_RAW:
                case SOCK_SEQPACKET:
                default:
                    Error = LinuxErrno.ESOCKTNOSUPPORT;
                    return false;
            }

            try
            {
                HostSocket HostHandle = new HostSocket(Family, HostType, HostProtocol);
                HostHandle.Blocking = !NonBlocking;
                int StatusFlags = O_RDWR | (NonBlocking ? O_NONBLOCK : 0);
                Socket = new SocketObject(HostHandle, Domain, BaseType, Protocol, StatusFlags, NonBlocking);
                return true;
            }
            catch (SocketException Ex)
            {
                Error = TranslateSocketError(Ex.SocketErrorCode);
                return false;
            }
            catch (ArgumentException)
            {
                Error = LinuxErrno.EINVAL;
                return false;
            }
            catch (ObjectDisposedException)
            {
                Error = LinuxErrno.EBADF;
                return false;
            }
        }

        public static bool TryGetSocket(LinuxSyscallsHelper Helper, ulong Descriptor, out SocketObject Socket, out LinuxErrno Error)
        {
            Socket = null;
            Error = LinuxErrno.ESUCCESS;

            FileDescriptorEntry? Entry = Helper.DescriptorTable.GetEntry(Descriptor);
            if (Entry == null)
            {
                Error = LinuxErrno.EBADF;
                return false;
            }

            if (Entry.Object is not SocketObject SocketObject)
            {
                Error = LinuxErrno.ENOTSOCK;
                return false;
            }

            Socket = SocketObject;
            return true;
        }

        public static bool TryCheckNetworkPolicy(BinaryEmulator Instance, EndPoint EndPointValue, out LinuxErrno Error)
        {
            Error = LinuxErrno.ESUCCESS;

            if (Instance.Settings.GetNetworkPolicy().IsEndpointAllowed(EndPointValue))
                return true;

            Error = LinuxErrno.ENETUNREACH;
            return false;
        }

        public static bool TryCheckNetworkPolicy(BinaryEmulator Instance, out LinuxErrno Error)
        {
            Error = LinuxErrno.ESUCCESS;

            if (Instance.Settings.GetNetworkPolicy().HasAnyAccess())
                return true;

            Error = LinuxErrno.ENETUNREACH;
            return false;
        }

        public static bool TryCheckSocketRemotePolicy(BinaryEmulator Instance, SocketObject Socket, bool RequireKnownRemote, out LinuxErrno Error)
        {
            Error = LinuxErrno.ESUCCESS;
            NetworkAccessPolicy Policy = Instance.Settings.GetNetworkPolicy();
            if (!Policy.HasAnyAccess())
            {
                Error = LinuxErrno.ENETUNREACH;
                return false;
            }

            EndPoint RemoteEndPoint = null;
            try
            {
                RemoteEndPoint = Socket.Handle.RemoteEndPoint;
            }
            catch (SocketException)
            {
            }
            catch (ObjectDisposedException)
            {
                Error = LinuxErrno.EBADF;
                return false;
            }

            if (RemoteEndPoint != null)
                return TryCheckNetworkPolicy(Instance, RemoteEndPoint, out Error);

            if (RequireKnownRemote && Policy.Mode != NetworkAccessMode.Full)
            {
                Error = LinuxErrno.ENETUNREACH;
                return false;
            }

            return true;
        }

        public static bool TryReadSocketAddress(BinaryEmulator Instance, ulong Address, ulong AddressLength, out EndPoint EndPointValue, out LinuxErrno Error)
        {
            EndPointValue = null;
            Error = LinuxErrno.ESUCCESS;

            if (Address == 0)
            {
                Error = LinuxErrno.EFAULT;
                return false;
            }

            if (AddressLength < 2 || AddressLength > int.MaxValue)
            {
                Error = LinuxErrno.EINVAL;
                return false;
            }

            if (!Instance.IsRegionMapped(Address, AddressLength))
            {
                Error = LinuxErrno.EFAULT;
                return false;
            }

            int HeaderLength = (int)Math.Min(AddressLength, 28UL);
            Span<byte> AddressBytes = stackalloc byte[28];
            if (!Instance.ReadMemory(Address, AddressBytes.Slice(0, HeaderLength)))
            {
                Error = LinuxErrno.EFAULT;
                return false;
            }

            ushort Family = BinaryPrimitives.ReadUInt16LittleEndian(AddressBytes.Slice(0, 2));
            switch (Family)
            {
                case AF_INET:
                    if (AddressLength < 16)
                    {
                        Error = LinuxErrno.EINVAL;
                        return false;
                    }

                    int Port = BinaryPrimitives.ReadUInt16BigEndian(AddressBytes.Slice(2, 2));
                    EndPointValue = new IPEndPoint(new IPAddress(AddressBytes.Slice(4, 4)), Port);
                    return true;
                case AF_INET6:
                    if (AddressLength < 28)
                    {
                        Error = LinuxErrno.EINVAL;
                        return false;
                    }

                    int IPv6Port = BinaryPrimitives.ReadUInt16BigEndian(AddressBytes.Slice(2, 2));
                    uint ScopeId = BinaryPrimitives.ReadUInt32LittleEndian(AddressBytes.Slice(24, 4));
                    EndPointValue = new IPEndPoint(new IPAddress(AddressBytes.Slice(8, 16), ScopeId), IPv6Port);
                    return true;
                default:
                    Error = LinuxErrno.EAFNOSUPPORT;
                    return false;
            }
        }

        public static bool TryWriteSocketAddress(BinaryEmulator Instance, ulong Address, ulong AddressLengthPointer, EndPoint EndPointValue, out LinuxErrno Error)
        {
            Error = LinuxErrno.ESUCCESS;

            if (Address == 0)
                return true;

            if (AddressLengthPointer == 0 || !Instance.IsRegionMapped(AddressLengthPointer, 4))
            {
                Error = LinuxErrno.EFAULT;
                return false;
            }

            Span<byte> LengthBytes = stackalloc byte[4];
            if (!Instance.ReadMemory(AddressLengthPointer, LengthBytes))
            {
                Error = LinuxErrno.EFAULT;
                return false;
            }

            uint RequestedLength = BinaryPrimitives.ReadUInt32LittleEndian(LengthBytes);
            Span<byte> AddressBytes = stackalloc byte[28];
            AddressBytes.Clear();
            int AddressBytesLength = BuildGuestSocketAddress(EndPointValue, AddressBytes);
            uint CopyLength = Math.Min(RequestedLength, (uint)AddressBytesLength);

            if (CopyLength != 0)
            {
                if (!Instance.IsRegionMapped(Address, CopyLength) || !Instance.WriteMemory(Address, AddressBytes.Slice(0, (int)CopyLength)))
                {
                    Error = LinuxErrno.EFAULT;
                    return false;
                }
            }

            BinaryPrimitives.WriteUInt32LittleEndian(LengthBytes, (uint)AddressBytesLength);
            if (!Instance.WriteMemory(AddressLengthPointer, LengthBytes))
            {
                Error = LinuxErrno.EFAULT;
                return false;
            }

            return true;
        }

        public static SocketFlags TranslateSendFlags(int Flags, out bool NonBlocking, out LinuxErrno Error)
        {
            NonBlocking = (Flags & MSG_DONTWAIT) != 0;
            Error = LinuxErrno.ESUCCESS;

            int UnsupportedFlags = Flags & ~(MSG_OOB | MSG_DONTROUTE | MSG_DONTWAIT | MSG_NOSIGNAL);
            if (UnsupportedFlags != 0)
            {
                Error = LinuxErrno.EOPNOTSUPP;
                return SocketFlags.None;
            }

            SocketFlags HostFlags = SocketFlags.None;
            if ((Flags & MSG_OOB) != 0)
                HostFlags |= SocketFlags.OutOfBand;

            if ((Flags & MSG_DONTROUTE) != 0)
                HostFlags |= SocketFlags.DontRoute;

            return HostFlags;
        }

        public static SocketFlags TranslateReceiveFlags(int Flags, out bool NonBlocking, out LinuxErrno Error)
        {
            NonBlocking = (Flags & MSG_DONTWAIT) != 0;
            Error = LinuxErrno.ESUCCESS;

            int UnsupportedFlags = Flags & ~(MSG_OOB | MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT | MSG_WAITALL);
            if (UnsupportedFlags != 0)
            {
                Error = LinuxErrno.EOPNOTSUPP;
                return SocketFlags.None;
            }

            SocketFlags HostFlags = SocketFlags.None;
            if ((Flags & MSG_OOB) != 0)
                HostFlags |= SocketFlags.OutOfBand;

            if ((Flags & MSG_PEEK) != 0)
                HostFlags |= SocketFlags.Peek;

            if ((Flags & MSG_TRUNC) != 0)
                HostFlags |= SocketFlags.Truncated;

            if ((Flags & MSG_WAITALL) != 0)
                HostFlags |= (SocketFlags)MSG_WAITALL;

            return HostFlags;
        }

        public static LinuxErrno TranslateSocketError(SocketError Error)
        {
            return Error switch
            {
                SocketError.AccessDenied => LinuxErrno.EACCES,
                SocketError.AddressAlreadyInUse => LinuxErrno.EADDRINUSE,
                SocketError.AddressNotAvailable => LinuxErrno.EADDRNOTAVAIL,
                SocketError.AlreadyInProgress => LinuxErrno.EALREADY,
                SocketError.ConnectionAborted => LinuxErrno.ECONNABORTED,
                SocketError.ConnectionRefused => LinuxErrno.ECONNREFUSED,
                SocketError.ConnectionReset => LinuxErrno.ECONNRESET,
                SocketError.DestinationAddressRequired => LinuxErrno.EDESTADDRREQ,
                SocketError.Fault => LinuxErrno.EFAULT,
                SocketError.HostDown => LinuxErrno.EHOSTDOWN,
                SocketError.HostNotFound => LinuxErrno.EHOSTUNREACH,
                SocketError.HostUnreachable => LinuxErrno.EHOSTUNREACH,
                SocketError.InProgress => LinuxErrno.EINPROGRESS,
                SocketError.Interrupted => LinuxErrno.EINTR,
                SocketError.InvalidArgument => LinuxErrno.EINVAL,
                SocketError.IsConnected => LinuxErrno.EISCONN,
                SocketError.MessageSize => LinuxErrno.EMSGSIZE,
                SocketError.NetworkDown => LinuxErrno.ENETDOWN,
                SocketError.NetworkReset => LinuxErrno.ENETRESET,
                SocketError.NetworkUnreachable => LinuxErrno.ENETUNREACH,
                SocketError.NoBufferSpaceAvailable => LinuxErrno.ENOBUFS,
                SocketError.NotConnected => LinuxErrno.ENOTCONN,
                SocketError.NotSocket => LinuxErrno.ENOTSOCK,
                SocketError.OperationAborted => LinuxErrno.ECANCELED,
                SocketError.OperationNotSupported => LinuxErrno.EOPNOTSUPP,
                SocketError.ProtocolFamilyNotSupported => LinuxErrno.EAFNOSUPPORT,
                SocketError.ProtocolNotSupported => LinuxErrno.EPROTONOSUPPORT,
                SocketError.ProtocolOption => LinuxErrno.ENOPROTOOPT,
                SocketError.ProtocolType => LinuxErrno.EPROTOTYPE,
                SocketError.Shutdown => LinuxErrno.ESHUTDOWN,
                SocketError.SocketError => LinuxErrno.EIO,
                SocketError.SocketNotSupported => LinuxErrno.ESOCKTNOSUPPORT,
                SocketError.AddressFamilyNotSupported => LinuxErrno.EAFNOSUPPORT,
                SocketError.Success => LinuxErrno.ESUCCESS,
                SocketError.TimedOut => LinuxErrno.ETIMEDOUT,
                SocketError.TooManyOpenSockets => LinuxErrno.EMFILE,
                SocketError.TryAgain => LinuxErrno.EAGAIN,
                SocketError.WouldBlock => LinuxErrno.EAGAIN,
                _ => LinuxErrno.EIO
            };
        }

        public static bool WouldBlock(SocketObject Socket, SelectMode Mode)
        {
            try
            {
                return !Socket.Handle.Poll(0, Mode);
            }
            catch
            {
                return false;
            }
        }

        private static int BuildGuestSocketAddress(EndPoint EndPointValue, Span<byte> AddressBytes)
        {
            if (EndPointValue is not IPEndPoint IPAddressEndPoint)
                return 0;

            if (IPAddressEndPoint.AddressFamily == AddressFamily.InterNetwork)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(AddressBytes.Slice(0, 2), AF_INET);
                BinaryPrimitives.WriteUInt16BigEndian(AddressBytes.Slice(2, 2), (ushort)IPAddressEndPoint.Port);
                if (!IPAddressEndPoint.Address.TryWriteBytes(AddressBytes.Slice(4, 4), out int BytesWritten) || BytesWritten != 4)
                    return 0;

                return 16;
            }

            if (IPAddressEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(AddressBytes.Slice(0, 2), AF_INET6);
                BinaryPrimitives.WriteUInt16BigEndian(AddressBytes.Slice(2, 2), (ushort)IPAddressEndPoint.Port);
                BinaryPrimitives.WriteUInt32LittleEndian(AddressBytes.Slice(4, 4), 0);
                if (!IPAddressEndPoint.Address.TryWriteBytes(AddressBytes.Slice(8, 16), out int BytesWritten) || BytesWritten != 16)
                    return 0;

                BinaryPrimitives.WriteUInt32LittleEndian(AddressBytes.Slice(24, 4), (uint)IPAddressEndPoint.Address.ScopeId);
                return 28;
            }

            return 0;
        }
    }

    public sealed class LinuxMountEntry
    {
        public string GuestPath { get; set; } = "";
        public string HostPath { get; set; } = "";
        public string FileSystemType { get; set; } = "";
        public bool IsDirectory { get; set; }
        public bool ReadOnly { get; set; }
    }

    public sealed class LinuxX86CpuIdentity
    {
        public uint MaxBasicLeaf { get; set; } = 0x00000019;
        public uint MaxExtendedLeaf { get; set; } = 0x80000008;
        public string VendorId { get; set; } = "GenuineIntel";
        public string BrandString { get; set; } = "Brovan Virtual CPU";
        public uint Leaf1Eax { get; set; } = 0x000106A5;
        public uint Leaf1Ebx { get; set; } = (8u << 8) | (1u << 16);
        public uint Leaf1Ecx { get; set; } =
            (1u << 0) |
            (1u << 9) |
            (1u << 13) |
            (1u << 19) |
            (1u << 20) |
            (1u << 23);
        public uint Leaf1Edx { get; set; } =
            (1u << 0) |
            (1u << 4) |
            (1u << 5) |
            (1u << 8) |
            (1u << 15) |
            (1u << 19) |
            (1u << 23) |
            (1u << 24) |
            (1u << 25) |
            (1u << 26);
        public uint Leaf7Subleaf0Eax { get; set; }
        public uint Leaf7Subleaf0Ebx { get; set; }
        public uint Leaf7Subleaf0Ecx { get; set; }
        public uint Leaf7Subleaf0Edx { get; set; }
        public uint Leaf80000001Ecx { get; set; } = 1u << 0;
        public uint Leaf80000001Edx { get; set; } = (1u << 11) | (1u << 20) | (1u << 27);
        public uint Leaf80000007Edx { get; set; } = 1u << 8;
        public uint Leaf80000008Eax { get; set; } = 0x00003030;

        public int GetDisplayStepping()
        {
            return (int)(Leaf1Eax & 0xFu);
        }

        public int GetDisplayFamily()
        {
            uint BaseFamily = (Leaf1Eax >> 8) & 0xFu;
            uint ExtendedFamily = (Leaf1Eax >> 20) & 0xFFu;
            if (BaseFamily == 0xFu)
                return (int)(BaseFamily + ExtendedFamily);

            return (int)BaseFamily;
        }

        public int GetDisplayModel()
        {
            uint BaseFamily = (Leaf1Eax >> 8) & 0xFu;
            uint BaseModel = (Leaf1Eax >> 4) & 0xFu;
            uint ExtendedModel = (Leaf1Eax >> 16) & 0xFu;
            if (BaseFamily == 0x6 || BaseFamily == 0xFu)
                return (int)(BaseModel | (ExtendedModel << 4));

            return (int)BaseModel;
        }

        public int GetPhysicalAddressBits()
        {
            return (int)(Leaf80000008Eax & 0xFFu);
        }

        public int GetVirtualAddressBits()
        {
            return (int)((Leaf80000008Eax >> 8) & 0xFFu);
        }

        public string GetModelName()
        {
            return string.IsNullOrWhiteSpace(BrandString) ? "Brovan Virtual CPU" : BrandString.Trim();
        }

        public string BuildProcCpuInfoFlags(bool IsX64Guest)
        {
            List<string> Flags = new List<string>();
            AddLeaf1EdxFlag(Flags, 0, "fpu");
            AddLeaf1EdxFlag(Flags, 4, "tsc");
            AddLeaf1EdxFlag(Flags, 5, "msr");
            AddLeaf1EdxFlag(Flags, 8, "cx8");
            AddLeaf1EdxFlag(Flags, 15, "cmov");
            AddLeaf1EdxFlag(Flags, 19, "clflush");
            AddLeaf1EdxFlag(Flags, 23, "mmx");
            AddLeaf1EdxFlag(Flags, 24, "fxsr");
            AddLeaf1EdxFlag(Flags, 25, "sse");
            AddLeaf1EdxFlag(Flags, 26, "sse2");
            AddLeaf1EcxFlag(Flags, 0, "sse3");
            AddLeaf1EcxFlag(Flags, 9, "ssse3");
            AddLeaf1EcxFlag(Flags, 13, "cx16");
            AddLeaf1EcxFlag(Flags, 19, "sse4_1");
            AddLeaf1EcxFlag(Flags, 20, "sse4_2");
            AddLeaf1EcxFlag(Flags, 23, "popcnt");
            AddLeaf80000001EcxFlag(Flags, 0, "lahf_lm");
            AddLeaf80000001EdxFlag(Flags, 11, "syscall", IsX64Guest);
            AddLeaf80000001EdxFlag(Flags, 20, "nx", IsX64Guest);
            AddLeaf80000001EdxFlag(Flags, 27, "rdtscp", IsX64Guest);
            AddLeaf80000007EdxFlag(Flags, 8, "constant_tsc");
            AddLeaf80000001EdxFlag(Flags, 29, "lm", IsX64Guest);
            return string.Join(" ", Flags);
        }

        public bool TryGetLeaf(uint Leaf, uint SubLeaf, bool IsX64Guest, out uint Eax, out uint Ebx, out uint Ecx, out uint Edx)
        {
            Eax = 0;
            Ebx = 0;
            Ecx = 0;
            Edx = 0;

            switch (Leaf)
            {
                case 0:
                    Eax = MaxBasicLeaf;
                    WriteVendorRegisters(out Ebx, out Edx, out Ecx);
                    return true;

                case 1:
                    Eax = Leaf1Eax;
                    Ebx = Leaf1Ebx;
                    Ecx = Leaf1Ecx;
                    Edx = Leaf1Edx;
                    return true;

                case 7:
                    if (SubLeaf != 0)
                        return false;

                    Eax = Leaf7Subleaf0Eax;
                    Ebx = Leaf7Subleaf0Ebx;
                    Ecx = Leaf7Subleaf0Ecx;
                    Edx = Leaf7Subleaf0Edx;
                    return true;

                case 0xD:
                case 0x14:
                case 0x19:
                    return true;

                case 0x80000000:
                    Eax = MaxExtendedLeaf;
                    return true;

                case 0x80000001:
                    Ecx = Leaf80000001Ecx;
                    Edx = GetLeaf80000001Edx(IsX64Guest);
                    return true;

                case 0x80000002:
                case 0x80000003:
                case 0x80000004:
                    WriteBrandLeaf(Leaf, out Eax, out Ebx, out Ecx, out Edx);
                    return true;

                case 0x80000007:
                    Edx = Leaf80000007Edx;
                    return true;

                case 0x80000008:
                    Eax = Leaf80000008Eax;
                    return true;
            }

            return false;
        }

        private void AddLeaf1EcxFlag(List<string> Flags, int Bit, string Name)
        {
            if ((Leaf1Ecx & (1u << Bit)) != 0)
                Flags.Add(Name);
        }

        private void AddLeaf1EdxFlag(List<string> Flags, int Bit, string Name)
        {
            if ((Leaf1Edx & (1u << Bit)) != 0)
                Flags.Add(Name);
        }

        private void AddLeaf80000001EcxFlag(List<string> Flags, int Bit, string Name)
        {
            if ((Leaf80000001Ecx & (1u << Bit)) != 0)
                Flags.Add(Name);
        }

        private void AddLeaf80000001EdxFlag(List<string> Flags, int Bit, string Name, bool IsX64Guest)
        {
            if ((GetLeaf80000001Edx(IsX64Guest) & (1u << Bit)) != 0)
                Flags.Add(Name);
        }

        private void AddLeaf80000007EdxFlag(List<string> Flags, int Bit, string Name)
        {
            if ((Leaf80000007Edx & (1u << Bit)) != 0)
                Flags.Add(Name);
        }

        private uint GetLeaf80000001Edx(bool IsX64Guest)
        {
            uint Value = Leaf80000001Edx;
            if (IsX64Guest)
                Value |= 1u << 29;

            return Value;
        }

        private void WriteVendorRegisters(out uint Ebx, out uint Edx, out uint Ecx)
        {
            byte[] VendorBytes = new byte[12];
            Encoding.ASCII.GetBytes((VendorId ?? string.Empty).PadRight(12, ' ').Substring(0, 12), 0, 12, VendorBytes, 0);
            Ebx = BinaryPrimitives.ReadUInt32LittleEndian(VendorBytes.AsSpan(0, 4));
            Edx = BinaryPrimitives.ReadUInt32LittleEndian(VendorBytes.AsSpan(4, 4));
            Ecx = BinaryPrimitives.ReadUInt32LittleEndian(VendorBytes.AsSpan(8, 4));
        }

        private void WriteBrandLeaf(uint Leaf, out uint Eax, out uint Ebx, out uint Ecx, out uint Edx)
        {
            byte[] BrandBytes = new byte[48];
            string Brand = GetModelName();
            int Count = Encoding.ASCII.GetBytes(Brand, 0, Brand.Length > 48 ? 48 : Brand.Length, BrandBytes, 0);
            if (Count < BrandBytes.Length)
                Array.Fill(BrandBytes, (byte)' ', Count, BrandBytes.Length - Count);

            int BaseOffset = (int)(Leaf - 0x80000002u) * 16;
            Eax = BinaryPrimitives.ReadUInt32LittleEndian(BrandBytes.AsSpan(BaseOffset + 0, 4));
            Ebx = BinaryPrimitives.ReadUInt32LittleEndian(BrandBytes.AsSpan(BaseOffset + 4, 4));
            Ecx = BinaryPrimitives.ReadUInt32LittleEndian(BrandBytes.AsSpan(BaseOffset + 8, 4));
            Edx = BinaryPrimitives.ReadUInt32LittleEndian(BrandBytes.AsSpan(BaseOffset + 12, 4));
        }
    }

    public sealed class LinuxSystemIdentity
    {
        public string SysName { get; set; } = "Linux";
        public string NodeName { get; set; } = "brovan";
        public string Release { get; set; } = "6.8.0-brovan";
        public string Version { get; set; } = "#1 SMP PREEMPT_DYNAMIC Brovan";
        public string DomainName { get; set; } = "localdomain";
        public LinuxX86CpuIdentity X86Cpu { get; set; } = new LinuxX86CpuIdentity();
        public string CpuVendorId { get => X86Cpu.VendorId; set => X86Cpu.VendorId = value; }
        public string CpuModelName { get => X86Cpu.GetModelName(); set => X86Cpu.BrandString = value; }
        public int CpuCount { get; set; } = 1;

        /// <summary>
        /// Gets the normalized number of virtual processors exposed to the Linux guest.
        /// </summary>
        public int GetCpuCount()
        {
            return Math.Max(1, CpuCount);
        }

        /// <summary>
        /// Gets the online CPU list string used by procfs and sysfs CPU topology files.
        /// </summary>
        public string GetCpuListString()
        {
            int Count = GetCpuCount();
            return Count == 1 ? "0" : "0-" + (Count - 1).ToString();
        }

        /// <summary>
        /// Gets a bit mask containing all virtual CPUs exposed to the guest.
        /// </summary>
        public ulong GetCpuMask64()
        {
            int Count = Math.Min(GetCpuCount(), 64);
            return Count == 64 ? ulong.MaxValue : ((1UL << Count) - 1UL);
        }

        public string GetMachineName(bool IsX64Guest)
        {
            return IsX64Guest ? "x86_64" : "i686";
        }

        public string GetPlatformName(bool IsX64Guest)
        {
            return GetMachineName(IsX64Guest);
        }

        public string BuildVersionString()
        {
            return SysName + " version " + Release + " " + Version;
        }
    }

    public sealed class LinuxCredentials
    {
        public uint RealUserId { get; set; }
        public uint EffectiveUserId { get; set; }
        public uint SavedUserId { get; set; }
        public uint FileSystemUserId { get; set; }
        public uint RealGroupId { get; set; }
        public uint EffectiveGroupId { get; set; }
        public uint SavedGroupId { get; set; }
        public uint FileSystemGroupId { get; set; }
        public uint Umask { get; set; }
        public List<uint> SupplementaryGroups { get; } = new List<uint>();
    }

    public struct LinuxResourceLimit
    {
        public ulong Current;
        public ulong Maximum;
    }

    public sealed class LinuxTerminalState
    {
        public byte[] Termios { get; } = new byte[36];
        public ushort Rows { get; set; } = 24;
        public ushort Columns { get; set; } = 80;
        public ushort XPixel { get; set; }
        public ushort YPixel { get; set; }

        public LinuxTerminalState()
        {
            Termios[5] = 0;
            Termios[6] = 1;
        }
    }

    public sealed class LinuxTaskInfo
    {
        public uint ThreadId { get; set; }
        public string Name { get; set; } = "";
        public DateTimeOffset StartTimeUtc { get; set; }
    }

    public sealed class LinuxProcessInfo
    {
        public int ProcessId { get; set; }
        public int ParentProcessId { get; set; }
        public int ProcessGroupId { get; set; }
        public int SessionId { get; set; }
        public uint UserId { get; set; }
        public uint GroupId { get; set; }
        public string ExecutablePath { get; set; } = "";
        public string CommandName { get; set; } = "program";
        public string[] Arguments { get; set; } = Array.Empty<string>();
        public DateTimeOffset StartTimeUtc { get; set; }
        public Dictionary<uint, LinuxTaskInfo> Threads { get; } = new Dictionary<uint, LinuxTaskInfo>();
    }

    public class LinuxSyscallsHelper
    {
        private const int MinimumSyntheticUptimeSeconds = 2 * 60 * 60;
        private const int MaximumSyntheticUptimeSeconds = 2 * 24 * 60 * 60;
        private const int MaximumDefaultGuestCpuCount = 4;

        public ulong ProgramBreak { get; set; }
        public ulong ProgramBreakBase { get; set; }
        public bool CpuidEnabled { get; set; }
        public int PID { get; private set; }
        public int ParentPid { get; private set; }
        public int ProcessGroupId { get; private set; }
        public int SessionId { get; private set; }
        public int CurrentThreadId { get; set; }
        public Dictionary<int, LinuxResourceLimit> ResourceLimits { get; private set; }
        public FileDescriptorTable DescriptorTable { get; private set; }
        public Dictionary<string, LinuxMountEntry> MountTable { get; private set; }
        public SharedBuffer Shared { get; private set; }
        public DateTimeOffset RealtimeClockBaseUtc { get; private set; }
        public Stopwatch MonotonicClock { get; private set; }
        public TimeSpan SyntheticUptimeBase { get; private set; }
        private long EmulatedClockMilliseconds;
        public LinuxTerminalState TerminalState { get; private set; }
        public string ProcessExecutablePath { get; set; }
        public string[] ProcessArguments { get; set; }
        public DateTimeOffset ProcessStartTimeUtc { get; private set; }
        public LinuxProcessInfo CurrentProcess { get; private set; }
        public Dictionary<int, LinuxProcessInfo> ProcessTable { get; private set; }
        private readonly Dictionary<ulong, List<uint>> FutexWaiters = new Dictionary<ulong, List<uint>>();
        private readonly Dictionary<int, byte[]> SignalActions = new Dictionary<int, byte[]>();

        public int PATH_MAX = 4096;
        public SpecialPathsHandlers SpecialPathsHandler { get; private set; }
        public LinuxCredentials Credentials { get; private set; }
        public LinuxSystemIdentity SystemIdentity { get; private set; }

        public LinuxSyscallsHelper()
        {
            Shared = new SharedBuffer();
            ResourceLimits = new Dictionary<int, LinuxResourceLimit>();
            DescriptorTable = new FileDescriptorTable();
            MountTable = new Dictionary<string, LinuxMountEntry>(StringComparer.Ordinal);
            ProcessTable = new Dictionary<int, LinuxProcessInfo>();
            PID = AllocateGuestProcessId();
            ParentPid = 273;
            ProcessGroupId = 273;
            SessionId = 273;
            CpuidEnabled = true;
            RealtimeClockBaseUtc = DateTimeOffset.UtcNow;
            MonotonicClock = Stopwatch.StartNew();
            SyntheticUptimeBase = TimeSpan.FromSeconds(RandomNumberGenerator.GetInt32(MinimumSyntheticUptimeSeconds, MaximumSyntheticUptimeSeconds + 1));
            ProcessStartTimeUtc = DateTimeOffset.UtcNow;
            ProcessExecutablePath = "/program";
            ProcessArguments = Array.Empty<string>();
            Credentials = new LinuxCredentials()
            {
                RealUserId = 1000,
                EffectiveUserId = 1000,
                SavedUserId = 1000,
                FileSystemUserId = 1000,
                RealGroupId = 1000,
                EffectiveGroupId = 1000,
                SavedGroupId = 1000,
                FileSystemGroupId = 1000,
                Umask = 0x12,
            };
            Credentials.SupplementaryGroups.Add(1000);
            SystemIdentity = new LinuxSystemIdentity()
            {
                CpuCount = GetDefaultGuestCpuCount()
            };
            TerminalState = new LinuxTerminalState();
            SpecialPathsHandler = new SpecialPathsHandlers();
            InitializeSystemProcesses();
            InitializeCurrentProcess();
        }

        private static int GetDefaultGuestCpuCount()
        {
            int HostCpuCount = Environment.ProcessorCount;
            if (HostCpuCount <= 0)
                return MaximumDefaultGuestCpuCount;

            return Math.Clamp(HostCpuCount, 1, MaximumDefaultGuestCpuCount);
        }

        public void SyncCurrentProcessMetadata()
        {
            InitializeCurrentProcess();
            CurrentProcess.ExecutablePath = string.IsNullOrWhiteSpace(ProcessExecutablePath) ? "/program" : ProcessExecutablePath;
            CurrentProcess.CommandName = GetProcessCommandName();
            CurrentProcess.Arguments = ProcessArguments ?? Array.Empty<string>();
        }

        /// <summary>
        /// Returns the synthetic system uptime exposed to the Linux guest.
        /// </summary>
        public void SyncEmulatedClock(BinaryEmulator Instance)
        {
            if (Instance == null)
                return;

            long Tick = Instance.EmulatedTickCount64;
            if (Tick > EmulatedClockMilliseconds)
                EmulatedClockMilliseconds = Tick;
        }

        public TimeSpan GetClockElapsed()
        {
            TimeSpan HostElapsed = MonotonicClock.Elapsed;
            TimeSpan GuestElapsed = EmulatedClockMilliseconds <= 0 ? TimeSpan.Zero : TimeSpan.FromMilliseconds(EmulatedClockMilliseconds);
            return GuestElapsed > HostElapsed ? GuestElapsed : HostElapsed;
        }

        public DateTimeOffset GetRealtimeNowUtc()
        {
            return RealtimeClockBaseUtc + GetClockElapsed();
        }

        public TimeSpan GetSystemUptime()
        {
            TimeSpan Uptime = SyntheticUptimeBase + GetClockElapsed();
            if (Uptime < TimeSpan.Zero)
                return TimeSpan.Zero;

            return Uptime;
        }

        public string GetProcessCommandName()
        {
            string Value = string.Empty;
            if (ProcessArguments != null && ProcessArguments.Length != 0)
                Value = ProcessArguments[0] ?? string.Empty;

            if (string.IsNullOrWhiteSpace(Value) && !string.IsNullOrWhiteSpace(ProcessExecutablePath))
                Value = Path.GetFileName(ProcessExecutablePath);

            if (string.IsNullOrWhiteSpace(Value))
                Value = "program";

            Value = Path.GetFileName(Value.Replace('\\', '/'));
            return Value.Length > 15 ? Value.Substring(0, 15) : Value;
        }

        public string GetSystemName()
        {
            return SystemIdentity.SysName;
        }

        public string GetHostName()
        {
            return string.IsNullOrWhiteSpace(SystemIdentity.NodeName) ? "brovan" : SystemIdentity.NodeName;
        }

        public string GetKernelRelease()
        {
            return SystemIdentity.Release;
        }

        public string GetKernelVersion()
        {
            return SystemIdentity.Version;
        }

        public string GetDomainName()
        {
            return string.IsNullOrWhiteSpace(SystemIdentity.DomainName) ? "localdomain" : SystemIdentity.DomainName;
        }

        public string GetMachineName(bool IsX64Guest)
        {
            return SystemIdentity.GetMachineName(IsX64Guest);
        }

        public string GetPlatformName(bool IsX64Guest)
        {
            return SystemIdentity.GetPlatformName(IsX64Guest);
        }

        public Utsname CreateUtsname(bool IsX64Guest)
        {
            return new Utsname()
            {
                sysname = GetSystemName(),
                nodename = GetHostName(),
                release = GetKernelRelease(),
                version = GetKernelVersion(),
                machine = GetMachineName(IsX64Guest),
                domainname = GetDomainName(),
            };
        }

        public byte[] GetSignalAction(int Signal, int Size)
        {
            if (SignalActions.TryGetValue(Signal, out byte[] Action) && Action.Length == Size)
                return (byte[])Action.Clone();

            byte[] Result = new byte[Size];
            if (Action != null)
                Buffer.BlockCopy(Action, 0, Result, 0, Math.Min(Action.Length, Result.Length));

            return Result;
        }

        public void SetSignalAction(int Signal, byte[] Action)
        {
            if (Action == null)
                SignalActions.Remove(Signal);
            else
                SignalActions[Signal] = (byte[])Action.Clone();
        }

        public void AddFutexWaiter(ulong Address, EmulatedThread Thread)
        {
            if (Thread == null)
                return;

            if (!FutexWaiters.TryGetValue(Address, out List<uint> Waiters))
            {
                Waiters = new List<uint>();
                FutexWaiters[Address] = Waiters;
            }

            if (!Waiters.Contains(Thread.ThreadId))
                Waiters.Add(Thread.ThreadId);
        }

        public void RemoveFutexWaiter(ulong Address, EmulatedThread Thread)
        {
            if (Thread == null || !FutexWaiters.TryGetValue(Address, out List<uint> Waiters))
                return;

            Waiters.Remove(Thread.ThreadId);
            if (Waiters.Count == 0)
                FutexWaiters.Remove(Address);
        }

        public uint WakeFutexWaiters(BinaryEmulator Instance, ulong Address, uint Count, uint Bitset)
        {
            if (Instance == null || Count == 0 || !FutexWaiters.TryGetValue(Address, out List<uint> Waiters))
                return 0;

            uint Woken = 0;
            for (int i = 0; i < Waiters.Count && Woken < Count;)
            {
                uint ThreadId = Waiters[i];
                if (!Instance.Threads.TryGetValue(ThreadId, out EmulatedThread Thread) || Thread == null)
                {
                    Waiters.RemoveAt(i);
                    continue;
                }

                LinuxThreadState State = Thread.GuestState as LinuxThreadState;
                if (State == null || !State.FutexWaitActive || State.FutexAddress != Address || (State.FutexBitset & Bitset) == 0)
                {
                    i++;
                    continue;
                }

                State.FutexWaitActive = false;
                State.FutexWaitResult = 0;
                SetThreadReturnValue(Instance, Thread, 0);
                State.FutexWaitCompleted = Thread.Context != null && Thread.Context.RIP == State.FutexWaitResumeRIP;
                if (!State.FutexWaitCompleted)
                    State.FutexWaitResumeRIP = 0;

                State.FutexAddress = 0;
                State.FutexBitset = 0;
                Thread.WaitActive = false;
                Thread.WaitHandles = null;
                Thread.WaitDeadline = -1;
                Thread.WaitTimedOut = false;
                Thread.WaitSatisfiedIndex = -1;
                Thread.State = EmulatedThreadState.Ready;
                Waiters.RemoveAt(i);
                Woken++;
            }

            if (Waiters.Count == 0)
                FutexWaiters.Remove(Address);

            return Woken;
        }

        public void RegisterThread(EmulatedThread Thread)
        {
            if (Thread == null)
                return;

            SyncCurrentProcessMetadata();
            CurrentThreadId = (int)Thread.ThreadId;

            if (!CurrentProcess.Threads.TryGetValue(Thread.ThreadId, out LinuxTaskInfo Task))
            {
                Task = new LinuxTaskInfo()
                {
                    ThreadId = Thread.ThreadId,
                    StartTimeUtc = DateTimeOffset.UtcNow,
                };

                CurrentProcess.Threads[Thread.ThreadId] = Task;
            }

            string TaskName = !string.IsNullOrWhiteSpace(Thread.Name) ? Thread.Name : CurrentProcess.CommandName;
            Task.Name = TaskName.Length > 15 ? TaskName.Substring(0, 15) : TaskName;
        }

        public void UnregisterThread(uint ThreadId)
        {
            if (CurrentProcess == null)
                return;

            CurrentProcess.Threads.Remove(ThreadId);
            if (CurrentThreadId == (int)ThreadId)
                CurrentThreadId = 0;
        }

        public bool TryGetThreadInfo(uint ThreadId, out LinuxTaskInfo Task)
        {
            InitializeCurrentProcess();
            if (CurrentProcess.Threads.TryGetValue(ThreadId, out Task))
                return true;

            Task = null;
            return false;
        }

        public bool TryGetProcessInfo(int ProcessId, out LinuxProcessInfo Process)
        {
            InitializeCurrentProcess();
            return ProcessTable.TryGetValue(ProcessId, out Process);
        }

        public bool TryGetThreadInfo(int ProcessId, uint ThreadId, out LinuxTaskInfo Task)
        {
            InitializeCurrentProcess();
            if (ProcessTable.TryGetValue(ProcessId, out LinuxProcessInfo Process) && Process.Threads.TryGetValue(ThreadId, out Task))
                return true;

            Task = null;
            return false;
        }


        public IEnumerable<LinuxTaskInfo> EnumerateThreads()
        {
            InitializeCurrentProcess();
            return CurrentProcess.Threads.Values.OrderBy(Task => Task.ThreadId);
        }

        public IEnumerable<LinuxProcessInfo> EnumerateProcesses()
        {
            InitializeCurrentProcess();
            return ProcessTable.Values.OrderBy(Process => Process.ProcessId);
        }

        private void InitializeCurrentProcess()
        {
            if (CurrentProcess != null)
                return;

            CurrentProcess = new LinuxProcessInfo()
            {
                ProcessId = PID,
                ParentProcessId = ParentPid,
                ProcessGroupId = ProcessGroupId,
                SessionId = SessionId,
                UserId = Credentials.RealUserId,
                GroupId = Credentials.RealGroupId,
                ExecutablePath = ProcessExecutablePath,
                CommandName = "program",
                Arguments = ProcessArguments ?? Array.Empty<string>(),
                StartTimeUtc = ProcessStartTimeUtc,
            };

            ProcessTable[PID] = CurrentProcess;
            SyncCurrentProcessMetadata();
        }

        private void InitializeSystemProcesses()
        {
            if (ProcessTable.Count != 0)
                return;

            DateTimeOffset Now = DateTimeOffset.UtcNow;

            AddSyntheticProcess(1, 0, 1, 1, 0, 0, "/usr/lib/systemd/systemd", "systemd", new[] { "/sbin/init" }, Now - TimeSpan.FromMinutes(180));
            AddSyntheticProcess(2, 0, 1, 1, 0, 0, string.Empty, "init-systemd(Ub", Array.Empty<string>(), Now - TimeSpan.FromMinutes(180));
            AddSyntheticProcess(7, 0, 1, 1, 0, 0, string.Empty, "init", Array.Empty<string>(), Now - TimeSpan.FromMinutes(180));
            AddSyntheticProcess(39, 1, 1, 1, 0, 0, "/usr/lib/systemd/systemd-journald", "systemd-journal", new[] { "systemd-journal" }, Now - TimeSpan.FromMinutes(179));
            AddSyntheticProcess(87, 1, 1, 1, 0, 0, "/usr/lib/systemd/systemd-udevd", "systemd-udevd", new[] { "systemd-udevd" }, Now - TimeSpan.FromMinutes(178));
            AddSyntheticProcess(96, 1, 1, 1, 100, 102, "/usr/lib/systemd/systemd-resolved", "systemd-resolve", new[] { "systemd-resolve" }, Now - TimeSpan.FromMinutes(177));
            AddSyntheticProcess(97, 1, 1, 1, 101, 103, "/usr/lib/systemd/systemd-timesyncd", "systemd-timesyn", new[] { "systemd-timesyn" }, Now - TimeSpan.FromMinutes(177));
            AddSyntheticProcess(132, 1, 1, 1, 0, 0, "/usr/sbin/cron", "cron", new[] { "cron" }, Now - TimeSpan.FromMinutes(176));
            AddSyntheticProcess(133, 1, 1, 1, 102, 105, "/usr/bin/dbus-daemon", "dbus-daemon", new[] { "dbus-daemon" }, Now - TimeSpan.FromMinutes(176));
            AddSyntheticProcess(140, 1, 1, 1, 0, 0, "/usr/lib/systemd/systemd-logind", "systemd-logind", new[] { "systemd-logind" }, Now - TimeSpan.FromMinutes(175));
            AddSyntheticProcess(148, 1, 148, 148, 0, 0, "/sbin/agetty", "agetty", new[] { "agetty", "--noclear", "hvc0" }, Now - TimeSpan.FromMinutes(170));
            AddSyntheticProcess(153, 1, 1, 1, 104, 108, "/usr/sbin/rsyslogd", "rsyslogd", new[] { "rsyslogd" }, Now - TimeSpan.FromMinutes(169));
            AddSyntheticProcess(161, 1, 161, 161, 0, 0, "/sbin/agetty", "agetty", new[] { "agetty", "tty1" }, Now - TimeSpan.FromMinutes(168));
            AddSyntheticProcess(178, 1, 1, 1, 0, 0, "/usr/bin/unattended-upgrade", "unattended-upgr", new[] { "unattended-upgr" }, Now - TimeSpan.FromMinutes(160));
            AddSyntheticProcess(271, 1, 271, 271, 1000, 1000, "/init", "SessionLeader", new[] { "SessionLeader" }, Now - TimeSpan.FromMinutes(90));
            AddSyntheticProcess(272, 271, 271, 271, 1000, 1000, "/init", "Relay(273)", new[] { "Relay(273)" }, Now - TimeSpan.FromMinutes(90));
            AddSyntheticProcess(273, 272, 273, 273, 1000, 1000, "/usr/bin/bash", "bash", new[] { "bash" }, Now - TimeSpan.FromMinutes(89));
            AddSyntheticProcess(274, 1, 274, 274, 0, 0, "/bin/login", "login", new[] { "login" }, Now - TimeSpan.FromMinutes(88));
            AddSyntheticProcess(359, 1, 359, 359, 1000, 1000, "/usr/lib/systemd/systemd", "systemd", new[] { "systemd", "--user" }, Now - TimeSpan.FromMinutes(87));
            AddSyntheticProcess(364, 359, 359, 359, 1000, 1000, string.Empty, "(sd-pam)", Array.Empty<string>(), Now - TimeSpan.FromMinutes(87));
            AddSyntheticProcess(382, 274, 382, 274, 1000, 1000, "/usr/bin/bash", "bash", new[] { "-bash" }, Now - TimeSpan.FromMinutes(86));
            AddSyntheticProcess(730, 1, 1, 1, 105, 109, "/usr/lib/polkit-1/polkitd", "polkitd", new[] { "polkitd" }, Now - TimeSpan.FromMinutes(80));
            AddSyntheticProcess(2939, 273, 2939, 273, 1000, 1000, "/usr/bin/sudo", "sudo", new[] { "sudo" }, Now - TimeSpan.FromMinutes(5));
            AddSyntheticProcess(2940, 382, 2940, 274, 1000, 1000, "/usr/bin/sudo", "sudo", new[] { "sudo" }, Now - TimeSpan.FromMinutes(5));
            AddSyntheticProcess(2941, 2940, 2941, 274, 1000, 1000, "/usr/bin/ps", "ps", new[] { "ps" }, Now - TimeSpan.FromMinutes(4));
        }

        private int AllocateGuestProcessId()
        {
            int Candidate = Random.Shared.Next(3000, 9999);
            while (ProcessTable.ContainsKey(Candidate))
                Candidate++;

            return Candidate;
        }

        private void AddSyntheticProcess(int ProcessId, int ParentProcessId, int ProcessGroupId, int SessionId, uint UserId, uint GroupId, string ExecutablePath, string CommandName, string[] Arguments, DateTimeOffset StartTimeUtc)
        {
            LinuxProcessInfo Process = new LinuxProcessInfo()
            {
                ProcessId = ProcessId,
                ParentProcessId = ParentProcessId,
                ProcessGroupId = ProcessGroupId,
                SessionId = SessionId,
                UserId = UserId,
                GroupId = GroupId,
                ExecutablePath = ExecutablePath ?? string.Empty,
                CommandName = string.IsNullOrWhiteSpace(CommandName) ? "process" : (CommandName.Length > 15 ? CommandName.Substring(0, 15) : CommandName),
                Arguments = Arguments ?? Array.Empty<string>(),
                StartTimeUtc = StartTimeUtc,
            };

            Process.Threads[(uint)ProcessId] = new LinuxTaskInfo()
            {
                ThreadId = (uint)ProcessId,
                Name = Process.CommandName,
                StartTimeUtc = StartTimeUtc,
            };

            ProcessTable[ProcessId] = Process;
        }

        public string NormalizePath(string PathValue)
        {
            if (string.IsNullOrWhiteSpace(PathValue))
                return null;

            string Normalized = PathValue.Trim().TrimEnd('\0').Replace('\\', '/');
            if (Normalized.Length == 0)
                return null;

            while (Normalized.Contains("//"))
                Normalized = Normalized.Replace("//", "/");

            if (!Normalized.StartsWith("/", StringComparison.Ordinal))
                Normalized = "/" + Normalized;

            if (Normalized.Length > 1)
                Normalized = Normalized.TrimEnd('/');

            return Normalized.Length == 0 ? "/" : Normalized;
        }

        public void SetMount(string GuestPath, string HostPath, bool IsDirectory, bool ReadOnly, string FileSystemType)
        {
            string NormalizedGuest = NormalizePath(GuestPath);
            if (string.IsNullOrEmpty(NormalizedGuest) || string.IsNullOrWhiteSpace(HostPath))
                return;

            MountTable[NormalizedGuest] = new LinuxMountEntry
            {
                GuestPath = NormalizedGuest,
                HostPath = HostPath,
                IsDirectory = IsDirectory,
                ReadOnly = ReadOnly,
                FileSystemType = FileSystemType ?? string.Empty
            };
        }

        public bool TryGetMountForPath(string GuestPath, out LinuxMountEntry Entry)
        {
            Entry = null;
            string NormalizedGuest = NormalizePath(GuestPath);
            if (string.IsNullOrEmpty(NormalizedGuest))
                return false;

            if (MountTable.TryGetValue(NormalizedGuest, out LinuxMountEntry ExactEntry))
            {
                Entry = ExactEntry;
                return true;
            }

            LinuxMountEntry BestEntry = null;
            foreach (LinuxMountEntry Candidate in MountTable.Values)
            {
                if (!Candidate.IsDirectory)
                    continue;

                if (NormalizedGuest != Candidate.GuestPath && !NormalizedGuest.StartsWith(Candidate.GuestPath + "/", StringComparison.Ordinal))
                    continue;

                if (BestEntry == null || Candidate.GuestPath.Length > BestEntry.GuestPath.Length)
                    BestEntry = Candidate;
            }

            if (BestEntry == null)
                return false;

            Entry = BestEntry;
            return true;
        }

        public string ResolveHostPath(string GuestPath, bool CreateDirectories = false, bool PreserveFinalLink = false)
        {
            string NormalizedGuest = NormalizePath(GuestPath);
            if (!string.IsNullOrEmpty(NormalizedGuest) && TryGetMountForPath(NormalizedGuest, out LinuxMountEntry Entry))
            {
                if (!Entry.IsDirectory || NormalizedGuest == Entry.GuestPath)
                    return Entry.HostPath;

                string RelativePath = NormalizedGuest.Substring(Entry.GuestPath.Length).TrimStart('/');
                return CombineHostPath(Entry.HostPath, RelativePath);
            }

            return GeneralHelper.IO.ResolveHostPath(GuestPath, BinaryFormat.ELF, CreateDirectories, PreserveFinalLink);
        }

        public string ResolveVirtualHostPath(string GuestPath, bool CreateDirectories = false)
        {
            return GeneralHelper.IO.ResolveVirtualHostPath(GuestPath, BinaryFormat.ELF, CreateDirectories);
        }

        private static string CombineHostPath(string Root, string RelativePath)
        {
            if (string.IsNullOrWhiteSpace(Root))
                return null;

            if (string.IsNullOrWhiteSpace(RelativePath))
                return Root;

            string Result = Root;
            string[] Parts = RelativePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < Parts.Length; i++)
                Result = Path.Combine(Result, Parts[i]);

            return Result;
        }

        public MemoryProtection TranslateLinuxMemToNative(uint flags)
        {
            MemoryProtection Protection = MemoryProtection.None;
            const uint PROT_READ = 1;
            const uint PROT_WRITE = 2;
            const uint PROT_EXEC = 4;

            if ((flags & PROT_READ) != 0)
                Protection |= MemoryProtection.Read;

            if ((flags & PROT_WRITE) != 0)
                Protection |= MemoryProtection.Write;

            if ((flags & PROT_EXEC) != 0)
                Protection |= MemoryProtection.Execute;

            return Protection;
        }

        public void SetReturnValue(BinaryEmulator Instance, LinuxSyscallContext Context, long Value)
        {
            if (Context.Abi == SyscallAbi.X64)
            {
                Instance.WriteRegister(Registers.UC_X86_REG_RAX, unchecked((ulong)Value));
            }
            else
            {
                Instance.WriteRegister32(Registers.UC_X86_REG_EAX, unchecked((uint)Value));
            }
        }

        public void SetThreadReturnValue(BinaryEmulator Instance, EmulatedThread Thread, long Value)
        {
            if (Instance == null || Thread?.Context == null)
                return;

            if (Instance.IsX64Guest)
                Thread.Context.RAX = unchecked((ulong)Value);
            else
                Thread.Context.RAX = unchecked((uint)Value);
        }

        public void SetReturnValue(BinaryEmulator Instance, LinuxSyscallContext Context, LinuxErrno Value)
        {
            if (Context.Abi == SyscallAbi.X64)
            {
                Instance.WriteRegister(Registers.UC_X86_REG_RAX, unchecked((ulong)Value));
            }
            else
            {
                Instance.WriteRegister32(Registers.UC_X86_REG_EAX, unchecked((uint)Value));
            }
        }

        public void SetReturnValue(BinaryEmulator Instance, LinuxSyscallContext Context, ulong Value)
        {
            if (Context.Abi == SyscallAbi.X64)
            {
                Instance.WriteRegister(Registers.UC_X86_REG_RAX, Value);
            }
            else
            {
                Instance.WriteRegister32(Registers.UC_X86_REG_EAX, unchecked((uint)Value));
            }
        }
    }

    internal struct LinuxSignalAction
    {
        public ulong Handler;
        public ulong Flags;
        public ulong Restorer;
        public byte[] Mask;
    }

    internal static class LinuxSignalHelpers
    {
        public const int SIGILL = 4;
        public const int SIGKILL = 9;
        public const int SIGSEGV = 11;
        public const int SIGSTOP = 19;
        public const int ILL_ILLOPN = 2;
        public const int ILL_PRVOPC = 5;
        public const int SEGV_MAPERR = 1;
        public const int SEGV_ACCERR = 2;

        private const ulong SIG_DFL = 0;
        private const ulong SIG_IGN = 1;
        private const ulong SignalFrameMagic = 0x4252564E53494731UL;
        private const int SS_ONSTACK = 1;
        private const int SS_DISABLE = 2;
        private const ulong SA_ONSTACK = 0x08000000UL;
        private const ulong SA_RESETHAND = 0x80000000UL;
        private const ulong SA_NODEFER = 0x40000000UL;
        private const ulong SA_RESTORER = 0x04000000UL;
        private const ulong SA_SIGINFO = 4;
        private const ulong X86_EFLAGS_DF = 1UL << 10;
        private const ulong X86_EFLAGS_TF = 1UL << 8;
        private const ulong X86_EFLAGS_RF = 1UL << 16;

        private const int X64FrameSize = 0x400;
        private const int X64SavedSignalOffset = 0x10;
        private const int X64SavedFaultOffset = 0x18;
        private const int X64SavedMaskOffset = 0x20;
        private const int X64SavedStackActiveOffset = 0x28;
        private const int X64SavedContextOffset = 0x30;
        private const int X64SigInfoOffset = 0x100;
        private const int X64UContextOffset = 0x180;

        private const int REG_R8 = 0;
        private const int REG_R9 = 1;
        private const int REG_R10 = 2;
        private const int REG_R11 = 3;
        private const int REG_R12 = 4;
        private const int REG_R13 = 5;
        private const int REG_R14 = 6;
        private const int REG_R15 = 7;
        private const int REG_RDI = 8;
        private const int REG_RSI = 9;
        private const int REG_RBP = 10;
        private const int REG_RBX = 11;
        private const int REG_RDX = 12;
        private const int REG_RAX = 13;
        private const int REG_RCX = 14;
        private const int REG_RSP = 15;
        private const int REG_RIP = 16;
        private const int REG_EFL = 17;
        private const int REG_CR2 = 22;

        public static bool IsValidSignalSetSize(ulong Size)
        {
            return Size != 0 && Size <= LinuxThreadState.SignalSetSize;
        }

        public static int GetSigActionSize(LinuxSyscallContext Context, ulong SignalSetSize)
        {
            int HeaderSize = Context.Abi == SyscallAbi.X64 ? 24 : 12;
            return HeaderSize + (int)SignalSetSize;
        }

        public static LinuxThreadState GetOrCreateThreadState(BinaryEmulator Instance, LinuxSyscallsHelper Helper)
        {
            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null)
                return null;

            LinuxThreadState State = Thread.GuestState as LinuxThreadState;
            if (State == null)
            {
                State = new LinuxThreadState
                {
                    CpuidEnabled = Helper.CpuidEnabled
                };

                if (Instance.IsX64Guest)
                {
                    State.FsBase = Instance.ReadRegister(Registers.UC_X86_REG_FS_BASE);
                    State.GsBase = Instance.ReadRegister(Registers.UC_X86_REG_GS_BASE);
                }

                Thread.GuestState = State;
            }

            State.EnsureSignalState();
            return State;
        }

        public static void ClearUnblockableSignals(byte[] Mask)
        {
            ClearSignal(Mask, SIGKILL);
            ClearSignal(Mask, SIGSTOP);
        }

        public static bool IsProtectionFault(MemoryType Type)
        {
            return Type == MemoryType.UC_MEM_READ_PROT ||
                   Type == MemoryType.UC_MEM_WRITE_PROT ||
                   Type == MemoryType.UC_MEM_FETCH_PROT;
        }


        public static bool IsSignalBlocked(byte[] Mask, int Signal)
        {
            if (Signal <= 0)
                return false;

            int Bit = Signal - 1;
            int ByteIndex = Bit >> 3;
            int BitIndex = Bit & 7;
            return (uint)ByteIndex < (uint)(Mask?.Length ?? 0) && (Mask[ByteIndex] & (1 << BitIndex)) != 0;
        }

        public static void QueueSignal(BinaryEmulator Instance, LinuxSyscallsHelper Helper, EmulatedThread Thread, LinuxPendingSignal Pending, bool ForceDelivery = false)
        {
            if (Instance == null || Helper == null || Thread == null || Pending.Signal <= 0 || Pending.Signal >= LinuxThreadState.SignalCount)
                return;

            LinuxThreadState State = Thread.GuestState as LinuxThreadState;
            if (State == null)
            {
                State = new LinuxThreadState
                {
                    CpuidEnabled = Helper.CpuidEnabled
                };
                Thread.GuestState = State;
            }

            State.EnsureSignalState();
            if (!ForceDelivery)
            {
                LinuxSignalAction Action = ReadSignalAction(Helper, Instance.IsX64Guest ? SyscallAbi.X64 : SyscallAbi.X86, Pending.Signal);
                if (Action.Handler == SIG_IGN)
                    return;

                if (IsSignalBlocked(State.SignalMask, Pending.Signal))
                {
                    AddPendingSignal(State, Pending);
                    return;
                }
            }

            State.PendingSignal = Pending;
            State.DispatchSignal = true;
        }

        public static bool TryActivatePendingSignal(LinuxThreadState State)
        {
            if (State?.PendingSignals == null || State.PendingSignals.Count == 0 || State.DispatchSignal)
                return State != null && State.DispatchSignal;

            for (int i = 0; i < State.PendingSignals.Count; i++)
            {
                LinuxPendingSignal Pending = State.PendingSignals[i];
                if (IsSignalBlocked(State.SignalMask, Pending.Signal))
                    continue;

                State.PendingSignals.RemoveAt(i);
                State.PendingSignal = Pending;
                State.DispatchSignal = true;
                return true;
            }

            return false;
        }

        public static void WritePendingSignals(LinuxThreadState State, Span<byte> Destination)
        {
            Destination.Clear();
            if (State?.PendingSignals == null)
                return;

            for (int i = 0; i < State.PendingSignals.Count; i++)
                SetSignal(Destination, State.PendingSignals[i].Signal);
        }

        public static void RestoreEpollWaitSignalMask(LinuxThreadState State)
        {
            if (State?.EpollWaitSavedSignalMask == null)
                return;

            State.EnsureSignalState();
            Array.Clear(State.SignalMask, 0, State.SignalMask.Length);
            Buffer.BlockCopy(State.EpollWaitSavedSignalMask, 0, State.SignalMask, 0, Math.Min(State.SignalMask.Length, State.EpollWaitSavedSignalMask.Length));
            ClearUnblockableSignals(State.SignalMask);
            State.EpollWaitSavedSignalMask = null;
            TryActivatePendingSignal(State);
        }

        public static void ClearEpollWait(LinuxThreadState State)
        {
            if (State == null)
                return;

            State.EpollWaitActive = false;
            State.EpollWaitDescriptor = 0;
            State.EpollWaitEventsAddress = 0;
            State.EpollWaitMaxEvents = 0;
            State.EpollWaitReturnRIP = 0;
            State.EpollWaitSavedSignalMask = null;
        }

        public static void CompleteSigsuspendAfterSignal(LinuxThreadState State, CpuContext Context)
        {
            if (State == null || Context == null || !State.SigsuspendActive)
                return;

            if (State.SigsuspendSavedSignalMask != null)
            {
                State.EnsureSignalState();
                Array.Clear(State.SignalMask, 0, State.SignalMask.Length);
                Buffer.BlockCopy(State.SigsuspendSavedSignalMask, 0, State.SignalMask, 0, Math.Min(State.SignalMask.Length, State.SigsuspendSavedSignalMask.Length));
                ClearUnblockableSignals(State.SignalMask);
            }

            Context.RIP = State.SigsuspendReturnRIP;
            Context.RAX = unchecked((ulong)-(long)LinuxErrno.EINTR);
            State.SigsuspendActive = false;
            State.SigsuspendReturnRIP = 0;
            State.SigsuspendSavedSignalMask = null;
        }

        private static void AddPendingSignal(LinuxThreadState State, LinuxPendingSignal Pending)
        {
            for (int i = 0; i < State.PendingSignals.Count; i++)
            {
                if (State.PendingSignals[i].Signal == Pending.Signal)
                {
                    State.PendingSignals[i] = Pending;
                    return;
                }
            }

            State.PendingSignals.Add(Pending);
        }

        public static bool DeliverPendingSignal(BinaryEmulator Instance, LinuxGuest Guest, LinuxSyscallsHelper Helper, EmulatedThread Thread, LinuxThreadState State)
        {
            if (Instance == null || Guest == null || Helper == null || Thread?.Context == null || State == null)
                return false;

            if (!State.DispatchSignal && !TryActivatePendingSignal(State))
                return false;

            LinuxPendingSignal Pending = State.PendingSignal;
            State.DispatchSignal = false;

            if (Pending.Signal <= 0 || Pending.Signal >= LinuxThreadState.SignalCount)
                return false;

            LinuxSignalAction Action = ReadSignalAction(Helper, Instance.IsX64Guest ? SyscallAbi.X64 : SyscallAbi.X86, Pending.Signal);
            if (Action.Handler == SIG_IGN)
            {
                Thread.State = EmulatedThreadState.Ready;
                return true;
            }

            if (Action.Handler == SIG_DFL)
            {
                TerminateProcessForSignal(Instance, Pending.Signal);
                return false;
            }

            if (!Instance.IsX64Guest)
            {
                TerminateProcessForSignal(Instance, Pending.Signal);
                return false;
            }

            State.SignalNesting++;
            State.IsHandlingSignal = true;
            if (State.SignalNesting > 8)
            {
                TerminateProcessForSignal(Instance, SIGSEGV);
                return false;
            }

            ulong Restorer = ((Action.Flags & SA_RESTORER) != 0 && Action.Restorer != 0) ? Action.Restorer : Guest.GetOrCreateSignalRestorer(Instance);
            if (Restorer == 0)
            {
                TerminateProcessForSignal(Instance, SIGSEGV);
                return false;
            }

            bool WasOnSignalStack = State.SignalStackActive;
            ulong Frame = AllocateSignalFrame(Instance, State, Action.Flags);
            if (Frame == 0 || !WriteSignalFrame64(Instance, Thread.Context, State, Pending, Action, Restorer, Frame, WasOnSignalStack))
            {
                TerminateProcessForSignal(Instance, SIGSEGV);
                return false;
            }

            byte[] OldMask = (byte[])State.SignalMask.Clone();
            ApplySignalMaskForHandler(State, Action, Pending.Signal);
            WriteMask64(Instance, Frame + X64SavedMaskOffset, OldMask);

            if ((Action.Flags & SA_RESETHAND) != 0)
                Helper.SetSignalAction(Pending.Signal, null);

            ulong SigInfo = Frame + X64SigInfoOffset;
            ulong UContext = Frame + X64UContextOffset;
            Thread.Context.RIP = Action.Handler;
            Thread.Context.RSP = Frame;
            Thread.Context.RAX = 0;
            Thread.Context.RDI = (ulong)(uint)Pending.Signal;
            Thread.Context.RSI = (Action.Flags & SA_SIGINFO) != 0 ? SigInfo : 0;
            Thread.Context.RDX = (Action.Flags & SA_SIGINFO) != 0 ? UContext : 0;
            Thread.Context.RFLAGS &= ~(X86_EFLAGS_DF | X86_EFLAGS_TF | X86_EFLAGS_RF);
            Thread.State = EmulatedThreadState.Running;

            LoadContextIntoLiveRegisters(Instance, Thread.Context, State);
            return true;
        }

        public static bool RestoreSignalContext(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            LinuxThreadState State = GetOrCreateThreadState(Instance, Helper);
            EmulatedThread Thread = Instance.CurrentThread;
            if (State == null || Thread == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return false;
            }

            if (!Instance.IsX64Guest)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOSYS);
                return false;
            }

            ulong Rsp = Instance.ReadRegister(Registers.UC_X86_REG_RSP);
            ulong Frame = LocateSignalFrame64(Instance, Rsp);
            if (Frame == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return false;
            }

            CpuContext Saved = ReadContextFromUContext64(Instance, Frame + X64UContextOffset);
            Saved.FS = Instance.ReadMemoryULong(Frame + X64SavedContextOffset + 0x90);
            Saved.GS = Instance.ReadMemoryULong(Frame + X64SavedContextOffset + 0x98);
            ReadMask64(Instance, Frame + X64SavedMaskOffset, State.SignalMask);
            State.SignalStackActive = Instance.ReadMemory(Frame + X64SavedStackActiveOffset, 1)[0] != 0;
            if (State.SignalNesting > 0)
                State.SignalNesting--;

            State.IsHandlingSignal = State.SignalNesting > 0;
            State.DispatchSignal = false;
            State.SignalReturnCompleted = true;

            if (State.EpollWaitActive)
            {
                RestoreEpollWaitSignalMask(State);
                Saved.RIP = State.EpollWaitReturnRIP;
                Saved.RAX = unchecked((ulong)-(long)LinuxErrno.EINTR);
                ClearEpollWait(State);
                Thread.WaitActive = false;
                Thread.WaitHandles = null;
                Thread.WaitDeadline = -1;
                Thread.WaitTimedOut = false;
                Thread.WaitSatisfiedIndex = -1;
            }

            bool WasSigsuspendActive = State.SigsuspendActive;
            CompleteSigsuspendAfterSignal(State, Saved);
            if (WasSigsuspendActive)
            {
                Thread.WaitActive = false;
                Thread.WaitHandles = null;
                Thread.WaitDeadline = -1;
                Thread.WaitTimedOut = false;
                Thread.WaitSatisfiedIndex = -1;
            }

            TryActivatePendingSignal(State);

            if (Instance.IsX64Guest)
            {
                State.FsBase = Saved.FS;
                State.GsBase = Saved.GS;
            }

            Thread.Context = Saved;
            Thread.State = EmulatedThreadState.Ready;
            Thread.SwitchingContext = true;
            LoadContextIntoLiveRegisters(Instance, Saved, State);
            Instance.SuppressSyscallStatusWrite = true;
            Instance._emulator.StopEmulation();
            return true;
        }

        public static LinuxSignalStack ReadStackT(BinaryEmulator Instance, LinuxSyscallContext Context, ulong Address)
        {
            if (Context.Abi == SyscallAbi.X64)
            {
                byte[] Buffer = Instance.ReadMemory(Address, 24);
                return new LinuxSignalStack
                {
                    StackPointer = BinaryPrimitives.ReadUInt64LittleEndian(Buffer.AsSpan(0, 8)),
                    Flags = BinaryPrimitives.ReadInt32LittleEndian(Buffer.AsSpan(8, 4)),
                    Size = BinaryPrimitives.ReadUInt64LittleEndian(Buffer.AsSpan(16, 8))
                };
            }
            else
            {
                byte[] Buffer = Instance.ReadMemory(Address, 12);
                return new LinuxSignalStack
                {
                    StackPointer = BinaryPrimitives.ReadUInt32LittleEndian(Buffer.AsSpan(0, 4)),
                    Flags = BinaryPrimitives.ReadInt32LittleEndian(Buffer.AsSpan(4, 4)),
                    Size = BinaryPrimitives.ReadUInt32LittleEndian(Buffer.AsSpan(8, 4))
                };
            }
        }

        public static bool WriteStackT(BinaryEmulator Instance, LinuxSyscallContext Context, ulong Address, LinuxSignalStack Stack)
        {
            if (Context.Abi == SyscallAbi.X64)
            {
                Span<byte> Buffer = stackalloc byte[24];
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0, 8), Stack.StackPointer);
                BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(8, 4), Stack.Flags);
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(16, 8), Stack.Size);
                return Instance.WriteMemory(Address, Buffer);
            }
            else
            {
                Span<byte> Buffer = stackalloc byte[12];
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0, 4), (uint)Stack.StackPointer);
                BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(4, 4), Stack.Flags);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(8, 4), (uint)Stack.Size);
                return Instance.WriteMemory(Address, Buffer);
            }
        }

        private static LinuxSignalAction ReadSignalAction(LinuxSyscallsHelper Helper, SyscallAbi Abi, int Signal)
        {
            LinuxSignalAction Action = new LinuxSignalAction
            {
                Handler = SIG_DFL,
                Flags = 0,
                Restorer = 0,
                Mask = new byte[LinuxThreadState.SignalSetSize]
            };

            int Size = Abi == SyscallAbi.X64 ? 24 + LinuxThreadState.SignalSetSize : 12 + LinuxThreadState.SignalSetSize;
            byte[] Raw = Helper.GetSignalAction(Signal, Size);
            if (Abi == SyscallAbi.X64)
            {
                Action.Handler = BinaryPrimitives.ReadUInt64LittleEndian(Raw.AsSpan(0, 8));
                Action.Flags = BinaryPrimitives.ReadUInt64LittleEndian(Raw.AsSpan(8, 8));
                Action.Restorer = BinaryPrimitives.ReadUInt64LittleEndian(Raw.AsSpan(16, 8));
                Buffer.BlockCopy(Raw, 24, Action.Mask, 0, Math.Min(Action.Mask.Length, Raw.Length - 24));
            }
            else
            {
                Action.Handler = BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(0, 4));
                Action.Flags = BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(4, 4));
                Action.Restorer = BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(8, 4));
                Buffer.BlockCopy(Raw, 12, Action.Mask, 0, Math.Min(Action.Mask.Length, Raw.Length - 12));
            }

            return Action;
        }

        private static ulong AllocateSignalFrame(BinaryEmulator Instance, LinuxThreadState State, ulong Flags)
        {
            ulong StackPointer = Instance.ReadRegister(Registers.UC_X86_REG_RSP);
            LinuxSignalStack AltStack = State.AlternateSignalStack;
            bool UseAltStack = (Flags & SA_ONSTACK) != 0 &&
                               (AltStack.Flags & SS_DISABLE) == 0 &&
                               AltStack.StackPointer != 0 &&
                               AltStack.Size >= X64FrameSize &&
                               !State.SignalStackActive;

            if (UseAltStack)
            {
                StackPointer = AltStack.StackPointer + AltStack.Size;
                State.SignalStackActive = true;
            }

            StackPointer -= 128;
            ulong Frame = (StackPointer - X64FrameSize) & ~0xFUL;
            Frame -= 8;
            return Instance.IsRegionMapped(Frame, X64FrameSize) ? Frame : 0;
        }

        private static bool WriteSignalFrame64(BinaryEmulator Instance, CpuContext Context, LinuxThreadState State, LinuxPendingSignal Pending, LinuxSignalAction Action, ulong Restorer, ulong Frame, bool WasOnSignalStack)
        {
            Span<byte> Empty = stackalloc byte[256];
            Empty.Clear();
            for (int Offset = 0; Offset < X64FrameSize; Offset += Empty.Length)
            {
                int Count = Math.Min(Empty.Length, X64FrameSize - Offset);
                if (!Instance.WriteMemory(Frame + (ulong)Offset, Empty.Slice(0, Count)))
                    return false;
            }

            WriteU64(Instance, Frame, Restorer);
            WriteU64(Instance, Frame + 8, SignalFrameMagic);
            WriteU64(Instance, Frame + X64SavedSignalOffset, (ulong)(uint)Pending.Signal);
            WriteU64(Instance, Frame + X64SavedFaultOffset, Pending.FaultAddress);
            Instance.WriteMemory(Frame + X64SavedStackActiveOffset, new byte[] { WasOnSignalStack ? (byte)1 : (byte)0 });
            WriteContext64(Instance, Frame + X64SavedContextOffset, Context, State);
            WriteSigInfo64(Instance, Frame + X64SigInfoOffset, Pending);
            WriteUContext64(Instance, Frame + X64UContextOffset, Context, State, Pending.FaultAddress);
            return true;
        }

        private static void ApplySignalMaskForHandler(LinuxThreadState State, LinuxSignalAction Action, int Signal)
        {
            for (int i = 0; i < State.SignalMask.Length && i < Action.Mask.Length; i++)
                State.SignalMask[i] |= Action.Mask[i];

            if ((Action.Flags & (SA_NODEFER | SA_RESETHAND)) == 0)
                SetSignal(State.SignalMask, Signal);

            ClearUnblockableSignals(State.SignalMask);
        }

        private static void SetSignal(Span<byte> Mask, int Signal)
        {
            int Bit = Signal - 1;
            int ByteIndex = Bit >> 3;
            int BitIndex = Bit & 7;
            if ((uint)ByteIndex >= (uint)Mask.Length)
                return;

            Mask[ByteIndex] |= (byte)(1 << BitIndex);
        }

        private static void SetSignal(byte[] Mask, int Signal)
        {
            if (Mask == null)
                return;

            SetSignal(Mask.AsSpan(), Signal);
        }

        private static void ClearSignal(byte[] Mask, int Signal)
        {
            int Bit = Signal - 1;
            int ByteIndex = Bit >> 3;
            int BitIndex = Bit & 7;
            if ((uint)ByteIndex >= (uint)Mask.Length)
                return;

            Mask[ByteIndex] &= unchecked((byte)~(1 << BitIndex));
        }

        private static void TerminateProcessForSignal(BinaryEmulator Instance, int Signal)
        {
            int ExitCode = 128 + Signal;
            foreach (EmulatedThread Thread in Instance.Threads.Values)
            {
                if (Thread == null || Thread.State == EmulatedThreadState.Terminated)
                    continue;

                Thread.State = EmulatedThreadState.Terminated;
                Thread.ExitCode = ExitCode;
                if (Thread.Context != null)
                    Thread.Context.RAX = unchecked((ulong)ExitCode);
            }

            Instance.TriggerEventMessage($"[!] Linux process terminated by signal {Signal}.", LogFlags.Issues);
            Instance._emulator.StopEmulation();
        }

        private static ulong LocateSignalFrame64(BinaryEmulator Instance, ulong Rsp)
        {
            if (IsSignalFrame64(Instance, Rsp))
                return Rsp;

            if (Rsp >= 8 && IsSignalFrame64(Instance, Rsp - 8))
                return Rsp - 8;

            return 0;
        }

        private static bool IsSignalFrame64(BinaryEmulator Instance, ulong Address)
        {
            if (!Instance.IsRegionMapped(Address, 16))
                return false;

            return Instance.ReadMemoryULong(Address + 8) == SignalFrameMagic;
        }

        private static void WriteSigInfo64(BinaryEmulator Instance, ulong Address, LinuxPendingSignal Pending)
        {
            WriteI32(Instance, Address, Pending.Signal);
            WriteI32(Instance, Address + 4, 0);
            WriteI32(Instance, Address + 8, Pending.Code);
            WriteU64(Instance, Address + 16, Pending.FaultAddress);
        }

        private static void WriteUContext64(BinaryEmulator Instance, ulong Address, CpuContext Context, LinuxThreadState State, ulong FaultAddress)
        {
            WriteU64(Instance, Address, 0);
            WriteU64(Instance, Address + 8, 0);
            WriteU64(Instance, Address + 0x10, State.AlternateSignalStack.StackPointer);
            WriteI32(Instance, Address + 0x18, State.SignalStackActive ? SS_ONSTACK : State.AlternateSignalStack.Flags);
            WriteU64(Instance, Address + 0x20, State.AlternateSignalStack.Size);
            WriteGRegs64(Instance, Address + 0x28, Context, State, FaultAddress);
        }

        private static void WriteGRegs64(BinaryEmulator Instance, ulong Address, CpuContext Context, LinuxThreadState State, ulong FaultAddress)
        {
            WriteGReg(Instance, Address, REG_R8, Context.R8);
            WriteGReg(Instance, Address, REG_R9, Context.R9);
            WriteGReg(Instance, Address, REG_R10, Context.R10);
            WriteGReg(Instance, Address, REG_R11, Context.R11);
            WriteGReg(Instance, Address, REG_R12, Context.R12);
            WriteGReg(Instance, Address, REG_R13, Context.R13);
            WriteGReg(Instance, Address, REG_R14, Context.R14);
            WriteGReg(Instance, Address, REG_R15, Context.R15);
            WriteGReg(Instance, Address, REG_RDI, Context.RDI);
            WriteGReg(Instance, Address, REG_RSI, Context.RSI);
            WriteGReg(Instance, Address, REG_RBP, Context.RBP);
            WriteGReg(Instance, Address, REG_RBX, Context.RBX);
            WriteGReg(Instance, Address, REG_RDX, Context.RDX);
            WriteGReg(Instance, Address, REG_RAX, Context.RAX);
            WriteGReg(Instance, Address, REG_RCX, Context.RCX);
            WriteGReg(Instance, Address, REG_RSP, Context.RSP);
            WriteGReg(Instance, Address, REG_RIP, Context.RIP);
            WriteGReg(Instance, Address, REG_EFL, Context.RFLAGS);
            WriteGReg(Instance, Address, REG_CR2, FaultAddress);
        }

        private static CpuContext ReadContextFromUContext64(BinaryEmulator Instance, ulong UContext)
        {
            ulong GRegs = UContext + 0x28;
            return new CpuContext
            {
                R8 = ReadGReg(Instance, GRegs, REG_R8),
                R9 = ReadGReg(Instance, GRegs, REG_R9),
                R10 = ReadGReg(Instance, GRegs, REG_R10),
                R11 = ReadGReg(Instance, GRegs, REG_R11),
                R12 = ReadGReg(Instance, GRegs, REG_R12),
                R13 = ReadGReg(Instance, GRegs, REG_R13),
                R14 = ReadGReg(Instance, GRegs, REG_R14),
                R15 = ReadGReg(Instance, GRegs, REG_R15),
                RDI = ReadGReg(Instance, GRegs, REG_RDI),
                RSI = ReadGReg(Instance, GRegs, REG_RSI),
                RBP = ReadGReg(Instance, GRegs, REG_RBP),
                RBX = ReadGReg(Instance, GRegs, REG_RBX),
                RDX = ReadGReg(Instance, GRegs, REG_RDX),
                RAX = ReadGReg(Instance, GRegs, REG_RAX),
                RCX = ReadGReg(Instance, GRegs, REG_RCX),
                RSP = ReadGReg(Instance, GRegs, REG_RSP),
                RIP = ReadGReg(Instance, GRegs, REG_RIP),
                RFLAGS = ReadGReg(Instance, GRegs, REG_EFL),
                FS = 0,
                GS = 0
            };
        }

        private static void WriteContext64(BinaryEmulator Instance, ulong Address, CpuContext Context, LinuxThreadState State)
        {
            WriteU64(Instance, Address + 0x00, Context.RAX);
            WriteU64(Instance, Address + 0x08, Context.RBX);
            WriteU64(Instance, Address + 0x10, Context.RCX);
            WriteU64(Instance, Address + 0x18, Context.RDX);
            WriteU64(Instance, Address + 0x20, Context.RSI);
            WriteU64(Instance, Address + 0x28, Context.RDI);
            WriteU64(Instance, Address + 0x30, Context.RBP);
            WriteU64(Instance, Address + 0x38, Context.RSP);
            WriteU64(Instance, Address + 0x40, Context.R8);
            WriteU64(Instance, Address + 0x48, Context.R9);
            WriteU64(Instance, Address + 0x50, Context.R10);
            WriteU64(Instance, Address + 0x58, Context.R11);
            WriteU64(Instance, Address + 0x60, Context.R12);
            WriteU64(Instance, Address + 0x68, Context.R13);
            WriteU64(Instance, Address + 0x70, Context.R14);
            WriteU64(Instance, Address + 0x78, Context.R15);
            WriteU64(Instance, Address + 0x80, Context.RIP);
            WriteU64(Instance, Address + 0x88, Context.RFLAGS);
            WriteU64(Instance, Address + 0x90, State.FsBase);
            WriteU64(Instance, Address + 0x98, State.GsBase);
        }

        private static void LoadContextIntoLiveRegisters(BinaryEmulator Instance, CpuContext Context, LinuxThreadState State)
        {
            Instance.WriteRegister(Registers.UC_X86_REG_RAX, Context.RAX);
            Instance.WriteRegister(Registers.UC_X86_REG_RBX, Context.RBX);
            Instance.WriteRegister(Registers.UC_X86_REG_RCX, Context.RCX);
            Instance.WriteRegister(Registers.UC_X86_REG_RDX, Context.RDX);
            Instance.WriteRegister(Registers.UC_X86_REG_RSI, Context.RSI);
            Instance.WriteRegister(Registers.UC_X86_REG_RDI, Context.RDI);
            Instance.WriteRegister(Registers.UC_X86_REG_RBP, Context.RBP);
            Instance.WriteRegister(Registers.UC_X86_REG_RSP, Context.RSP);
            Instance.WriteRegister(Registers.UC_X86_REG_R8, Context.R8);
            Instance.WriteRegister(Registers.UC_X86_REG_R9, Context.R9);
            Instance.WriteRegister(Registers.UC_X86_REG_R10, Context.R10);
            Instance.WriteRegister(Registers.UC_X86_REG_R11, Context.R11);
            Instance.WriteRegister(Registers.UC_X86_REG_R12, Context.R12);
            Instance.WriteRegister(Registers.UC_X86_REG_R13, Context.R13);
            Instance.WriteRegister(Registers.UC_X86_REG_R14, Context.R14);
            Instance.WriteRegister(Registers.UC_X86_REG_R15, Context.R15);
            Instance.WriteRegister(Registers.UC_X86_REG_RIP, Context.RIP);
            Instance.WriteRegister(Registers.UC_X86_REG_EFLAGS, Context.RFLAGS == 0 ? 0x202 : Context.RFLAGS);
            Instance.WriteRegister(Registers.UC_X86_REG_FS_BASE, State.FsBase);
            Instance.WriteRegister(Registers.UC_X86_REG_GS_BASE, State.GsBase);
        }

        private static void WriteMask64(BinaryEmulator Instance, ulong Address, byte[] Mask)
        {
            Span<byte> Buffer = stackalloc byte[LinuxThreadState.SignalSetSize];
            Buffer.Clear();
            if (Mask != null)
                Mask.AsSpan(0, Math.Min(Mask.Length, Buffer.Length)).CopyTo(Buffer);
            Instance.WriteMemory(Address, Buffer);
        }

        private static void ReadMask64(BinaryEmulator Instance, ulong Address, byte[] Mask)
        {
            if (Mask == null)
                return;

            byte[] Buffer = Instance.ReadMemory(Address, (uint)Math.Min(Mask.Length, LinuxThreadState.SignalSetSize));
            Array.Clear(Mask, 0, Mask.Length);
            System.Buffer.BlockCopy(Buffer, 0, Mask, 0, Math.Min(Buffer.Length, Mask.Length));
        }

        private static void WriteGReg(BinaryEmulator Instance, ulong Address, int Index, ulong Value)
        {
            WriteU64(Instance, Address + (ulong)(Index * 8), Value);
        }

        private static ulong ReadGReg(BinaryEmulator Instance, ulong Address, int Index)
        {
            return Instance.ReadMemoryULong(Address + (ulong)(Index * 8));
        }

        private static void WriteU64(BinaryEmulator Instance, ulong Address, ulong Value)
        {
            Span<byte> Buffer = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer, Value);
            Instance.WriteMemory(Address, Buffer);
        }

        private static void WriteI32(BinaryEmulator Instance, ulong Address, int Value)
        {
            Span<byte> Buffer = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(Buffer, Value);
            Instance.WriteMemory(Address, Buffer);
        }
    }


    internal static class LinuxSignalSyscallHelpers
    {
        public static void HandleThreadSignal(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, int Tgid, int Tid, int Signal, bool IgnoreTgid)
        {
            if (Signal < 0 || Signal >= LinuxThreadState.SignalCount)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (!IgnoreTgid && Tgid != Helper.PID)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ESRCH);
                return;
            }

            if (!Instance.Threads.TryGetValue(unchecked((uint)Tid), out EmulatedThread Thread) || Thread == null || Thread.State == EmulatedThreadState.Terminated)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ESRCH);
                return;
            }

            if (Signal != 0)
            {
                LinuxSignalHelpers.QueueSignal(Instance, Helper, Thread, new LinuxPendingSignal
                {
                    Signal = Signal,
                    Code = -6,
                    FaultAddress = 0,
                    MemoryAccess = default
                });
            }

            Helper.SetReturnValue(Instance, Context, 0L);
        }
    }

}