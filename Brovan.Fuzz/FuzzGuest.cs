// The window sits between PROT_NONE pages so an access past the end faults where libFuzzer sees it.

using System.Runtime.InteropServices;
using Brovan.Core.Emulation;
using Brovan.Core.Emulation.OS.SharedHelpers;

namespace Brovan.Fuzz;

internal sealed unsafe class FuzzGuest : IGuestMemory, IDisposable
{
    public const ulong GuestBase = 0x4000_0000UL;
    public const ulong GuestSize = 8UL << 20;
    private const nuint Page = 4096;

    private static readonly byte[] Fills = { 0x00, 0xFF, 0xA5, 0x80 };

    private readonly IntPtr[] _regions = new IntPtr[Fills.Length];
    private readonly bool[] _filled = new bool[Fills.Length];
    private int _window;
    private byte* _guest;

    public bool AllowShareBacking;

    public LogFlags Flags = default;

    public long RefusedReads, RefusedWrites;

    private ulong _dirtyLow = ulong.MaxValue;
    private ulong _dirtyHigh;

    public FuzzGuest()
    {
        nuint total = (nuint)GuestSize + Page * 2;
        for (int i = 0; i < _regions.Length; i++)
        {
            IntPtr region = Native.mmap(IntPtr.Zero, total, Native.PROT_READ | Native.PROT_WRITE,
                                        Native.MAP_PRIVATE | Native.MAP_ANONYMOUS, -1, 0);
            if (region == IntPtr.Zero || region == new IntPtr(-1))
                throw new InvalidOperationException("guest address space mmap failed");

            Native.mprotect(region, Page, Native.PROT_NONE);
            Native.mprotect(region + (int)((nuint)GuestSize + Page), Page, Native.PROT_NONE);
            _regions[i] = region;
        }

        _filled[0] = true;
        _guest = (byte*)_regions[0] + Page;
    }

    // BinaryEmulator.IsRegionMapped tests overlap, not containment.
    private static bool Overlaps(ulong Address, ulong Size)
    {
        if (Size == 0)
            return false;
        ulong end = Address + Size < Address ? ulong.MaxValue : Address + Size;
        return Address < GuestBase + GuestSize && end > GuestBase;
    }

    private static bool Contains(ulong Address, ulong Size)
    {
        if (Address < GuestBase)
            return false;
        ulong offset = Address - GuestBase;
        return offset <= GuestSize && Size <= GuestSize - offset;
    }

    private void Dirty(ulong offset, ulong end)
    {
        if (offset < _dirtyLow)
            _dirtyLow = offset;
        if (end > _dirtyHigh)
            _dirtyHigh = end;
    }

    public bool IsRegionMapped(ulong Address, ulong Size) => Overlaps(Address, Size);

    public IntPtr GetHostPointer(ulong Address, ulong Size)
    {
        if (!Contains(Address, Size))
            return IntPtr.Zero;
        // The caller can write through the pointer without going through WriteMemory.
        ulong offset = Address - GuestBase;
        Dirty(offset, offset + Size);
        return (IntPtr)(_guest + offset);
    }

    public bool ReadMemory(ulong Address, Span<byte> Destination)
    {
        if (!Contains(Address, (ulong)Destination.Length))
        {
            RefusedReads++;
            return false;
        }
        new ReadOnlySpan<byte>(_guest + (Address - GuestBase), Destination.Length).CopyTo(Destination);
        return true;
    }

    public bool WriteMemory(ulong Address, ReadOnlySpan<byte> Source)
    {
        if (!Contains(Address, (ulong)Source.Length))
        {
            RefusedWrites++;
            return false;
        }
        ulong offset = Address - GuestBase;
        Source.CopyTo(new Span<byte>(_guest + offset, Source.Length));
        Dirty(offset, offset + (ulong)Source.Length);
        return true;
    }

    // The harness cannot remap its window. Refusing drives the copy path, accepting the aliased one.
    public bool RebackRegionWithHostMemory(ulong BaseAddress, ulong Size, IntPtr HostPointer)
    {
        if (HostPointer == IntPtr.Zero || Size == 0)
            return false;
        if ((BaseAddress & (Page - 1)) != 0 || (Size & (Page - 1)) != 0)
            return false;
        return AllowShareBacking && Contains(BaseAddress, Size);
    }

    public bool RestoreRegionBacking(ulong BaseAddress, ulong Size)
    {
        if (Size == 0 || (BaseAddress & (Page - 1)) != 0 || (Size & (Page - 1)) != 0)
            return false;
        return Contains(BaseAddress, Size);
    }

    public LogFlags GuestLogFlags => Flags;

    public void TriggerEventMessage(string Message, LogFlags FlagType) { }

    public DpiAwareness GuestDpiAwareness => DpiAwareness.PerMonitor;

    public IntPtr EnsureHostWindowHandle(ulong GuestHwnd) => IntPtr.Zero;

    public void EnsureHostXlibSurfaceHandles(out IntPtr Connection, out IntPtr Window)
    {
        Connection = IntPtr.Zero;
        Window = IntPtr.Zero;
    }

    public ulong AddSharedGpuMemoryHandle(SafeHandle Host)
    {
        Host.Dispose();
        return 0;
    }

    public SafeHandle? FindSharedGpuMemoryHandle(ulong GuestHandle) => null;

    public static int WindowCount => Fills.Length;

    public void ResetDirty(int window)
    {
        if (_dirtyHigh > _dirtyLow)
            new Span<byte>(_guest + _dirtyLow, (int)(Math.Min(_dirtyHigh, GuestSize) - _dirtyLow)).Fill(Fills[_window]);
        _dirtyLow = ulong.MaxValue;
        _dirtyHigh = 0;

        if (!_filled[window])
        {
            new Span<byte>((byte*)_regions[window] + Page, (int)GuestSize).Fill(Fills[window]);
            _filled[window] = true;
        }
        _window = window;
        _guest = (byte*)_regions[window] + Page;

        RefusedReads = 0;
        RefusedWrites = 0;
    }

    public void Dispose()
    {
        for (int i = 0; i < _regions.Length; i++)
        {
            if (_regions[i] == IntPtr.Zero)
                continue;
            Native.munmap(_regions[i], (nuint)GuestSize + Page * 2);
            _regions[i] = IntPtr.Zero;
        }
        _guest = null;
    }

    private static class Native
    {
        internal const int PROT_NONE = 0, PROT_READ = 1, PROT_WRITE = 2;
        internal const int MAP_PRIVATE = 2, MAP_ANONYMOUS = 0x20;

        [DllImport("libc", SetLastError = true)]
        internal static extern IntPtr mmap(IntPtr addr, nuint length, int prot, int flags, int fd, nint offset);
        [DllImport("libc", SetLastError = true)]
        internal static extern int mprotect(IntPtr addr, nuint len, int prot);
        [DllImport("libc", SetLastError = true)]
        internal static extern int munmap(IntPtr addr, nuint length);
    }
}
