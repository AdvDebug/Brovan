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

    private IntPtr _region;
    private byte* _guest;

    public bool AllowShareBacking;

    public LogFlags Flags = default;

    public long RefusedReads, RefusedWrites;

    // Repainting the whole window between iterations costs more than the iteration itself.
    private ulong _dirtyHigh;

    public FuzzGuest()
    {
        nuint total = (nuint)GuestSize + Page * 2;
        _region = Native.mmap(IntPtr.Zero, total, Native.PROT_READ | Native.PROT_WRITE,
                              Native.MAP_PRIVATE | Native.MAP_ANONYMOUS, -1, 0);
        if (_region == IntPtr.Zero || _region == new IntPtr(-1))
            throw new InvalidOperationException("guest address space mmap failed");

        Native.mprotect(_region, Page, Native.PROT_NONE);
        Native.mprotect(_region + (int)((nuint)GuestSize + Page), Page, Native.PROT_NONE);
        _guest = (byte*)_region + Page;
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

    public bool IsRegionMapped(ulong Address, ulong Size) => Overlaps(Address, Size);

    public IntPtr GetHostPointer(ulong Address, ulong Size)
    {
        if (!Contains(Address, Size))
            return IntPtr.Zero;
        // The caller can write through the pointer without going through WriteMemory.
        ulong end = (Address - GuestBase) + Size;
        if (end > _dirtyHigh)
            _dirtyHigh = end;
        return (IntPtr)(_guest + (Address - GuestBase));
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
        ulong end = offset + (ulong)Source.Length;
        if (end > _dirtyHigh)
            _dirtyHigh = end;
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

    public IntPtr EnsureHostWindowHandle() => IntPtr.Zero;

    public void EnsureHostXlibSurfaceHandles(out IntPtr Connection, out IntPtr Window)
    {
        Connection = IntPtr.Zero;
        Window = IntPtr.Zero;
    }

    public void ResetDirty(byte Fill)
    {
        if (_dirtyHigh != 0)
        {
            new Span<byte>(_guest, (int)Math.Min(_dirtyHigh, GuestSize)).Fill(Fill);
            _dirtyHigh = 0;
        }
        else if (_lastFill != Fill)
        {
            new Span<byte>(_guest, (int)GuestSize).Fill(Fill);
        }

        _lastFill = Fill;
        RefusedReads = 0;
        RefusedWrites = 0;
    }

    private byte _lastFill;

    public void Dispose()
    {
        if (_region != IntPtr.Zero)
        {
            Native.munmap(_region, (nuint)GuestSize + Page * 2);
            _region = IntPtr.Zero;
            _guest = null;
        }
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
