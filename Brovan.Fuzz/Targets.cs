// The oracles are the guard pages, a native crash, -timeout and -rss_limit_mb. A managed exception
// is not one: HandleGenIoctl catches Exception, so a throw is the parser rejecting input as designed.
// -rss_limit_mb being an oracle is why the per-iteration paths hold no allocation.

using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Brovan.Core.Emulation;
using Brovan.Core.Emulation.OS.Windows;

namespace Brovan.Fuzz;

internal sealed unsafe class GuardedRegion : IDisposable
{
    private const nuint Page = 4096;

    private IntPtr _region;
    private nuint _total;
    private byte* _guard;

    public int Capacity { get; }

    public GuardedRegion(int capacity)
    {
        nuint span = ((nuint)capacity + Page - 1) / Page * Page;
        if (span == 0) span = Page;
        Capacity = (int)span;
        _total = span + Page;

        _region = Native.mmap(IntPtr.Zero, _total, Native.PROT_READ | Native.PROT_WRITE,
                              Native.MAP_PRIVATE | Native.MAP_ANONYMOUS, -1, 0);
        if (_region == IntPtr.Zero || _region == new IntPtr(-1))
            throw new InvalidOperationException("guarded region mmap failed");

        Native.mprotect(_region + (int)span, Page, Native.PROT_NONE);
        _guard = (byte*)_region + (int)span;
    }

    /// <summary>Copies the payload so its last byte sits against the guard page.</summary>
    public byte* Place(ReadOnlySpan<byte> payload)
    {
        if (payload.Length > Capacity)
            payload = payload[..Capacity];
        byte* dst = _guard - payload.Length;
        payload.CopyTo(new Span<byte>(dst, payload.Length));
        return dst;
    }

    public void Dispose()
    {
        if (_region != IntPtr.Zero) { Native.munmap(_region, _total); _region = IntPtr.Zero; _guard = null; }
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

internal static class StructTarget
{
    private static readonly GenReader Reader = new();

    // RebuildAt only reads the handle tables and allocates from the arena, so one is reusable.
    private static readonly GenState State = new();

    private static byte[] _payload = new byte[1 << 16];

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 3)
            return;

        int sid = (data[0] | (data[1] << 8)) % Grammar.StructCount;
        ReadOnlySpan<byte> body = data[2..];

        if (body.Length > _payload.Length)
            _payload = new byte[Math.Max(body.Length, _payload.Length * 2)];
        body.CopyTo(_payload);

        Reader.Reset(_payload, 0, body.Length);
        try
        {
            BrovVulkGenStruct.Rebuild(sid, Reader, State);
        }
        catch (Exception e) when (Expected(e))
        {
        }
        finally
        {
            State.FreeCallAllocs();
        }
    }

    internal static bool Expected(Exception e) =>
        e is InvalidOperationException
          or IndexOutOfRangeException
          or ArgumentOutOfRangeException
          or ArgumentException
          or OverflowException
          or NullReferenceException;
}

/// <summary>The SPIR-V entry points reached from vkCreateShaderModule and the pipeline stand-ins.</summary>
internal static class SpirvTarget
{
    private const int MaxModuleBytes = 1 << 20;
    private static readonly GuardedRegion Region = new(MaxModuleBytes);

    public static unsafe void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 5)
            return;

        byte mode = data[0];
        ReadOnlySpan<byte> body = data[1..];
        int words = Math.Min(body.Length, Region.Capacity) / 4;
        if (words < 5)
            return;

        uint* w = (uint*)Region.Place(body[..(words * 4)]);

        // Without the magic every parser returns at once, so keep most inputs carrying it.
        if ((mode & 0x80) == 0)
            w[0] = Spirv.Magic;

        try
        {
            switch (mode & 0x03)
            {
                case 0:
                {
                    SpirvRelocation where = new((mode & 0x04) != 0 ? 4 : -1,
                                                (mode & 0x08) != 0 ? 8 : -1,
                                                (mode & 0x10) != 0 ? 12 : -1);
                    Spirv.Relocate(w, words, where, out _);
                    break;
                }
                case 1:
                {
                    uint model = (uint)((mode >> 2) & 0x07);
                    SpirvInterface? iface = Spirv.ParseInterface(w, words, model, null);
                    if (iface != null)
                        SpirvPassThrough.Build(iface, (mode & 0x20) != 0, (mode & 0x40) != 0, true, true);
                    break;
                }
                case 2:
                {
                    int location = (mode >> 2) & 0x0F;
                    int elements = 1 + ((mode >> 6) & 0x03);
                    SpirvClipDiscard.Build(w, words, location, elements);
                    break;
                }
                default:
                {
                    // A pipeline create relocates in place and then parses the result.
                    Spirv.Relocate(w, words, new SpirvRelocation(4, 8, 12), out SpirvModuleInfo info);
                    if (!info.Left)
                        Spirv.ParseInterface(w, words, 0, null);
                    break;
                }
            }
        }
        catch (Exception e) when (StructTarget.Expected(e))
        {
        }
    }
}

internal static class IoctlTarget
{
    private const uint IoctlBrovVulkGen = 0x80002004;

    private static FuzzGuest? _guest;
    private static BrovVulkDevice? _device;
    private static long _iterations;

    private static byte[] _input = new byte[1 << 16];
    private static readonly byte[] Output = new byte[1 << 16];

    // Nothing an iteration creates is ever destroyed, so both are rebuilt on a fixed period.
    private const long RecycleEvery = 4000;

    public static void Init()
    {
        VulkanBootstrap.TryInitialise();
        Recycle();
    }

    private static void Recycle()
    {
        _guest?.Dispose();
        _guest = new FuzzGuest();
        // The arena behind a dropped GenState is unmanaged, so the collector never returns it.
        _device?.GenState.Dispose();
        _device = new BrovVulkDevice();
        VulkanBootstrap.ReopenDevice();
        VulkanBootstrap.Register(_device.GenState);
    }

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 13 || _device == null || _guest == null)
            return;

        if (Interlocked.Increment(ref _iterations) % RecycleEvery == 0)
        {
            Recycle();
            if (_device == null || _guest == null)
                return;
        }

        // The first five bytes steer the harness. The rest is what the guest hands the ioctl.
        byte knobs = data[0];
        _guest.AllowShareBacking = (knobs & 1) != 0;
        _guest.Flags = (knobs & 2) != 0 ? LogFlags.Issues : default;
        _guest.ResetDirty((byte)(knobs & 0xFC));
        VulkanBootstrap.SetStandIns(_device.GenState,
            (int)BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(1, 4)));

        ReadOnlySpan<byte> body = data[5..];
        if (body.Length > _input.Length)
            _input = new byte[Math.Max(body.Length, _input.Length * 2)];
        body.CopyTo(_input);

        DeviceData dd = new()
        {
            InputBuffer = _input,
            InputLength = (uint)body.Length,
            OutputBuffer = Output,
            OutputLength = (uint)Output.Length,
        };

        try
        {
            _device.HandleIoctl(IoctlBrovVulkGen, ref dd, _guest);
        }
        catch (Exception e) when (StructTarget.Expected(e))
        {
        }
    }
}

// Without these the ioctl target reaches the framing and the reader and nothing else.
internal static unsafe class VulkanBootstrap
{
    public static bool Available { get; private set; }
    public static IntPtr Instance, PhysicalDevice, Device, Queue, Surface;

    private const string VK = "libvulkan.so.1";
    [DllImport(VK)] private static extern int vkCreateInstance(void* ci, IntPtr alloc, out IntPtr instance);
    [DllImport(VK)] private static extern int vkEnumeratePhysicalDevices(IntPtr inst, ref uint count, IntPtr* pds);
    [DllImport(VK)] private static extern int vkCreateDevice(IntPtr pd, void* ci, IntPtr alloc, out IntPtr dev);
    [DllImport(VK)] private static extern void vkDestroyDevice(IntPtr dev, IntPtr alloc);
    [DllImport(VK)] private static extern int vkDeviceWaitIdle(IntPtr dev);
    [DllImport(VK)] private static extern void vkGetDeviceQueue(IntPtr dev, uint family, uint index, out IntPtr queue);
    [DllImport(VK)] private static extern int vkEnumerateInstanceVersion(out uint version);
    [DllImport(VK)] private static extern IntPtr vkGetInstanceProcAddr(IntPtr instance, IntPtr name);
    [DllImport(VK)] private static extern int vkEnumerateInstanceExtensionProperties(IntPtr layer, ref uint count, IntPtr props);
    [DllImport(VK)] private static extern int vkEnumerateDeviceExtensionProperties(IntPtr pd, IntPtr layer, ref uint count, IntPtr props);

    public static void TryInitialise()
    {
        if (Instance != IntPtr.Zero)
            return;

        try
        {
            // The loader leaves a device dispatch slot NULL unless the instance asked for the core
            // version the command was promoted in. BrovVulkGenDispatch raises it the same way.
            uint api = (1u << 22) | (1u << 12);
            if (vkEnumerateInstanceVersion(out uint loader) >= 0 && loader > api)
                api = loader;

            byte* app = stackalloc byte[48]; new Span<byte>(app, 48).Clear();
            *(uint*)(app + 44) = api;

            IntPtr instExt = Extensions(IntPtr.Zero, out uint instExtCount);

            byte* ici = stackalloc byte[64]; new Span<byte>(ici, 64).Clear();
            *(int*)ici = 1;
            *(void**)(ici + 24) = app;
            *(uint*)(ici + 48) = instExtCount;
            *(IntPtr*)(ici + 56) = instExt;
            if (vkCreateInstance(ici, IntPtr.Zero, out IntPtr inst) != 0)
            {
                *(uint*)(ici + 48) = 0;
                *(IntPtr*)(ici + 56) = IntPtr.Zero;
                if (vkCreateInstance(ici, IntPtr.Zero, out inst) != 0)
                    return;
            }

            uint n = 0;
            vkEnumeratePhysicalDevices(inst, ref n, null);
            if (n == 0)
                return;
            IntPtr* pds = stackalloc IntPtr[(int)n];
            vkEnumeratePhysicalDevices(inst, ref n, pds);

            Instance = inst;
            PhysicalDevice = pds[0];
            BrovVulkProc.HostInstance = inst;
            Available = OpenDevice();
        }
        catch
        {
            // No loader or no ICD. The target still covers framing and the reader.
            Available = false;
        }
    }

    public static void ReopenDevice()
    {
        if (Instance == IntPtr.Zero)
            return;
        if (Device != IntPtr.Zero)
        {
            vkDeviceWaitIdle(Device);
            vkDestroyDevice(Device, IntPtr.Zero);
            Device = Queue = IntPtr.Zero;
        }
        Available = OpenDevice();
        OpenSurface();
    }

    private const uint HeadlessSurfaceCreateInfo = 1000256000;

    // Every surface-taking query dereferences the handle in the loader, so without a real one in the
    // table each of them stops at its handle lookup. VK_EXT_headless_surface needs no window system.
    private static void OpenSurface()
    {
        if (Instance == IntPtr.Zero)
            return;

        IntPtr name = Marshal.StringToHGlobalAnsi("vkCreateHeadlessSurfaceEXT");
        IntPtr proc;
        try { proc = vkGetInstanceProcAddr(Instance, name); }
        finally { Marshal.FreeHGlobal(name); }

        if (proc == IntPtr.Zero)
            return;

        byte* ci = stackalloc byte[24]; new Span<byte>(ci, 24).Clear();
        *(uint*)ci = HeadlessSurfaceCreateInfo;

        // The one this replaces is left alone. vkDestroySurfaceKHR is reachable from an input, so the
        // harness cannot tell whether its own handle is still live, and the object is a few hundred
        // bytes against -rss_limit_mb.
        IntPtr surface = IntPtr.Zero;
        if (((delegate* unmanaged[Cdecl]<IntPtr, void*, IntPtr, IntPtr*, int>)proc)(Instance, ci, IntPtr.Zero, &surface) == 0)
            Surface = surface;
    }

    private static bool OpenDevice()
    {
        float prio = 1f;
        byte* q = stackalloc byte[40]; new Span<byte>(q, 40).Clear();
        *(int*)q = 2; *(uint*)(q + 24) = 1; *(void**)(q + 32) = &prio;

        // The loader aborts the process when a command from an extension the device did not enable
        // reaches a NULL driver slot.
        IntPtr devExt = Extensions(PhysicalDevice, out uint devExtCount);

        byte* dci = stackalloc byte[72]; new Span<byte>(dci, 72).Clear();
        *(int*)dci = 3; *(uint*)(dci + 20) = 1; *(void**)(dci + 24) = q;
        *(uint*)(dci + 48) = devExtCount;
        *(IntPtr*)(dci + 56) = devExt;
        if (vkCreateDevice(PhysicalDevice, dci, IntPtr.Zero, out IntPtr dev) != 0)
        {
            *(uint*)(dci + 48) = 0;
            *(IntPtr*)(dci + 56) = IntPtr.Zero;
            if (vkCreateDevice(PhysicalDevice, dci, IntPtr.Zero, out dev) != 0)
                return false;
        }

        Device = dev;
        vkGetDeviceQueue(dev, 0, 0, out Queue);
        return true;
    }

    private const int ExtensionPropertiesSize = 260;

    private static IntPtr Extensions(IntPtr physicalDevice, out uint count)
    {
        count = 0;
        if (Cached.TryGetValue(physicalDevice, out (IntPtr Names, uint Count) hit))
        {
            count = hit.Count;
            return hit.Names;
        }

        uint n = 0;
        if (Enumerate(physicalDevice, ref n, IntPtr.Zero) < 0 || n == 0 || n > 4096)
            return IntPtr.Zero;

        IntPtr props = Marshal.AllocHGlobal((int)n * ExtensionPropertiesSize);
        IntPtr names;
        try
        {
            if (Enumerate(physicalDevice, ref n, props) < 0)
                return IntPtr.Zero;
            names = Marshal.AllocHGlobal((int)n * IntPtr.Size);
            for (uint k = 0; k < n; k++)
                *(IntPtr*)(names + (int)(k * (uint)IntPtr.Size)) =
                    Marshal.StringToHGlobalAnsi(Marshal.PtrToStringAnsi(props + (int)(k * ExtensionPropertiesSize)));
        }
        finally
        {
            Marshal.FreeHGlobal(props);
        }

        Cached[physicalDevice] = (names, n);
        count = n;
        return names;
    }

    private static readonly Dictionary<IntPtr, (IntPtr Names, uint Count)> Cached = new();

    private static int Enumerate(IntPtr physicalDevice, ref uint count, IntPtr props) =>
        physicalDevice == IntPtr.Zero
            ? vkEnumerateInstanceExtensionProperties(IntPtr.Zero, ref count, props)
            : vkEnumerateDeviceExtensionProperties(physicalDevice, IntPtr.Zero, ref count, props);

    /// <summary>Fills the handle table with ids 1 to 5, the order the seed corpus assumes.</summary>
    public static void Register(GenState st)
    {
        if (!Available)
            return;
        st.Register(Instance, "VkInstance");
        st.Register(PhysicalDevice, "VkPhysicalDevice");
        st.Register(Device, "VkDevice");
        st.Register(Queue, "VkQueue");
        st.SetDevicePhysical(Device, PhysicalDevice);
        st.Register(Surface, "VkSurfaceKHR");
    }

    public static void SetStandIns(GenState st, int bits)
    {
        if (Available)
            st.SetDeviceStandIns(Device, bits);
    }
}
