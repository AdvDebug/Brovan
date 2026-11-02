// The oracles are the guard pages, a native crash, -timeout and -rss_limit_mb. A managed exception
// is not one: HandleGenIoctl catches Exception, so a throw is the parser rejecting input as designed.
// -rss_limit_mb being an oracle is why the per-iteration paths hold no allocation.

using System.Buffers.Binary;
using System.Numerics;
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

// Edge coverage cannot distinguish struct kinds or uninstrumented driver results.
internal static unsafe class Feedback
{
    public const uint StructRead = 1, CommandResult = 2, CommandOutput = 3, ValidationMessage = 4;

    public static void Add(uint kind, uint a, uint b)
    {
        byte* map = SharpFuzz.Common.Trace.SharedMem;
        if (map == null)
            return;
        uint h = kind * 0x9E3779B1u ^ a * 0x85EBCA77u ^ b * 0xC2B2AE3Du;
        map[(h ^ h >> 16) & 0xFFFF]++;
    }

    public static uint Bucket(int bytes) => bytes < 64 ? (uint)bytes : 64 + (uint)BitOperations.Log2((uint)bytes);
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
        uint outcome = 0;
        try
        {
            BrovVulkGenStruct.Rebuild(sid, Reader, State);
        }
        catch (Exception e) when (Expected(e))
        {
            outcome = e is IndexOutOfRangeException ? 2u : 1u;
        }
        finally
        {
            State.FreeCallAllocs();
        }
        Feedback.Add(Feedback.StructRead, (uint)sid, Feedback.Bucket(Reader.Offset) | outcome << 8);
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

    // Rewind forgets handles without destroying host objects.
    private const long RecycleEvery = 4000;

    private static readonly List<(uint Id, string Type, IntPtr Ptr)> Made = new();
    private static readonly Dictionary<string, uint> FirstOfType = new(StringComparer.Ordinal);
    private static uint _mark;

    [Flags]
    private enum Restore : byte
    {
        None = 0,
        Recording = 1,
        Sync = 2,
    }

    private static readonly Restore[] Restores = new Restore[BrovVulkApi.CommandCount];

    public static uint NextId => _mark;

    public static uint HandleOf(string type) => FirstOfType.TryGetValue(type, out uint id) ? id : 0;

    public static void Init()
    {
        if (_device != null)
            return;

        // Generated core imports use vulkan-1.dll on every host.
        NativeLibraryResolver.Register();

        // Reset recording to close render passes, queries and conditional rendering.
        for (int id = 0; id < Restores.Length; id++)
        {
            if (Grammar.ShapeOf(id) is ["h:VkCommandBuffer", ..])
                Restores[id] = Restore.Recording;
        }
        Restores[Grammar.CommandId("vkResetCommandPool")] |= Restore.Recording;
        foreach (string name in new[] { "vkQueueSubmit", "vkQueueSubmit2", "vkQueueBindSparse", "vkSetEvent" })
            Restores[Grammar.CommandId(name)] |= Restore.Recording | Restore.Sync;

        VulkanBootstrap.TryInitialise();
        Recycle();
    }

    // The loader aborts on a second destroy of a bootstrap object.
    private static void Recycle(string? destroyed = null)
    {
        _guest ??= new FuzzGuest();
        // The arena behind a dropped GenState is unmanaged, so the collector never returns it.
        _device?.GenState.Dispose();
        _device = new BrovVulkDevice();
        if (destroyed == "VkInstance")
            VulkanBootstrap.Restart();
        else
            VulkanBootstrap.ReopenDevice(destroyed != "VkDevice");

        Made.Clear();
        FirstOfType.Clear();
        foreach ((uint id, string type) in VulkanBootstrap.Register(_device.GenState))
            Keep(id, type);
        Bootstrap.Run();
        _mark = _device.GenState.NextHostId;
    }

    private static void Keep(uint id, string type)
    {
        if (id == 0)
            return;
        Made.Add((id, type, _device!.GenState.Lookup(id, type)));
        FirstOfType.TryAdd(type, id);
    }

    public static byte[] Frame(uint command, byte[] payload)
    {
        byte[] frame = new byte[8 + payload.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(frame, command);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(4), (uint)payload.Length);
        payload.CopyTo(frame, 8);
        return frame;
    }

    internal static int Send(byte[] frame, out ReadOnlySpan<byte> written) => Send(frame, frame.Length, out written);

    private static int Send(byte[] input, int inputLength, out ReadOnlySpan<byte> written)
    {
        DeviceData dd = new() { InputBuffer = input, InputLength = (uint)inputLength, OutputBuffer = Output, OutputLength = (uint)Output.Length };
        _device!.HandleIoctl(IoctlBrovVulkGen, ref dd, _guest!);
        byte[] output = dd.OutputBuffer ?? Array.Empty<byte>();
        int length = (int)Math.Min(dd.Information, (ulong)output.Length);
        written = length > 4 ? output.AsSpan(4, length - 4) : default;
        return length >= 4 ? BinaryPrimitives.ReadInt32LittleEndian(output) : int.MinValue;
    }

    internal static uint Create(string type, string command, byte[] frame)
    {
        int result = Send(frame, out ReadOnlySpan<byte> written);
        uint id = result >= 0 && written.Length >= 4 ? BinaryPrimitives.ReadUInt32LittleEndian(written) : 0;
        if (id == 0)
            Console.Error.WriteLine($"[ioctl] bootstrap {command} failed with {result}");
        Keep(id, type);
        return id;
    }

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 13 || _device == null || _guest == null)
            return;

        if (Interlocked.Increment(ref _iterations) % RecycleEvery == 0)
            Recycle();

        // The first five bytes steer the harness. The rest is what the guest hands the ioctl.
        byte knobs = data[0];
        _guest.AllowShareBacking = (knobs & 1) != 0;
        _guest.Flags = (knobs & 2) != 0 ? LogFlags.Issues : default;
        _guest.ResetDirty((knobs >> 2) % FuzzGuest.WindowCount);
        VulkanBootstrap.SetStandIns(_device.GenState,
            (int)BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(1, 4)));

        ReadOnlySpan<byte> body = data[5..];
        if (body.Length > _input.Length)
            _input = new byte[Math.Max(body.Length, _input.Length * 2)];
        body.CopyTo(_input);

        int result = int.MinValue;
        ReadOnlySpan<byte> written = default;
        try
        {
            result = Send(_input, body.Length, out written);
        }
        catch (Exception e) when (StructTarget.Expected(e))
        {
        }

        uint command = BinaryPrimitives.ReadUInt32LittleEndian(body);
        uint known = command < (uint)BrovVulkApi.CommandCount || command >= BrovVulkGenDispatch.PostedBatchId ? command : uint.MaxValue;
        Feedback.Add(Feedback.CommandResult, known, (uint)result);
        Feedback.Add(Feedback.CommandOutput, known, Feedback.Bucket(written.Length));

        Settle(command);
    }

    // Each input must replay without earlier inputs.
    private static void Settle(uint command)
    {
        GenState st = _device!.GenState;
        st.Rewind(_mark);

        foreach ((uint id, string type, IntPtr ptr) in Made)
        {
            if (st.IdOf(ptr, type) != id)
            {
                Recycle(type);
                return;
            }
        }

        if (st.HasLostDevice)
        {
            Recycle();
            return;
        }

        Restore restore = command == BrovVulkDevice.BatchId || command == BrovVulkGenDispatch.PostedBatchId
            ? Restore.Recording | Restore.Sync
            : command < (uint)Restores.Length ? Restores[command] : Restore.None;
        if ((restore & Restore.Sync) != 0)
            Bootstrap.Resync();
        if (restore != Restore.None)
            Bootstrap.Record();
        Bootstrap.Unmap(st);
    }

    internal static IntPtr PtrOf(string type) => _device!.GenState.Lookup(HandleOf(type), type);
}

internal static class Bootstrap
{
    private const uint UsageAllBufferBits = 0x1FF;
    private const uint UsageColorImageBits = 0x1F;
    private const ulong MemoryBytes = 1 << 20;
    private const uint Queries = 4;

    private static byte[]? _reset, _begin, _idle;
    private static IntPtr _fence, _event, _queryPool;
    private static readonly List<(uint Memory, byte[] Unmap)> Memories = new();

    private static int Off(string path)
    {
        int at = 0;
        foreach (string member in path.Split('/'))
            at += BrovVulkLayout.MemberOffset[member];
        return at;
    }

    private static byte[] Frame(string command, Dictionary<string, ulong>? set = null, Func<string, uint>? count = null)
    {
        Func<int, byte[]>? body = null;
        if (set != null)
        {
            Dictionary<int, ulong> values = new();
            foreach ((string path, ulong value) in set)
                values[Off(path)] = value;
            body = sid => Grammar.Struct(sid, values);
        }

        int id = Grammar.CommandId(command);
        return IoctlTarget.Frame((uint)id, Grammar.Command(id, IoctlTarget.HandleOf, body, count));
    }

    private static uint Create(string type, string command, Dictionary<string, ulong>? set = null, Func<string, uint>? count = null) =>
        IoctlTarget.Create(type, command, Frame(command, set, count));

    public static void Run()
    {
        _reset = _begin = _idle = null;
        _fence = _event = _queryPool = IntPtr.Zero;
        Memories.Clear();
        if (!VulkanBootstrap.Available)
            return;

        Create("VkCommandPool", "vkCreateCommandPool", new()
        {
            ["VkCommandPoolCreateInfo.flags"] = BrovVulkConstants.VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,
        });
        uint commandBuffer = Create("VkCommandBuffer", "vkAllocateCommandBuffers", new()
        {
            ["VkCommandBufferAllocateInfo.commandPool"] = IoctlTarget.HandleOf("VkCommandPool"),
            ["VkCommandBufferAllocateInfo.commandBufferCount"] = 1,
        }, _ => 1);
        if (commandBuffer != 0)
        {
            _reset = Frame("vkResetCommandBuffer");
            _begin = Frame("vkBeginCommandBuffer");
            Record();
        }
        _idle = Frame("vkQueueWaitIdle");

        Create("VkFence", "vkCreateFence");
        Create("VkSemaphore", "vkCreateSemaphore");
        Create("VkEvent", "vkCreateEvent");
        Create("VkSampler", "vkCreateSampler");
        Create("VkDescriptorSetLayout", "vkCreateDescriptorSetLayout");
        Create("VkPipelineLayout", "vkCreatePipelineLayout");
        Create("VkPipelineCache", "vkCreatePipelineCache");
        Create("VkQueryPool", "vkCreateQueryPool", new() { ["VkQueryPoolCreateInfo.queryCount"] = Queries });

        Create("VkBuffer", "vkCreateBuffer", new()
        {
            ["VkBufferCreateInfo.size"] = 1 << 16,
            ["VkBufferCreateInfo.usage"] = UsageAllBufferBits,
        });
        Create("VkImage", "vkCreateImage", new()
        {
            ["VkImageCreateInfo.imageType"] = BrovVulkConstants.VK_IMAGE_TYPE_2D,
            ["VkImageCreateInfo.format"] = BrovVulkConstants.VK_FORMAT_R8G8B8A8_UNORM,
            ["VkImageCreateInfo.extent/VkExtent3D.width"] = 64,
            ["VkImageCreateInfo.extent/VkExtent3D.height"] = 64,
            ["VkImageCreateInfo.extent/VkExtent3D.depth"] = 1,
            ["VkImageCreateInfo.mipLevels"] = 1,
            ["VkImageCreateInfo.arrayLayers"] = 1,
            ["VkImageCreateInfo.samples"] = 1,
            ["VkImageCreateInfo.usage"] = UsageColorImageBits,
        });

        Bind("vkBindBufferMemory", AllocateMemory());
        Bind("vkBindImageMemory", AllocateMemory());

        Create("VkImageView", "vkCreateImageView", new()
        {
            ["VkImageViewCreateInfo.image"] = IoctlTarget.HandleOf("VkImage"),
            ["VkImageViewCreateInfo.viewType"] = BrovVulkConstants.VK_IMAGE_VIEW_TYPE_2D,
            ["VkImageViewCreateInfo.format"] = BrovVulkConstants.VK_FORMAT_R8G8B8A8_UNORM,
            ["VkImageViewCreateInfo.subresourceRange/VkImageSubresourceRange.aspectMask"] = BrovVulkConstants.VK_IMAGE_ASPECT_COLOR_BIT,
            ["VkImageViewCreateInfo.subresourceRange/VkImageSubresourceRange.levelCount"] = 1,
            ["VkImageViewCreateInfo.subresourceRange/VkImageSubresourceRange.layerCount"] = 1,
        });

        _fence = IoctlTarget.PtrOf("VkFence");
        _event = IoctlTarget.PtrOf("VkEvent");
        _queryPool = IoctlTarget.PtrOf("VkQueryPool");
    }

    // Custom wire adds the guest bounce range after the allocation info.
    private static uint AllocateMemory()
    {
        int sid = Grammar.StructOf(BrovVulkConstants.VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO);
        byte[] info = Grammar.Struct(sid, new Dictionary<int, ulong> { [Off("VkMemoryAllocateInfo.allocationSize")] = MemoryBytes });
        byte[] payload = new WireWriter().U32(IoctlTarget.HandleOf("VkDevice")).U32(1).Raw(info).U64(0).U64(0).Done();
        uint memory = IoctlTarget.Create("VkDeviceMemory", "vkAllocateMemory",
                                         IoctlTarget.Frame((uint)Grammar.CommandId("vkAllocateMemory"), payload));
        if (memory != 0)
        {
            byte[] unmap = new WireWriter().U32(IoctlTarget.HandleOf("VkDevice")).U32(memory).Done();
            Memories.Add((memory, IoctlTarget.Frame((uint)Grammar.CommandId("vkUnmapMemory"), unmap)));
        }
        return memory;
    }

    private static void Bind(string command, uint memory)
    {
        int id = Grammar.CommandId(command);
        byte[] payload = Grammar.Command(id, t => t == "VkDeviceMemory" ? memory : IoctlTarget.HandleOf(t));
        int result = IoctlTarget.Send(IoctlTarget.Frame((uint)id, payload), out _);
        if (result < 0)
            Console.Error.WriteLine($"[ioctl] bootstrap {command} failed with {result}");
    }

    public static void Record()
    {
        if (_reset == null || _begin == null)
            return;
        IoctlTarget.Send(_reset, out _);
        IoctlTarget.Send(_begin, out _);
    }

    public static void Unmap(GenState st)
    {
        foreach ((uint memory, byte[] unmap) in Memories)
        {
            if (st.HasMapping(memory))
                IoctlTarget.Send(unmap, out _);
        }
    }

    public static void Resync()
    {
        if (_idle == null)
            return;
        // Vulkan forbids resetting a pending command buffer.
        IoctlTarget.Send(_idle, out _);
        VulkanBootstrap.ResetSync(_fence, _event, _queryPool, Queries);
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
    [DllImport(VK)] private static extern int vkEnumerateInstanceExtensionProperties(IntPtr layer, ref uint count, IntPtr props);
    [DllImport(VK)] private static extern int vkEnumerateDeviceExtensionProperties(IntPtr pd, IntPtr layer, ref uint count, IntPtr props);
    [DllImport("libc")] private static extern int setenv(string name, string value, int overwrite);

    private const string ValidationLayer = "VK_LAYER_KHRONOS_validation";
    private const int LayerPropertiesSize = 520;
    private const uint AllMessageTypes = BrovVulkConstants.VK_DEBUG_UTILS_MESSAGE_TYPE_GENERAL_BIT_EXT
                                       | BrovVulkConstants.VK_DEBUG_UTILS_MESSAGE_TYPE_VALIDATION_BIT_EXT
                                       | BrovVulkConstants.VK_DEBUG_UTILS_MESSAGE_TYPE_PERFORMANCE_BIT_EXT;

    public static bool Validating { get; private set; }

    public static bool EchoValidation;

    public static void TryInitialise()
    {
        if (Instance != IntPtr.Zero)
            return;

        Available = false;
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

            // Returning VK_TRUE from the messenger stops invalid calls before the driver.
            Validating = HasLayer(ValidationLayer);
            IntPtr layerName = Marshal.StringToHGlobalAnsi(ValidationLayer);
            IntPtr* layers = stackalloc IntPtr[1];
            layers[0] = layerName;
            if (Validating)
                setenv("VK_KHRONOS_VALIDATION_DEBUG_ACTION", "VK_DBG_LAYER_ACTION_IGNORE", 1);

            byte* ici = stackalloc byte[64]; new Span<byte>(ici, 64).Clear();
            *(int*)ici = 1;
            *(void**)(ici + 24) = app;
            *(uint*)(ici + 32) = Validating ? 1u : 0u;
            *(IntPtr**)(ici + 40) = Validating ? layers : null;
            *(uint*)(ici + 48) = instExtCount;
            *(IntPtr*)(ici + 56) = instExt;
            int created = vkCreateInstance(ici, IntPtr.Zero, out IntPtr inst);
            if (created != 0)
            {
                *(uint*)(ici + 48) = 0;
                *(IntPtr*)(ici + 56) = IntPtr.Zero;
                created = vkCreateInstance(ici, IntPtr.Zero, out inst);
            }
            if (created != 0 && Validating)
            {
                Validating = false;
                *(uint*)(ici + 32) = 0;
                *(IntPtr**)(ici + 40) = null;
                created = vkCreateInstance(ici, IntPtr.Zero, out inst);
            }
            Marshal.FreeHGlobal(layerName);
            if (created != 0)
                return;

            if (Validating)
                Validating = OpenMessenger(inst);

            uint n = 0;
            vkEnumeratePhysicalDevices(inst, ref n, null);
            if (n == 0)
                return;
            IntPtr* pds = stackalloc IntPtr[(int)n];
            vkEnumeratePhysicalDevices(inst, ref n, pds);

            Instance = inst;
            PhysicalDevice = pds[0];
            BrovVulkProc.HostInstance = inst;
        }
        catch
        {
            // No loader or no ICD. The target still covers framing and the reader.
            Available = false;
        }
    }

    private static bool HasLayer(string name)
    {
        uint n = 0;
        if (BrovVulkApi.vkEnumerateInstanceLayerProperties((IntPtr)(&n), IntPtr.Zero) < 0 || n == 0 || n > 4096)
            return false;
        IntPtr props = Marshal.AllocHGlobal((int)n * LayerPropertiesSize);
        try
        {
            if (BrovVulkApi.vkEnumerateInstanceLayerProperties((IntPtr)(&n), props) < 0)
                return false;
            for (uint k = 0; k < n; k++)
                if (Marshal.PtrToStringAnsi(props + (int)(k * LayerPropertiesSize)) == name)
                    return true;
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(props);
        }
    }

    private static bool OpenMessenger(IntPtr instance)
    {
        IntPtr proc = BrovVulkProc.OwnedProc(instance, false, "vkCreateDebugUtilsMessengerEXT");
        if (proc == IntPtr.Zero)
            return false;

        byte* ci = stackalloc byte[48]; new Span<byte>(ci, 48).Clear();
        *(uint*)ci = BrovVulkConstants.VK_STRUCTURE_TYPE_DEBUG_UTILS_MESSENGER_CREATE_INFO_EXT;
        *(uint*)(ci + 20) = BrovVulkConstants.VK_DEBUG_UTILS_MESSAGE_SEVERITY_ERROR_BIT_EXT;
        *(uint*)(ci + 24) = AllMessageTypes;
        *(IntPtr*)(ci + 32) = (IntPtr)(delegate* unmanaged[Cdecl]<uint, uint, IntPtr, IntPtr, uint>)&OnValidation;

        IntPtr messenger;
        return ((delegate* unmanaged[Cdecl]<IntPtr, void*, IntPtr, IntPtr*, int>)proc)(instance, ci, IntPtr.Zero, &messenger) == 0;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    private static uint OnValidation(uint severity, uint types, IntPtr data, IntPtr user)
    {
        if (data == IntPtr.Zero)
            return 1;
        Feedback.Add(Feedback.ValidationMessage, *(uint*)(data + 32), 0);
        if (EchoValidation)
            Console.Error.WriteLine("[validation] " + Marshal.PtrToStringAnsi(*(IntPtr*)(data + 40)));
        return 1;
    }

    public static void ReopenDevice(bool destroyOld)
    {
        if (Instance == IntPtr.Zero)
            return;
        if (Device != IntPtr.Zero && destroyOld)
        {
            vkDeviceWaitIdle(Device);
            vkDestroyDevice(Device, IntPtr.Zero);
        }
        Device = Queue = IntPtr.Zero;
        Available = OpenDevice();
        OpenSurface();
    }

    public static void Restart()
    {
        Instance = PhysicalDevice = Device = Queue = Surface = IntPtr.Zero;
        BrovVulkProc.HostInstance = IntPtr.Zero;
        TryInitialise();
        ReopenDevice(false);
    }

    // Every surface-taking query dereferences the handle in the loader, so without a real one in the
    // table each of them stops at its handle lookup. VK_EXT_headless_surface needs no window system.
    private static void OpenSurface()
    {
        if (Instance == IntPtr.Zero)
            return;

        IntPtr proc = BrovVulkProc.OwnedProc(Instance, false, "vkCreateHeadlessSurfaceEXT");
        if (proc == IntPtr.Zero)
            return;

        byte* ci = stackalloc byte[24]; new Span<byte>(ci, 24).Clear();
        *(uint*)ci = BrovVulkConstants.VK_STRUCTURE_TYPE_HEADLESS_SURFACE_CREATE_INFO_EXT;

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

        byte* hostQueryReset = stackalloc byte[24]; new Span<byte>(hostQueryReset, 24).Clear();
        *(uint*)hostQueryReset = BrovVulkConstants.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_HOST_QUERY_RESET_FEATURES;
        *(uint*)(hostQueryReset + 16) = 1;

        byte* dci = stackalloc byte[72]; new Span<byte>(dci, 72).Clear();
        *(int*)dci = 3; *(void**)(dci + 8) = hostQueryReset; *(uint*)(dci + 20) = 1; *(void**)(dci + 24) = q;
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

    public static (uint Id, string Type)[] Register(GenState st)
    {
        if (!Available)
            return Array.Empty<(uint, string)>();
        uint instanceId = st.Register(Instance, "VkInstance", 0);
        uint physicalId = st.Register(PhysicalDevice, "VkPhysicalDevice", instanceId);
        uint deviceId = st.Register(Device, "VkDevice", physicalId);
        uint queueId = st.Register(Queue, "VkQueue", deviceId);
        st.SetDevicePhysical(Device, PhysicalDevice);
        uint surfaceId = st.Register(Surface, "VkSurfaceKHR", instanceId);

        return new[]
        {
            (instanceId, "VkInstance"), (physicalId, "VkPhysicalDevice"), (deviceId, "VkDevice"),
            (queueId, "VkQueue"), (surfaceId, "VkSurfaceKHR"),
        };
    }

    public static void ResetSync(IntPtr fence, IntPtr evt, IntPtr queryPool, uint queries)
    {
        if (Device == IntPtr.Zero)
            return;
        if (fence != IntPtr.Zero)
            BrovVulkApi.vkResetFences(Device, 1, (IntPtr)(&fence));
        if (evt != IntPtr.Zero)
            BrovVulkApi.vkResetEvent(Device, evt);
        if (queryPool != IntPtr.Zero)
            BrovVulkApi.vkResetQueryPool(Device, queryPool, 0, queries);
    }

    public static void SetStandIns(GenState st, int bits)
    {
        if (Available)
            st.SetDeviceStandIns(Device, bits);
    }
}
