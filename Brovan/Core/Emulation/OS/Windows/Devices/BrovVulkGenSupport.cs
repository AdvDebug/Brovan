using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows
{
    // The counters are plain fields, so every caller holds BrovVulkDevice.Lock.
    internal sealed class BrovVulkStats
    {
        private const int ReportInterval = 256;

        private readonly string _title;
        private readonly Action<StringBuilder> _describe;
        private int _sinceReport;

        internal readonly bool Enabled;

        internal BrovVulkStats(string variable, string title, Action<StringBuilder> describe)
        {
            Enabled = string.Equals(Environment.GetEnvironmentVariable(variable), "1", StringComparison.Ordinal);
            _title = title;
            _describe = describe;
        }

        internal void Tick()
        {
            if (++_sinceReport < ReportInterval)
                return;

            _sinceReport = 0;
            StringBuilder sb = new StringBuilder(_title);
            _describe(sb);
            Utils.LogError(sb.ToString());
            Utils.FlushLog();
        }
    }

    internal sealed unsafe class GenReader
    {
        private byte[] _data;
        private int _base;
        private int _len;
        private int _pos;

        public void Reset(byte[] data, int offset, int len)
        {
            _data = data ?? Array.Empty<byte>();
            _base = offset < 0 ? 0 : offset;
            int max = _data.Length - _base;
            _len = len < 0 || len > max ? max : len;
            _pos = 0;
        }

        private ReadOnlySpan<byte> Take(int n)
        {
            if (n < 0 || (long)_pos + n > _len)
                throw new IndexOutOfRangeException("BrovVulk generic reader overrun.");
            ReadOnlySpan<byte> s = _data.AsSpan(_base + _pos, n);
            _pos += n;
            return s;
        }

        public int Remaining => _len - _pos;

        public int Offset => _base + _pos;

        public void Skip(int n) => Take(n);

        public uint ReadU32() => BinaryPrimitives.ReadUInt32LittleEndian(Take(4));

        public ulong ReadU64() => BinaryPrimitives.ReadUInt64LittleEndian(Take(8));

        public void CopyInto(IntPtr dst, uint n)
        {
            ReadOnlySpan<byte> s = Take((int)n);
            s.CopyTo(new Span<byte>((void*)dst, (int)n));
        }
    }

    internal sealed unsafe class GenBuf
    {
        private byte[] _data = new byte[256];
        private int _len;

        public void Reset() => _len = 0;

        private void Ensure(int extra)
        {
            if (_len + extra <= _data.Length)
                return;
            int newCap = Math.Max(_data.Length * 2, _len + extra);
            Array.Resize(ref _data, newCap);
        }

        public void WriteU32(uint value)
        {
            Ensure(4);
            BinaryPrimitives.WriteUInt32LittleEndian(_data.AsSpan(_len, 4), value);
            _len += 4;
        }

        public void WriteU64(ulong value)
        {
            Ensure(8);
            BinaryPrimitives.WriteUInt64LittleEndian(_data.AsSpan(_len, 8), value);
            _len += 8;
        }

        public void WriteBytesFrom(IntPtr src, uint n)
        {
            Ensure((int)n);
            new ReadOnlySpan<byte>((void*)src, (int)n).CopyTo(_data.AsSpan(_len, (int)n));
            _len += (int)n;
        }

        public void WriteBytesFrom(IntPtr src, uint n, int[] padding)
        {
            int start = _len;
            WriteBytesFrom(src, n);
            Span<byte> written = _data.AsSpan(start, (int)n);
            for (int i = 0; i < padding.Length; i += 2)
                written.Slice(padding[i], padding[i + 1]).Clear();
        }

        public void WriteBytes(byte[] src)
        {
            Ensure(src.Length);
            src.CopyTo(_data.AsSpan(_len, src.Length));
            _len += src.Length;
        }

        public byte[] Finish(int result)
        {
            byte[] outp = new byte[4 + _len];
            BinaryPrimitives.WriteInt32LittleEndian(outp.AsSpan(0, 4), result);
            if (_len > 0)
                Array.Copy(_data, 0, outp, 4, _len);
            return outp;
        }
    }

    internal static class BrovVulkGenNative
    {
        [DllImport("kernel32.dll", EntryPoint = "GetModuleHandleW")]
        internal static extern IntPtr GetModuleHandleW(IntPtr lpModuleName);
    }

    /// <summary>
    /// Resolves host Vulkan commands the loader does not export. A loader exports only the core commands of
    /// its own version, the rest comes from vkGetInstanceProcAddr.
    /// </summary>
    internal static class BrovVulkProc
    {
        private static IntPtr Library;
        private static bool LibraryTried;

        internal static IntPtr HostInstance;

        private static readonly IntPtr[] Globals = new IntPtr[BrovVulkApi.CommandCount];

        // The loader dispatch pointer is shared by an owner and its child handles.
        private static readonly ConcurrentDictionary<IntPtr, HostProcs> Owners = new ConcurrentDictionary<IntPtr, HostProcs>();

        internal static unsafe IntPtr AddOwner(IntPtr Owner, bool Device)
        {
            IntPtr Key = *(IntPtr*)Owner;
            Owners[Key] = new HostProcs(Owner, Device);
            return Key;
        }

        internal static void RemoveOwner(IntPtr Key) => Owners.TryRemove(Key, out _);

        internal static unsafe IntPtr Owned(IntPtr Handle, int Command)
        {
            if (Handle == IntPtr.Zero || !Owners.TryGetValue(*(IntPtr*)Handle, out HostProcs? Procs))
                return Global(Command);

            IntPtr Proc = Procs.Get(Command);
            if (Proc == IntPtr.Zero)
                throw new EntryPointNotFoundException("The host has no " + BrovVulkApi.CommandNames[Command] + " for this object.");
            return Proc;
        }

        private static IntPtr Resolve(string Name, string[]? Aliases)
        {
            if (!LibraryTried)
            {
                LibraryTried = true;
                if (GeneralHelper.IsWindows)
                    NativeLibrary.TryLoad("vulkan-1.dll", out Library);
                else if (!NativeLibrary.TryLoad("libvulkan.so.1", out Library))
                    NativeLibrary.TryLoad("libvulkan.so", out Library);
            }

            if (Library != IntPtr.Zero && NativeLibrary.TryGetExport(Library, Name, out IntPtr Export) && Export != IntPtr.Zero)
                return Export;

            if (HostInstance != IntPtr.Zero)
            {
                IntPtr Proc = OwnedProc(HostInstance, false, Name, Aliases);
                if (Proc != IntPtr.Zero)
                    return Proc;
            }

            throw new EntryPointNotFoundException("The host Vulkan loader has no entry point for " + Name + ".");
        }

        internal static IntPtr Global(int Command)
        {
            IntPtr Proc = Globals[Command];
            if (Proc == IntPtr.Zero)
                Proc = Globals[Command] = Resolve(BrovVulkApi.CommandNames[Command], BrovVulkApi.CommandAliases[Command]);
            return Proc;
        }

        internal static IntPtr OwnedProc(IntPtr Owner, bool Device, string Name, string[]? Aliases = null)
        {
            IntPtr Proc = AskLoader(Owner, Device, Name);
            for (int i = 0; Proc == IntPtr.Zero && Aliases != null && i < Aliases.Length; i++)
                Proc = AskLoader(Owner, Device, Aliases[i]);
            return Proc;
        }

        private static IntPtr AskLoader(IntPtr Owner, bool Device, string Name)
        {
            IntPtr Ansi = Marshal.StringToHGlobalAnsi(Name);
            try { return Device ? BrovVulkApi.vkGetDeviceProcAddr(Owner, Ansi) : BrovVulkApi.vkGetInstanceProcAddr(Owner, Ansi); }
            finally { Marshal.FreeHGlobal(Ansi); }
        }
    }

    // Waiter threads also read this cache outside BrovVulkDevice.Lock.
    internal sealed class HostProcs
    {
        private static readonly IntPtr Absent = new IntPtr(-1);

        private readonly IntPtr _owner;
        private readonly bool _device;
        private readonly IntPtr[] _procs = new IntPtr[BrovVulkApi.CommandCount];

        public HostProcs(IntPtr owner, bool device)
        {
            _owner = owner;
            _device = device;
        }

        public IntPtr Get(int command)
        {
            IntPtr proc = Volatile.Read(ref _procs[command]);
            if (proc == IntPtr.Zero)
            {
                proc = BrovVulkProc.OwnedProc(_owner, _device, BrovVulkApi.CommandNames[command], BrovVulkApi.CommandAliases[command]);
                if (proc == IntPtr.Zero)
                    proc = Absent;
                Volatile.Write(ref _procs[command], proc);
            }
            return proc == Absent ? IntPtr.Zero : proc;
        }
    }

    internal static unsafe class BrovVulkGenExt
    {
        private const int PropSize = 260;
        private const uint ApiPatchMask = 0xFFF;

        internal static readonly int PropertiesApiVersion = BrovVulkLayout.MemberOffset["VkPhysicalDeviceProperties.apiVersion"];

        private static byte[] _instance;
        private static byte[] _device;
        private static IntPtr _devicePd;

        public static int Instance(GenBuf w)
        {
            _instance ??= Filter(QueryHost(IntPtr.Zero), BrovVulkExtensions.Instance, IntPtr.Zero);
            w.WriteBytes(_instance);
            return 0;
        }

        public static int Device(IntPtr physicalDevice, GenBuf w)
        {
            if (_device == null || _devicePd != physicalDevice)
            {
                _device = Filter(QueryHost(physicalDevice), BrovVulkExtensions.Device, physicalDevice);
                _devicePd = physicalDevice;
            }
            w.WriteBytes(_device);
            return 0;
        }

        public static uint ClampApiVersion(uint version)
        {
            uint max = BrovVulkGenDispatch.MaxApiVersion;
            return version > (max | ApiPatchMask) ? max | (version & ApiPatchMask) : version;
        }

        public static void ClampApiVersion(IntPtr properties)
        {
            uint* version = (uint*)(properties + PropertiesApiVersion);
            *version = ClampApiVersion(*version);
        }

        public static IntPtr PhysicalDeviceCommand(IntPtr physicalDevice, uint coreVersion, params ReadOnlySpan<string> extensions)
        {
            VulkanStandIns.DeviceGaps gaps = VulkanStandIns.Gaps(physicalDevice);
            if (coreVersion != 0 && gaps.ApiVersion >= coreVersion)
                return physicalDevice;
            foreach (string name in extensions)
            {
                if (gaps.HostExtensions.ContainsKey(name))
                    return physicalDevice;
            }
            throw new EntryPointNotFoundException("BrovVulk generic: the host physical device lacks " + (extensions.Length != 0 ? extensions[0] : "the core version") + ".");
        }

        internal static Dictionary<string, uint> QueryHost(IntPtr physicalDevice)
        {
            Dictionary<string, uint> map = new Dictionary<string, uint>(StringComparer.Ordinal);
            uint n = 0;
            int rr = physicalDevice == IntPtr.Zero
                ? (int)BrovVulkApi.vkEnumerateInstanceExtensionProperties(IntPtr.Zero, (IntPtr)(&n), IntPtr.Zero)
                : (int)BrovVulkApi.vkEnumerateDeviceExtensionProperties(physicalDevice, IntPtr.Zero, (IntPtr)(&n), IntPtr.Zero);
            if (rr < 0 || n == 0)
                return map;
            if (n > 4096)
                n = 4096;
            IntPtr buf = Marshal.AllocHGlobal((int)(n * PropSize));
            try
            {
                rr = physicalDevice == IntPtr.Zero
                    ? (int)BrovVulkApi.vkEnumerateInstanceExtensionProperties(IntPtr.Zero, (IntPtr)(&n), buf)
                    : (int)BrovVulkApi.vkEnumerateDeviceExtensionProperties(physicalDevice, IntPtr.Zero, (IntPtr)(&n), buf);
                if (rr < 0)
                    return map;
                for (uint k = 0; k < n; k++)
                {
                    IntPtr rec = buf + (int)(k * PropSize);
                    string name = Marshal.PtrToStringAnsi(rec);
                    if (!string.IsNullOrEmpty(name))
                        map[name] = (uint)Marshal.ReadInt32(rec, 256);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
            return map;
        }

        private static byte[] Filter(Dictionary<string, uint> host, (string Name, uint Version)[] advertised, IntPtr physicalDevice)
        {
            List<(string Name, uint Version)> keep = new List<(string, uint)>();
            foreach ((string name, uint ver) in advertised)
            {
                if (physicalDevice != IntPtr.Zero && VulkanStandIns.WithholdsExtension(physicalDevice, name))
                    continue;
                string hostName = name != "VK_KHR_win32_surface" ? name
                    : Brovan.Android.AndroidHost.IsActive ? "VK_KHR_android_surface"
                    : Brovan.GeneralHelper.IsLinux ? "VK_KHR_xcb_surface"
                    : name;
                if (host.TryGetValue(hostName, out uint hv))
                    keep.Add((name, Math.Min(ver, hv)));
                else if (physicalDevice != IntPtr.Zero && VulkanStandIns.AdvertisesExtension(physicalDevice, name))
                    keep.Add((name, ver));
            }
            byte[] payload = new byte[4 + keep.Count * PropSize];
            BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(0, 4), (uint)keep.Count);
            for (int k = 0; k < keep.Count; k++)
            {
                int off = 4 + k * PropSize;
                System.Text.Encoding.ASCII.GetBytes(keep[k].Name, payload.AsSpan(off, 255));
                BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(off + 256, 4), keep[k].Version);
            }
            return payload;
        }
    }

    internal sealed unsafe class GenArena
    {
        private const int ArenaCap = 1 << 20;

        private IntPtr _arena;
        private int _arenaUsed;
        private readonly List<IntPtr> _overflow = new List<IntPtr>();
        private readonly List<IntPtr> _retainPending = new List<IntPtr>();
        private long _retainPendingBytes;
        private bool _retainArmed;
        private int _chainDepth;

        public long PendingRetainedBytes => _retainPendingBytes;

        public IntPtr Alloc(int size)
        {
            if (size <= 0)
                throw new InvalidOperationException($"Generic forwarding: invalid allocation size {size}.");

            if (_chainDepth != 0)
                return AllocRetained(size);

            int aligned = (size + 15) & ~15;
            if (_arena == IntPtr.Zero)
                _arena = Marshal.AllocHGlobal(ArenaCap);

            if (aligned <= ArenaCap - _arenaUsed)
            {
                IntPtr p = _arena + _arenaUsed;
                _arenaUsed += aligned;
                // Arena slack can contain data from an earlier call.
                new Span<byte>((void*)p, aligned).Clear();
                return p;
            }

            return AllocBlock(size, _overflow);
        }

        private static IntPtr AllocBlock(int size, List<IntPtr> owner)
        {
            IntPtr p = Marshal.AllocHGlobal(size);
            new Span<byte>((void*)p, size).Clear();
            owner.Add(p);
            return p;
        }

        private static void FreeBlocks(List<IntPtr> blocks)
        {
            foreach (IntPtr p in blocks)
                Marshal.FreeHGlobal(p);
            blocks.Clear();
        }

        public void ArmRetain() => _retainArmed = true;

        public void EnterChain()
        {
            if (_retainArmed)
                _chainDepth++;
        }

        public void LeaveChain()
        {
            if (_chainDepth != 0)
                _chainDepth--;
        }

        private IntPtr AllocRetained(int size)
        {
            _retainPendingBytes += size;
            return AllocBlock(size, _retainPending);
        }

        public IntPtr[]? TakeRetained(out long bytes)
        {
            bytes = _retainPendingBytes;
            if (_retainPending.Count == 0)
                return null;

            IntPtr[] blocks = _retainPending.ToArray();
            _retainPending.Clear();
            _retainPendingBytes = 0;
            return blocks;
        }

        public void FreeCallAllocs()
        {
            _arenaUsed = 0;
            _retainArmed = false;
            _chainDepth = 0;
            _retainPendingBytes = 0;
            if (_retainPending.Count != 0)
                FreeBlocks(_retainPending);
            if (_overflow.Count != 0)
                FreeBlocks(_overflow);
        }

        public void FreeAll()
        {
            FreeCallAllocs();
            if (_arena == IntPtr.Zero)
                return;
            Marshal.FreeHGlobal(_arena);
            _arena = IntPtr.Zero;
        }
    }

    internal sealed class GenState : IDisposable
    {
        internal readonly struct MapEntry
        {
            public readonly IntPtr HostPtr;
            public readonly ulong GuestVa;
            public readonly ulong MapOffset;
            public readonly ulong Size;
            public readonly bool Imported;
            public readonly bool Shared;

            public MapEntry(IntPtr hostPtr, ulong guestVa, ulong mapOffset, ulong size, bool imported, bool shared)
            {
                HostPtr = hostPtr;
                GuestVa = guestVa;
                MapOffset = mapOffset;
                Size = size;
                Imported = imported;
                Shared = shared;
            }

            public bool NeedsCopy => !Imported && !Shared;
        }

        public readonly struct DeviceImport
        {
            public readonly IntPtr GetHostPointerProps;
            public readonly ulong Alignment;

            public DeviceImport(IntPtr getHostPointerProps, ulong alignment)
            {
                GetHostPointerProps = getHostPointerProps;
                Alignment = alignment;
            }
        }

        private const ulong WholeSize = ulong.MaxValue;

        private record struct HandleEntry(IntPtr Ptr, string Type, uint Parent, ulong Serial, uint Device)
        {
            // Last generation to name this handle. Use MaxValue for implicitly bound views.
            public ulong Named;
        }

        private readonly Dictionary<uint, HandleEntry> _handles = new Dictionary<uint, HandleEntry>();
        private readonly Dictionary<(IntPtr Ptr, string Type), uint> _ids = new Dictionary<(IntPtr, string), uint>();
        private readonly Dictionary<uint, HashSet<uint>> _children = new Dictionary<uint, HashSet<uint>>();
        private readonly Stack<uint> _forgetting = new Stack<uint>();
        private readonly Dictionary<uint, MapEntry> _mappings = new Dictionary<uint, MapEntry>();
        // Pins of the guest backing that the host driver reads.
        private readonly Dictionary<uint, IntPtr> _importedMem = new();
        private IGuestMemory? _importMemory;
        private readonly Dictionary<uint, ulong> _memorySizes = new Dictionary<uint, ulong>();
        private readonly Dictionary<IntPtr, DeviceImport> _deviceImports = new Dictionary<IntPtr, DeviceImport>();
        private readonly Dictionary<IntPtr, IntPtr> _devicePhysical = new Dictionary<IntPtr, IntPtr>();
        private readonly Dictionary<IntPtr, int> _deviceStandIns = new Dictionary<IntPtr, int>();
        private readonly Dictionary<IntPtr, SetLayoutShape?[]> _layoutSets = new Dictionary<IntPtr, SetLayoutShape?[]>();
        private readonly Dictionary<IntPtr, ulong> _bufferSizes = new Dictionary<IntPtr, ulong>();
        private const int RetireDrainMilliseconds = 2000;
        private static readonly int ImageInfoType = BrovVulkLayout.MemberOffset["VkImageCreateInfo.imageType"];
        private static readonly int ImageInfoFormat = BrovVulkLayout.MemberOffset["VkImageCreateInfo.format"];
        private static readonly int ImageInfoExtent = BrovVulkLayout.MemberOffset["VkImageCreateInfo.extent"];
        private static readonly int ImageInfoLevels = BrovVulkLayout.MemberOffset["VkImageCreateInfo.mipLevels"];
        private static readonly int ImageInfoLayers = BrovVulkLayout.MemberOffset["VkImageCreateInfo.arrayLayers"];
        private static readonly int SwapchainInfoFormat = BrovVulkLayout.MemberOffset["VkSwapchainCreateInfoKHR.imageFormat"];
        private static readonly int SwapchainInfoExtent = BrovVulkLayout.MemberOffset["VkSwapchainCreateInfoKHR.imageExtent"];
        private static readonly int SwapchainInfoLayers = BrovVulkLayout.MemberOffset["VkSwapchainCreateInfoKHR.imageArrayLayers"];
        private static readonly int PhysicalProperties2Size = BrovVulkLayout.StructSize["VkPhysicalDeviceProperties2"];
        private static readonly int RayTracingPropertiesSize = BrovVulkLayout.StructSize["VkPhysicalDeviceRayTracingPropertiesNV"];
        private static readonly int RayTracingHandleSize = BrovVulkLayout.MemberOffset["VkPhysicalDeviceRayTracingPropertiesNV.shaderGroupHandleSize"];
        private static readonly int PresentInfoSwapchainCount = BrovVulkLayout.MemberOffset["VkPresentInfoKHR.swapchainCount"];
        private static readonly int PresentInfoSwapchains = BrovVulkLayout.MemberOffset["VkPresentInfoKHR.pSwapchains"];
        private static readonly int PresentInfoImageIndices = BrovVulkLayout.MemberOffset["VkPresentInfoKHR.pImageIndices"];
        private static readonly int ReleaseInfoSwapchain = BrovVulkLayout.MemberOffset["VkReleaseSwapchainImagesInfoKHR.swapchain"];
        private static readonly int ReleaseInfoIndexCount = BrovVulkLayout.MemberOffset["VkReleaseSwapchainImagesInfoKHR.imageIndexCount"];
        private static readonly int ReleaseInfoImageIndices = BrovVulkLayout.MemberOffset["VkReleaseSwapchainImagesInfoKHR.pImageIndices"];
        private static readonly int SwapchainInfoSurface = BrovVulkLayout.MemberOffset["VkSwapchainCreateInfoKHR.surface"];
        private static readonly int ViewInfoImage = BrovVulkLayout.MemberOffset["VkImageViewCreateInfo.image"];
        private static readonly int ViewInfoType = BrovVulkLayout.MemberOffset["VkImageViewCreateInfo.viewType"];
        private static readonly int ViewInfoRange = BrovVulkLayout.MemberOffset["VkImageViewCreateInfo.subresourceRange"];
        private static readonly int RangeSize = BrovVulkLayout.StructSize["VkImageSubresourceRange"];
        private static readonly int RangeBaseLevel = BrovVulkLayout.MemberOffset["VkImageSubresourceRange.baseMipLevel"];
        private static readonly int RangeLevels = BrovVulkLayout.MemberOffset["VkImageSubresourceRange.levelCount"];
        private static readonly int RangeBaseLayer = BrovVulkLayout.MemberOffset["VkImageSubresourceRange.baseArrayLayer"];
        private static readonly int RangeLayers = BrovVulkLayout.MemberOffset["VkImageSubresourceRange.layerCount"];
        private static readonly int LayersAspect = BrovVulkLayout.MemberOffset["VkImageSubresourceLayers.aspectMask"];
        private static readonly int LayersLevel = BrovVulkLayout.MemberOffset["VkImageSubresourceLayers.mipLevel"];
        private static readonly int LayersBase = BrovVulkLayout.MemberOffset["VkImageSubresourceLayers.baseArrayLayer"];
        private static readonly int LayersCount = BrovVulkLayout.MemberOffset["VkImageSubresourceLayers.layerCount"];
        private static readonly int CopyRowLength = BrovVulkLayout.MemberOffset["VkBufferImageCopy.bufferRowLength"];
        private static readonly int CopyImageHeight = BrovVulkLayout.MemberOffset["VkBufferImageCopy.bufferImageHeight"];
        private static readonly int CopyLayers = BrovVulkLayout.MemberOffset["VkBufferImageCopy.imageSubresource"];
        private static readonly int CopyImageOffset = BrovVulkLayout.MemberOffset["VkBufferImageCopy.imageOffset"];
        private static readonly int CopyExtent = BrovVulkLayout.MemberOffset["VkBufferImageCopy.imageExtent"];
        private static readonly int CopyBufferOffset = BrovVulkLayout.MemberOffset["VkBufferImageCopy.bufferOffset"];
        private static readonly int BindBufferInfoSize = BrovVulkLayout.StructSize["VkBindBufferMemoryInfo"];
        private static readonly int BindBufferInfoBuffer = BrovVulkLayout.MemberOffset["VkBindBufferMemoryInfo.buffer"];
        private static readonly int BindBufferInfoMemory = BrovVulkLayout.MemberOffset["VkBindBufferMemoryInfo.memory"];
        private static readonly int BindBufferInfoOffset = BrovVulkLayout.MemberOffset["VkBindBufferMemoryInfo.memoryOffset"];
        private static readonly int BindImageInfoSize = BrovVulkLayout.StructSize["VkBindImageMemoryInfo"];
        private static readonly int BindImageInfoImage = BrovVulkLayout.MemberOffset["VkBindImageMemoryInfo.image"];
        private static readonly int BindImageInfoMemory = BrovVulkLayout.MemberOffset["VkBindImageMemoryInfo.memory"];
        private static readonly int BindImageInfoOffset = BrovVulkLayout.MemberOffset["VkBindImageMemoryInfo.memoryOffset"];
        private static readonly int BindSparseSize = BrovVulkLayout.StructSize["VkBindSparseInfo"];
        private static readonly int BindSparseBuffers = BrovVulkLayout.MemberOffset["VkBindSparseInfo.pBufferBinds"];
        private static readonly int BindSparseBufferCount = BrovVulkLayout.MemberOffset["VkBindSparseInfo.bufferBindCount"];
        private static readonly int BindSparseOpaque = BrovVulkLayout.MemberOffset["VkBindSparseInfo.pImageOpaqueBinds"];
        private static readonly int BindSparseOpaqueCount = BrovVulkLayout.MemberOffset["VkBindSparseInfo.imageOpaqueBindCount"];
        private static readonly int SparseBufferInfoSize = BrovVulkLayout.StructSize["VkSparseBufferMemoryBindInfo"];
        private static readonly int SparseBufferBinds = BrovVulkLayout.MemberOffset["VkSparseBufferMemoryBindInfo.pBinds"];
        private static readonly int SparseBufferBindCount = BrovVulkLayout.MemberOffset["VkSparseBufferMemoryBindInfo.bindCount"];
        private static readonly int SparseOpaqueInfoSize = BrovVulkLayout.StructSize["VkSparseImageOpaqueMemoryBindInfo"];
        private static readonly int SparseOpaqueBinds = BrovVulkLayout.MemberOffset["VkSparseImageOpaqueMemoryBindInfo.pBinds"];
        private static readonly int SparseOpaqueBindCount = BrovVulkLayout.MemberOffset["VkSparseImageOpaqueMemoryBindInfo.bindCount"];
        private static readonly int SparseMemoryBindBytes = BrovVulkLayout.StructSize["VkSparseMemoryBind"];
        private static readonly int SparseMemoryBindMemory = BrovVulkLayout.MemberOffset["VkSparseMemoryBind.memory"];
        private static readonly int SparseMemoryBindMemoryOffset = BrovVulkLayout.MemberOffset["VkSparseMemoryBind.memoryOffset"];
        private static readonly int SparseMemoryBindSize = BrovVulkLayout.MemberOffset["VkSparseMemoryBind.size"];
        private static readonly int PipelineLayoutSetCount = BrovVulkLayout.MemberOffset["VkPipelineLayoutCreateInfo.setLayoutCount"];
        private static readonly int PipelineLayoutSets = BrovVulkLayout.MemberOffset["VkPipelineLayoutCreateInfo.pSetLayouts"];
        private static readonly int FramebufferFlags = BrovVulkLayout.MemberOffset["VkFramebufferCreateInfo.flags"];
        private static readonly int FramebufferPass = BrovVulkLayout.MemberOffset["VkFramebufferCreateInfo.renderPass"];
        private static readonly int FramebufferAttachmentCount = BrovVulkLayout.MemberOffset["VkFramebufferCreateInfo.attachmentCount"];
        private static readonly int FramebufferAttachments = BrovVulkLayout.MemberOffset["VkFramebufferCreateInfo.pAttachments"];
        private static readonly int FramebufferWidth = BrovVulkLayout.MemberOffset["VkFramebufferCreateInfo.width"];
        private static readonly int FramebufferHeight = BrovVulkLayout.MemberOffset["VkFramebufferCreateInfo.height"];
        private static readonly int FramebufferLayers = BrovVulkLayout.MemberOffset["VkFramebufferCreateInfo.layers"];
        private static readonly int BeginPass = BrovVulkLayout.MemberOffset["VkRenderPassBeginInfo.renderPass"];
        private static readonly int BeginFramebuffer = BrovVulkLayout.MemberOffset["VkRenderPassBeginInfo.framebuffer"];
        private static readonly int BeginArea = BrovVulkLayout.MemberOffset["VkRenderPassBeginInfo.renderArea"];
        private static readonly int BeginClearCount = BrovVulkLayout.MemberOffset["VkRenderPassBeginInfo.clearValueCount"];
        private static readonly int BeginClearValues = BrovVulkLayout.MemberOffset["VkRenderPassBeginInfo.pClearValues"];
        private static readonly int ClearValueSize = BrovVulkLayout.StructSize["VkClearValue"];
        private static readonly int AttachmentBeginCount = BrovVulkLayout.MemberOffset["VkRenderPassAttachmentBeginInfo.attachmentCount"];
        private static readonly int AttachmentBeginViews = BrovVulkLayout.MemberOffset["VkRenderPassAttachmentBeginInfo.pAttachments"];
        private static readonly int GroupAreaCount = BrovVulkLayout.MemberOffset["VkDeviceGroupRenderPassBeginInfo.deviceRenderAreaCount"];
        private static readonly int GroupAreas = BrovVulkLayout.MemberOffset["VkDeviceGroupRenderPassBeginInfo.pDeviceRenderAreas"];
        private static readonly int Rect2DSize = BrovVulkLayout.StructSize["VkRect2D"];
        private static readonly int RenderingArea = BrovVulkLayout.MemberOffset["VkRenderingInfo.renderArea"];
        private static readonly int RenderingLayerCount = BrovVulkLayout.MemberOffset["VkRenderingInfo.layerCount"];
        private static readonly int RenderingViewMask = BrovVulkLayout.MemberOffset["VkRenderingInfo.viewMask"];
        private static readonly int RenderingColorCount = BrovVulkLayout.MemberOffset["VkRenderingInfo.colorAttachmentCount"];
        private static readonly int RenderingColors = BrovVulkLayout.MemberOffset["VkRenderingInfo.pColorAttachments"];
        private static readonly int RenderingDepth = BrovVulkLayout.MemberOffset["VkRenderingInfo.pDepthAttachment"];
        private static readonly int RenderingStencil = BrovVulkLayout.MemberOffset["VkRenderingInfo.pStencilAttachment"];
        private static readonly int RenderingAttachmentSize = BrovVulkLayout.StructSize["VkRenderingAttachmentInfo"];
        private static readonly int RenderingAttachmentView = BrovVulkLayout.MemberOffset["VkRenderingAttachmentInfo.imageView"];
        private static readonly int RenderingAttachmentResolveMode = BrovVulkLayout.MemberOffset["VkRenderingAttachmentInfo.resolveMode"];
        private static readonly int RenderingAttachmentResolveView = BrovVulkLayout.MemberOffset["VkRenderingAttachmentInfo.resolveImageView"];
        private static readonly int RateView = BrovVulkLayout.MemberOffset["VkRenderingFragmentShadingRateAttachmentInfoKHR.imageView"];
        private static readonly int RateTexel = BrovVulkLayout.MemberOffset["VkRenderingFragmentShadingRateAttachmentInfoKHR.shadingRateAttachmentTexelSize"];
        private static readonly int BeginInfoFlags = BrovVulkLayout.MemberOffset["VkCommandBufferBeginInfo.flags"];
        private static readonly int BeginInfoInheritance = BrovVulkLayout.MemberOffset["VkCommandBufferBeginInfo.pInheritanceInfo"];
        private static readonly int InheritancePass = BrovVulkLayout.MemberOffset["VkCommandBufferInheritanceInfo.renderPass"];
        private static readonly int InheritanceSubpass = BrovVulkLayout.MemberOffset["VkCommandBufferInheritanceInfo.subpass"];
        private static readonly int InheritanceColors = BrovVulkLayout.MemberOffset["VkCommandBufferInheritanceRenderingInfo.colorAttachmentCount"];
        private static readonly int InheritanceViewMask = BrovVulkLayout.MemberOffset["VkCommandBufferInheritanceRenderingInfo.viewMask"];
        private static readonly int AllocateLevel = BrovVulkLayout.MemberOffset["VkCommandBufferAllocateInfo.level"];
        private static readonly int ClearAttachmentSize = BrovVulkLayout.StructSize["VkClearAttachment"];
        private static readonly int ClearAttachmentAspect = BrovVulkLayout.MemberOffset["VkClearAttachment.aspectMask"];
        private static readonly int ClearAttachmentIndex = BrovVulkLayout.MemberOffset["VkClearAttachment.colorAttachment"];
        private static readonly int ClearRectSize = BrovVulkLayout.StructSize["VkClearRect"];
        private static readonly int ClearRectBaseLayer = BrovVulkLayout.MemberOffset["VkClearRect.baseArrayLayer"];
        private static readonly int ClearRectLayers = BrovVulkLayout.MemberOffset["VkClearRect.layerCount"];
        private static readonly int SetLayoutBindingCount = BrovVulkLayout.MemberOffset["VkDescriptorSetLayoutCreateInfo.bindingCount"];
        private static readonly int SetLayoutBindings = BrovVulkLayout.MemberOffset["VkDescriptorSetLayoutCreateInfo.pBindings"];
        private static readonly int SetLayoutBindingSize = BrovVulkLayout.StructSize["VkDescriptorSetLayoutBinding"];
        private static readonly int BindingNumber = BrovVulkLayout.MemberOffset["VkDescriptorSetLayoutBinding.binding"];
        private static readonly int BindingType = BrovVulkLayout.MemberOffset["VkDescriptorSetLayoutBinding.descriptorType"];
        private static readonly int BindingCount = BrovVulkLayout.MemberOffset["VkDescriptorSetLayoutBinding.descriptorCount"];
        private static readonly int AllocateSetLayouts = BrovVulkLayout.MemberOffset["VkDescriptorSetAllocateInfo.pSetLayouts"];
        private static readonly int WriteSize = BrovVulkLayout.StructSize["VkWriteDescriptorSet"];
        private static readonly int WriteSet = BrovVulkLayout.MemberOffset["VkWriteDescriptorSet.dstSet"];
        private static readonly int WriteBinding = BrovVulkLayout.MemberOffset["VkWriteDescriptorSet.dstBinding"];
        private static readonly int WriteElement = BrovVulkLayout.MemberOffset["VkWriteDescriptorSet.dstArrayElement"];
        private static readonly int WriteCount = BrovVulkLayout.MemberOffset["VkWriteDescriptorSet.descriptorCount"];
        private static readonly int WriteType = BrovVulkLayout.MemberOffset["VkWriteDescriptorSet.descriptorType"];
        private static readonly int WriteBuffers = BrovVulkLayout.MemberOffset["VkWriteDescriptorSet.pBufferInfo"];
        private static readonly int DescriptorBufferInfoSize = BrovVulkLayout.StructSize["VkDescriptorBufferInfo"];
        private static readonly int CopySize = BrovVulkLayout.StructSize["VkCopyDescriptorSet"];
        private static readonly int CopySrcSet = BrovVulkLayout.MemberOffset["VkCopyDescriptorSet.srcSet"];
        private static readonly int CopySrcBinding = BrovVulkLayout.MemberOffset["VkCopyDescriptorSet.srcBinding"];
        private static readonly int CopySrcElement = BrovVulkLayout.MemberOffset["VkCopyDescriptorSet.srcArrayElement"];
        private static readonly int CopyDstSet = BrovVulkLayout.MemberOffset["VkCopyDescriptorSet.dstSet"];
        private static readonly int CopyDstBinding = BrovVulkLayout.MemberOffset["VkCopyDescriptorSet.dstBinding"];
        private static readonly int CopyDstElement = BrovVulkLayout.MemberOffset["VkCopyDescriptorSet.dstArrayElement"];
        private static readonly int CopyCount = BrovVulkLayout.MemberOffset["VkCopyDescriptorSet.descriptorCount"];
        private static readonly int WriteImages = BrovVulkLayout.MemberOffset["VkWriteDescriptorSet.pImageInfo"];
        private static readonly int WriteTexelViews = BrovVulkLayout.MemberOffset["VkWriteDescriptorSet.pTexelBufferView"];
        private static readonly int ImageInfoSize = BrovVulkLayout.StructSize["VkDescriptorImageInfo"];
        private static readonly int ImageInfoSampler = BrovVulkLayout.MemberOffset["VkDescriptorImageInfo.sampler"];
        private static readonly int ImageInfoView = BrovVulkLayout.MemberOffset["VkDescriptorImageInfo.imageView"];
        private static readonly int BindingImmutable = BrovVulkLayout.MemberOffset["VkDescriptorSetLayoutBinding.pImmutableSamplers"];
        private static readonly int BufferViewInfoBuffer = BrovVulkLayout.MemberOffset["VkBufferViewCreateInfo.buffer"];
        private static readonly int AllocatePool = BrovVulkLayout.MemberOffset["VkCommandBufferAllocateInfo.commandPool"];
        private static readonly int AllocateSetCount = BrovVulkLayout.MemberOffset["VkDescriptorSetAllocateInfo.descriptorSetCount"];
        private static readonly int VariableSetCount = BrovVulkLayout.MemberOffset["VkDescriptorSetVariableDescriptorCountAllocateInfo.descriptorSetCount"];
        private static readonly int VariableCountsList = BrovVulkLayout.MemberOffset["VkDescriptorSetVariableDescriptorCountAllocateInfo.pDescriptorCounts"];
        private static readonly int AddressInfoBuffer = BrovVulkLayout.MemberOffset["VkBufferDeviceAddressInfo.buffer"];
        private static readonly int BufferInfoNext = BrovVulkLayout.MemberOffset["VkBufferCreateInfo.pNext"];
        private static readonly int BufferInfoSize = BrovVulkLayout.MemberOffset["VkBufferCreateInfo.size"];
        private static readonly int BufferInfoUsage = BrovVulkLayout.MemberOffset["VkBufferCreateInfo.usage"];
        private static readonly int BufferUsage2 = BrovVulkLayout.MemberOffset["VkBufferUsageFlags2CreateInfo.usage"];
        private static readonly int SetLayoutFlags = BrovVulkLayout.MemberOffset["VkDescriptorSetLayoutCreateInfo.flags"];
        private static readonly int PipelineLayoutRangeCount = BrovVulkLayout.MemberOffset["VkPipelineLayoutCreateInfo.pushConstantRangeCount"];
        private static readonly int PipelineLayoutRanges = BrovVulkLayout.MemberOffset["VkPipelineLayoutCreateInfo.pPushConstantRanges"];
        private static readonly int PushRangeSize = BrovVulkLayout.StructSize["VkPushConstantRange"];
        private static readonly int PushRangeOffset = BrovVulkLayout.MemberOffset["VkPushConstantRange.offset"];
        private static readonly int PushRangeBytes = BrovVulkLayout.MemberOffset["VkPushConstantRange.size"];
        private static readonly int AddressInfoSize = BrovVulkLayout.StructSize["VkBufferDeviceAddressInfo"];
        private static readonly int PlaneInfoSize = BrovVulkLayout.StructSize["VkImagePlaneMemoryRequirementsInfo"];
        private static readonly int PlaneInfoAspect = BrovVulkLayout.MemberOffset["VkImagePlaneMemoryRequirementsInfo.planeAspect"];
        private static readonly int RequirementsInfoSize = BrovVulkLayout.StructSize["VkImageMemoryRequirementsInfo2"];
        private static readonly int RequirementsInfoNext = BrovVulkLayout.MemberOffset["VkImageMemoryRequirementsInfo2.pNext"];
        private static readonly int RequirementsInfoImage = BrovVulkLayout.MemberOffset["VkImageMemoryRequirementsInfo2.image"];
        private static readonly int Requirements2Size = BrovVulkLayout.StructSize["VkMemoryRequirements2"];
        private static readonly int Requirements2Requirements = BrovVulkLayout.MemberOffset["VkMemoryRequirements2.memoryRequirements"];
        private static readonly int BindPlaneAspect = BrovVulkLayout.MemberOffset["VkBindImagePlaneMemoryInfo.planeAspect"];
        private static readonly int QueryPoolType = BrovVulkLayout.MemberOffset["VkQueryPoolCreateInfo.queryType"];
        private static readonly int QueryPoolStatistics = BrovVulkLayout.MemberOffset["VkQueryPoolCreateInfo.pipelineStatistics"];
        private static readonly int FeedbackFlags = BrovVulkLayout.MemberOffset["VkQueryPoolVideoEncodeFeedbackCreateInfoKHR.encodeFeedbackFlags"];
        private static readonly int FramebufferImageInfoCount = BrovVulkLayout.MemberOffset["VkFramebufferAttachmentsCreateInfo.attachmentImageInfoCount"];
        private static readonly int BindingFlagsCount = BrovVulkLayout.MemberOffset["VkDescriptorSetLayoutBindingFlagsCreateInfo.bindingCount"];
        private static readonly int BindingFlagsList = BrovVulkLayout.MemberOffset["VkDescriptorSetLayoutBindingFlagsCreateInfo.pBindingFlags"];
        private static readonly int MutableListCount = BrovVulkLayout.MemberOffset["VkMutableDescriptorTypeCreateInfoEXT.mutableDescriptorTypeListCount"];
        private static readonly int MutableLists = BrovVulkLayout.MemberOffset["VkMutableDescriptorTypeCreateInfoEXT.pMutableDescriptorTypeLists"];
        private static readonly int MutableListSize = BrovVulkLayout.StructSize["VkMutableDescriptorTypeListEXT"];
        private static readonly int MutableTypeCount = BrovVulkLayout.MemberOffset["VkMutableDescriptorTypeListEXT.descriptorTypeCount"];
        private static readonly int MutableTypes = BrovVulkLayout.MemberOffset["VkMutableDescriptorTypeListEXT.pDescriptorTypes"];
        private static readonly int VariableCountsSize = BrovVulkLayout.StructSize["VkDescriptorSetVariableDescriptorCountAllocateInfo"];
        private static readonly int InlineWriteBytes = BrovVulkLayout.MemberOffset["VkWriteDescriptorSetInlineUniformBlock.dataSize"];
        private static readonly int AccelerationWriteCount = BrovVulkLayout.MemberOffset["VkWriteDescriptorSetAccelerationStructureKHR.accelerationStructureCount"];
        private static readonly int AccelerationWriteCountNv = BrovVulkLayout.MemberOffset["VkWriteDescriptorSetAccelerationStructureNV.accelerationStructureCount"];
        private static readonly int PartitionedWriteCount = BrovVulkLayout.MemberOffset["VkWriteDescriptorSetPartitionedAccelerationStructureNV.accelerationStructureCount"];
        private static readonly int TensorWriteCount = BrovVulkLayout.MemberOffset["VkWriteDescriptorSetTensorARM.tensorViewCount"];
        private static readonly int VertexBindingSize = BrovVulkLayout.StructSize["VkVertexInputBindingDescription2EXT"];
        private static readonly int VertexBindingNumber = BrovVulkLayout.MemberOffset["VkVertexInputBindingDescription2EXT.binding"];
        private static readonly int VertexAttributeSize = BrovVulkLayout.StructSize["VkVertexInputAttributeDescription2EXT"];
        private static readonly int VertexAttributeLocation = BrovVulkLayout.MemberOffset["VkVertexInputAttributeDescription2EXT.location"];
        private static readonly int VertexAttributeBinding = BrovVulkLayout.MemberOffset["VkVertexInputAttributeDescription2EXT.binding"];
        private readonly Dictionary<IntPtr, ImageExtent> _images = new Dictionary<IntPtr, ImageExtent>();
        private readonly Dictionary<IntPtr, ImageExtent> _swapchainExtents = new Dictionary<IntPtr, ImageExtent>();
        private readonly Dictionary<IntPtr, uint> _swapchainImageCounts = new Dictionary<IntPtr, uint>();
        private readonly Dictionary<IntPtr, uint> _shaderGroupCounts = new Dictionary<IntPtr, uint>();
        private readonly Dictionary<IntPtr, uint> _shaderGroupHandleSizes = new Dictionary<IntPtr, uint>();
        private readonly Dictionary<IntPtr, (uint Count, uint Values)> _queryPools = new Dictionary<IntPtr, (uint, uint)>();
        private readonly Dictionary<IntPtr, RenderPassShape> _renderPasses = new Dictionary<IntPtr, RenderPassShape>();
        private readonly Dictionary<IntPtr, FramebufferExtent> _framebuffers = new Dictionary<IntPtr, FramebufferExtent>();
        private readonly Dictionary<IntPtr, (uint Width, uint Height, uint Layers)> _views = new Dictionary<IntPtr, (uint, uint, uint)>();
        private readonly Dictionary<IntPtr, Recording> _recordings = new Dictionary<IntPtr, Recording>();
        private readonly HashSet<IntPtr> _submitScratch = new HashSet<IntPtr>();
        private readonly List<IntPtr> _submitPath = new List<IntPtr>();
        private ulong _recordingGeneration;
        private const int MaxSecondaryNesting = 4;
        private readonly Dictionary<IntPtr, SetLayoutShape> _setLayouts = new Dictionary<IntPtr, SetLayoutShape>();
        private readonly Dictionary<IntPtr, SetRecord> _sets = new Dictionary<IntPtr, SetRecord>();
        private readonly Dictionary<(IntPtr Ptr, string Type), (IntPtr Device, List<(IntPtr Ptr, string Type)> Objects)> _holdsOf
            = new Dictionary<(IntPtr, string), (IntPtr, List<(IntPtr, string)>)>();
        private readonly List<(IntPtr Ptr, string Type)> _released = new List<(IntPtr, string)>();
        private long _heldDescriptors;
        private bool _holdRefusalLogged;
        private Recording? _callRecording;
        private Recording? _callCommand;
        private ulong _serial;
        private uint[]? _guestVariableCounts;
        private readonly HashSet<IntPtr> _addressBuffers = new HashSet<IntPtr>();
        private readonly Dictionary<IntPtr, (IntPtr Device, ulong Guest, ulong Span, IntPtr Record)> _bufferAddresses =
            new Dictionary<IntPtr, (IntPtr, ulong, ulong, IntPtr)>();
        private readonly Dictionary<IntPtr, PipelineReads> _pipelines = new Dictionary<IntPtr, PipelineReads>();
        private readonly List<PendingPipeline?> _pendingPipelines = new List<PendingPipeline?>();
        // The driver can reuse a destroyed image's address.
        private readonly Dictionary<IntPtr, (uint Id, ulong Serial)> _viewImages = new Dictionary<IntPtr, (uint, ulong)>();
        private uint _callOwner;

        // Descriptor index times driver stride must fit in 32 bits.
        private const uint MaxCpuSetDescriptors = 1u << 22;

        // Vulkan lets these objects be destroyed after recording.
        private static readonly HashSet<string> UnrecordedTypes = new HashSet<string>(StringComparer.Ordinal)
        {
            "VkPipelineLayout", "VkDescriptorSetLayout", "VkShaderModule", "VkPipelineCache",
        };
        private readonly HashSet<IntPtr> _win32MemoryDevices = new HashSet<IntPtr>();
        private readonly Dictionary<uint, uint> _exportTypes = new Dictionary<uint, uint>();
        private readonly Dictionary<uint, uint> _kmtTokenOfMemory = new Dictionary<uint, uint>();
        private readonly Dictionary<uint, IntPtr> _kmtHostShares = new Dictionary<uint, IntPtr>();
        private readonly Stack<uint> _freeKmtSlots = new Stack<uint>();
        private uint _nextKmtSlot;
        private uint _next = 1;
        private readonly HashSet<uint> _lostDevices = new HashSet<uint>();
        private readonly Dictionary<uint, IntPtr> _ownerKeys = new Dictionary<uint, IntPtr>();
        private readonly HashSet<uint> _guestIdScratch = new HashSet<uint>();
        private readonly Dictionary<uint, (IntPtr[] Blocks, long Bytes)> _retained = new Dictionary<uint, (IntPtr[], long)>();
        private long _retainedBytes;
        private bool _retainRefusalLogged;
        private int _chainDepth;
        private IntPtr _callDevice;

        private static readonly int MaxChainDepth = Array.FindAll(BrovVulkStructMeta.PNext, Allowed => Allowed).Length;

        // NT D3DKMT global share handles have this form.
        private const uint KmtTokenBase = 0x40000002;
        private const int KmtTokenShift = 6;
        private const uint MaxKmtSlots = 1u << 24;

        public readonly BrovVulkWsi Wsi = new BrovVulkWsi();
        public readonly VulkanStandInState StandIns = new VulkanStandInState();
        public readonly BrovVulkWaits Waits = new BrovVulkWaits();
        public readonly BrovVulkRetire Retire = new BrovVulkRetire();

        private readonly GenArena _arena = new GenArena();

        // Generated callers check this before the driver call, so the driver makes no object that cannot get an id.
        public bool HasHostIds(uint count) => (ulong)_next + count <= BrovVulkGenDispatch.GuestIdBase;

        // A handle ends with its parent, so forgetting the parent forgets everything under it.
        public uint Register(IntPtr ptr, string type, uint parent)
        {
            if (ptr == IntPtr.Zero)
                return 0;
            if (!HasHostIds(1))
            {
                Utils.LogError($"[!] BrovVulk(gen): no host handle id is left for a {type}.");
                return 0;
            }

            uint id = _next++;
            Add(id, ptr, type, parent);
            // Forget runs after host destruction, so save the dispatch key now.
            if (type == "VkDevice" || type == "VkInstance")
                _ownerKeys[id] = BrovVulkProc.AddOwner(ptr, type == "VkDevice");
            return id;
        }

        public uint NextHostId => _next;

        public void Rewind(uint next)
        {
            foreach (uint id in _handles.Keys)
            {
                if (id >= next)
                    _forgetting.Push(id);
            }
            ForgetQueued();
            _next = next;
        }

        public unsafe void CheckGuestIds(IntPtr ids, uint count, string type)
        {
            _guestIdScratch.Clear();
            for (uint k = 0; k < count; k++)
            {
                uint id = ((uint*)ids)[k];
                if (id < BrovVulkGenDispatch.GuestIdBase || id == uint.MaxValue || _handles.ContainsKey(id) || !_guestIdScratch.Add(id))
                    throw new InvalidOperationException($"BrovVulk generic: guest id 0x{id:X} for {type} is not free.");
            }
        }

        public unsafe void AddGuestIds(IntPtr ids, IntPtr ptrs, uint count, string type, uint parent)
        {
            for (uint k = 0; k < count; k++)
                Add(((uint*)ids)[k], ((IntPtr*)ptrs)[k], type, parent);
        }

        private void Add(uint id, IntPtr ptr, string type, uint parent)
        {
            uint device = type == "VkDevice" ? id
                : parent != 0 && _handles.TryGetValue(parent, out HandleEntry owner) ? owner.Device : 0;
            _handles[id] = new HandleEntry(ptr, type, parent, ++_serial, device);
            _ids[(ptr, type)] = id;

            if (parent != 0)
            {
                if (!_children.TryGetValue(parent, out HashSet<uint>? siblings))
                {
                    siblings = new HashSet<uint>();
                    _children[parent] = siblings;
                }
                siblings.Add(id);
            }
        }

        public bool HasLostDevice => _lostDevices.Count != 0;

        public void MarkDeviceLost(uint deviceId)
        {
            if (_handles.TryGetValue(deviceId, out HandleEntry e) && e.Type == "VkDevice")
                _lostDevices.Add(deviceId);
        }

        public void MarkDeviceLostOf(uint handleId)
        {
            if (_handles.TryGetValue(handleId, out HandleEntry e) && e.Device != 0)
                _lostDevices.Add(e.Device);
        }

        public IntPtr PoolOfSet(IntPtr set)
        {
            uint id = IdOf(set, "VkDescriptorSet");
            return id != 0 && _handles.TryGetValue(id, out HandleEntry e)
                && _handles.TryGetValue(e.Parent, out HandleEntry pool) && pool.Type == "VkDescriptorPool"
                ? pool.Ptr : IntPtr.Zero;
        }

        public bool IsDeviceLost(uint handleId) =>
            _handles.TryGetValue(handleId, out HandleEntry e) && e.Device != 0 && _lostDevices.Contains(e.Device);

        public uint RegisterQueried(IntPtr ptr, string type, uint parent)
        {
            if (ptr != IntPtr.Zero && _ids.TryGetValue((ptr, type), out uint id)
                && _handles.TryGetValue(id, out HandleEntry e) && e.Parent == parent)
                return id;

            return Register(ptr, type, parent);
        }

        public uint IdOf(IntPtr ptr, string type) => ptr != IntPtr.Zero && _ids.TryGetValue((ptr, type), out uint id) ? id : 0;

        public IntPtr InstanceOfDevice(IntPtr device)
        {
            uint id = IdOf(device, "VkDevice");
            for (int depth = 0; depth < 2 && id != 0; depth++)
                id = _handles.TryGetValue(id, out HandleEntry e) ? e.Parent : 0;

            return id != 0 && _handles.TryGetValue(id, out HandleEntry instance) && instance.Type == "VkInstance"
                ? instance.Ptr : IntPtr.Zero;
        }

        // A driver may dereference a required handle without checking it.
        public IntPtr LookupRequired(uint id, string type)
        {
            if (id == 0)
                throw new InvalidOperationException($"BrovVulk generic: null handle where {type} is required.");
            return Lookup(id, type);
        }

        public IntPtr Lookup(uint id, string type)
        {
            if (id == 0)
            {
                // A dispatchable handle is the object a command operates on and is never VK_NULL_HANDLE
                if (IsDispatchable(type))
                    throw new InvalidOperationException($"BrovVulk generic: null dispatchable handle ({type}).");

                return IntPtr.Zero;
            }
            ref HandleEntry e = ref CollectionsMarshal.GetValueRefOrNullRef(_handles, id);
            if (!System.Runtime.CompilerServices.Unsafe.IsNullRef(ref e) && e.Type == type)
            {
                if (e.Device != 0)
                {
                    if (_callOwner == 0)
                        _callOwner = e.Device;
                    else if (_callOwner != e.Device)
                        throw new InvalidOperationException($"BrovVulk generic: a {type} of another device.");
                }
                if (_callCommand != null)
                    e.Named = Math.Max(e.Named, _recordingGeneration);
                IntPtr ptr = e.Ptr;
                if (_callRecording != null)
                    NoteHandle(id, ptr, e.Type, e.Serial);
                return ptr;
            }
            throw new InvalidOperationException($"BrovVulk generic: bad handle id {id} (expected {type}).");
        }

        private static bool IsDispatchable(string type)
        {
            switch (type)
            {
                case "VkInstance":
                case "VkPhysicalDevice":
                case "VkDevice":
                case "VkQueue":
                case "VkCommandBuffer":
                    return true;
                default:
                    return false;
            }
        }

        public void Forget(uint id)
        {
            _forgetting.Push(id);
            ForgetQueued();
        }

        private void ForgetQueued()
        {
            IntPtr device = IntPtr.Zero;
            while (_forgetting.Count != 0)
            {
                uint next = _forgetting.Pop();
                IntPtr owner = IntPtr.Zero;
                string? ownerType = null;
                if (_handles.Remove(next, out HandleEntry e))
                {
                    if (e.Type == "VkDevice")
                        device = e.Ptr;
                    else if (_handles.TryGetValue(e.Parent, out HandleEntry parent) && parent.Type == "VkDevice")
                        device = parent.Ptr;
                    Retire.ForgetObject(e.Ptr, e.Type);
                    if (_openRecordings.Count != 0 && MayBeBound(e.Named))
                        InvalidateBound(e.Ptr, e.Type, e.Named);
                    owner = e.Ptr;
                    ownerType = e.Type;
                    if (e.Type == "VkBuffer")
                        ReleaseAddress(e.Ptr);
                    if (_holdsOf.Count != 0 && _holdsOf.Remove((e.Ptr, e.Type), out (IntPtr Device, List<(IntPtr Ptr, string Type)> Objects) held))
                        Retire.Unhold(held.Device, e.Ptr, e.Type, held.Objects.ToArray());

                    switch (e.Type)
                    {
                        case "VkPipelineLayout":
                            _layoutSets.Remove(e.Ptr);
                            break;
                        case "VkBuffer":
                            _bufferSizes.Remove(e.Ptr);
                            _addressBuffers.Remove(e.Ptr);
                            break;
                        case "VkQueryPool":
                            _queryPools.Remove(e.Ptr);
                            break;
                        case "VkImage":
                            _images.Remove(e.Ptr);
                            break;
                        case "VkImageView":
                            _views.Remove(e.Ptr);
                            _viewImages.Remove(e.Ptr);
                            break;
                        case "VkRenderPass":
                            _renderPasses.Remove(e.Ptr);
                            break;
                        case "VkFramebuffer":
                            _framebuffers.Remove(e.Ptr);
                            break;
                        case "VkCommandBuffer":
                            if (_recordings.Remove(e.Ptr, out Recording? freed))
                                ClearBound(freed);
                            break;
                        case "VkPipeline":
                            _pipelines.Remove(e.Ptr);
                            _shaderGroupCounts.Remove(e.Ptr);
                            break;
                        case "VkDescriptorSetLayout":
                            _setLayouts.Remove(e.Ptr);
                            break;
                        case "VkDescriptorSet":
                            ReleaseSet(e.Ptr);
                            break;
                        case "VkDevice":
                            _devicePhysical.Remove(e.Ptr);
                            _shaderGroupHandleSizes.Remove(e.Ptr);
                            _deviceImports.Remove(e.Ptr);
                            _deviceStandIns.Remove(e.Ptr);
                            _win32MemoryDevices.Remove(e.Ptr);
                            _lostDevices.Remove(next);
                            break;
                        case "VkSurfaceKHR":
                            Wsi.Forget(e.Ptr, e.Type);
                            break;
                        case "VkSwapchainKHR":
                            Wsi.Forget(e.Ptr, e.Type);
                            _swapchainExtents.Remove(e.Ptr);
                            _swapchainImageCounts.Remove(e.Ptr);
                            ScrubSwapchain(e.Ptr);
                            break;
                    }

                    if (_ids.TryGetValue((e.Ptr, e.Type), out uint mapped) && mapped == next)
                        _ids.Remove((e.Ptr, e.Type));

                    if (e.Parent != 0 && _children.TryGetValue(e.Parent, out HashSet<uint>? siblings))
                        siblings.Remove(next);
                }

                _mappings.Remove(next);
                if (_ownerKeys.Count != 0 && _ownerKeys.Remove(next, out IntPtr ownerKey))
                    BrovVulkProc.RemoveOwner(ownerKey);
                if (_retained.Count != 0 && _retained.Remove(next, out (IntPtr[] Blocks, long Bytes) kept) && !Retire.TryDeferRetained(device, kept, owner, ownerType))
                    FreeRetained(kept);
                if (_importedMem.Remove(next, out IntPtr pin) && !Retire.TryDeferUnpin(next, _importMemory!, pin, owner, ownerType))
                    _importMemory!.UnpinBacking(pin);
                _memorySizes.Remove(next);
                if (_exportTypes.Count != 0)
                    _exportTypes.Remove(next);
                if (_kmtTokenOfMemory.Count != 0 && _kmtTokenOfMemory.Remove(next, out uint token))
                {
                    _kmtHostShares.Remove(token);
                    _freeKmtSlots.Push((token - KmtTokenBase) >> KmtTokenShift);
                }

                if (_children.Remove(next, out HashSet<uint>? children))
                {
                    foreach (uint child in children)
                        _forgetting.Push(child);
                }
            }
        }

        public void ForgetChildren(uint id)
        {
            if (!_children.Remove(id, out HashSet<uint>? children))
                return;

            foreach (uint child in children)
                Forget(child);
        }

        public unsafe void SetPipelineLayoutSets(IntPtr layout, IntPtr info)
        {
            if (layout == IntPtr.Zero || info == IntPtr.Zero)
                return;

            uint count = *(uint*)(info + PipelineLayoutSetCount);
            IntPtr* layouts = *(IntPtr**)(info + PipelineLayoutSets);
            SetLayoutShape?[] shapes = new SetLayoutShape?[count];
            for (uint k = 0; layouts != null && k < count; k++)
                shapes[k] = _setLayouts.TryGetValue(layouts[k], out SetLayoutShape? shape) ? shape : null;
            _layoutSets[layout] = shapes;
            foreach (SetLayoutShape? shape in shapes)
            {
                foreach (IntPtr[]? samplers in shape?.Immutable ?? Array.Empty<IntPtr[]?>())
                {
                    foreach (IntPtr sampler in samplers ?? Array.Empty<IntPtr>())
                        HoldFor(CallDevice, layout, "VkPipelineLayout", sampler, "VkSampler");
                }
            }
        }

        public unsafe ulong GuestBufferAddress(IntPtr info)
        {
            IntPtr buffer = info != IntPtr.Zero ? *(IntPtr*)(info + AddressInfoBuffer) : IntPtr.Zero;
            return buffer != IntPtr.Zero && _bufferAddresses.TryGetValue(buffer, out (IntPtr Device, ulong Guest, ulong Span, IntPtr Record) range) ? range.Guest : 0;
        }

        public unsafe void SetBuffer(IntPtr device, IntPtr buffer, IntPtr info)
        {
            if (buffer == IntPtr.Zero || info == IntPtr.Zero)
                return;
            _bufferSizes[buffer] = *(ulong*)(info + BufferInfoSize);
            ulong usage = *(uint*)(info + BufferInfoUsage);
            for (IntPtr node = *(IntPtr*)(info + BufferInfoNext); node != IntPtr.Zero; node = *(IntPtr*)(node + VkOffsets.NodePNext))
            {
                if (*(int*)node == BrovVulkConstants.VK_STRUCTURE_TYPE_BUFFER_USAGE_FLAGS_2_CREATE_INFO)
                    usage = *(ulong*)(node + BufferUsage2);
            }
            if ((usage & (ulong)BrovVulkConstants.VK_BUFFER_USAGE_SHADER_DEVICE_ADDRESS_BIT) != 0 && Retire.IsCpu(device))
                _addressBuffers.Add(buffer);
        }

        public unsafe int RegisterAddress(IntPtr device, IntPtr buffer)
        {
            if (!_addressBuffers.Contains(buffer) || _bufferAddresses.ContainsKey(buffer))
                return BrovVulkConstants.VK_SUCCESS;
            BrovVulkAddressSpace? space = Retire.AddressSpaceOf(device);
            if (space == null || !_bufferSizes.TryGetValue(buffer, out ulong size))
                return BrovVulkConstants.VK_ERROR_OUT_OF_HOST_MEMORY;

            byte* info = stackalloc byte[AddressInfoSize];
            new Span<byte>(info, AddressInfoSize).Clear();
            *(int*)info = BrovVulkConstants.VK_STRUCTURE_TYPE_BUFFER_DEVICE_ADDRESS_INFO;
            *(IntPtr*)(info + AddressInfoBuffer) = buffer;
            ulong host = BrovVulkApi.vkGetBufferDeviceAddress(device, (IntPtr)info);
            if (!space.TryRegister(size, host, out ulong guest, out ulong span, out IntPtr record))
                return BrovVulkConstants.VK_ERROR_OUT_OF_HOST_MEMORY;
            _bufferAddresses[buffer] = (device, guest, span, record);
            return BrovVulkConstants.VK_SUCCESS;
        }

        public unsafe int RegisterAddresses(IntPtr device, IntPtr infos, uint count)
        {
            for (uint k = 0; infos != IntPtr.Zero && k < count; k++)
            {
                int result = RegisterAddress(device, *(IntPtr*)((byte*)infos + (long)k * BindBufferInfoSize + BindBufferInfoBuffer));
                if (result < 0)
                    return result;
            }
            return BrovVulkConstants.VK_SUCCESS;
        }

        private void ReleaseAddress(IntPtr buffer)
        {
            if (!_bufferAddresses.Remove(buffer, out (IntPtr Device, ulong Guest, ulong Span, IntPtr Record) range))
                return;
            Retire.AddressSpaceOf(range.Device)?.Clear(range.Guest, range.Span);
            Retire.FreeAddress(range.Device, range.Guest, range.Span, range.Record);
        }

        public void CheckBufferRange(IntPtr buffer, ulong offset, ulong range)
        {
            if (buffer == IntPtr.Zero || !_bufferSizes.TryGetValue(buffer, out ulong size))
                return;

            if (offset > size || (range != WholeSize && range > size - offset))
                throw new InvalidOperationException($"BrovVulk generic: descriptor range {offset}+{range} exceeds the buffer's {size} bytes.");
        }

        public void CheckBufferSpan(IntPtr buffer, ulong offset, ulong size)
        {
            if (buffer == IntPtr.Zero)
                return;

            if (!_bufferSizes.TryGetValue(buffer, out ulong total) || offset > total || size > total - offset)
                throw new InvalidOperationException($"BrovVulk generic: {size} bytes at {offset} are outside the buffer.");
        }

        public void CheckBufferSpanOrRest(IntPtr buffer, ulong offset, ulong size)
        {
            if (buffer == IntPtr.Zero)
                return;

            if (!_bufferSizes.TryGetValue(buffer, out ulong total) || offset >= total || (size != WholeSize && size > total - offset))
                throw new InvalidOperationException($"BrovVulk generic: {size} bytes at {offset} are outside the buffer.");
        }

        public unsafe void CheckBufferSpans(IntPtr buffers, IntPtr offsets, IntPtr sizes, uint count)
        {
            for (uint k = 0; buffers != IntPtr.Zero && offsets != IntPtr.Zero && k < count; k++)
                CheckBufferSpanOrRest(*(IntPtr*)(buffers + (int)(k * 8)), *(ulong*)(offsets + (int)(k * 8)), sizes != IntPtr.Zero ? *(ulong*)(sizes + (int)(k * 8)) : WholeSize);
        }

        // Vulkan treats a null offset array as all zeroes.
        public unsafe void CheckBufferWords(IntPtr buffers, IntPtr offsets, uint count)
        {
            for (uint k = 0; buffers != IntPtr.Zero && k < count; k++)
                CheckBufferSpan(*(IntPtr*)(buffers + (int)(k * 8)), offsets != IntPtr.Zero ? *(ulong*)(offsets + (int)(k * 8)) : 0, 4);
        }

        public void CheckIndirect(IntPtr buffer, ulong offset, uint count, uint stride, int commandBytes)
        {
            if (count == 0)
                return;

            ulong span = (ulong)commandBytes;
            if (count > 1)
            {
                if ((ulong)(count - 1) > (ulong.MaxValue - span) / Math.Max(1u, stride))
                    throw new InvalidOperationException($"BrovVulk generic: {count} indirect commands {stride} bytes apart overflow.");
                span += (ulong)(count - 1) * stride;
            }

            CheckBufferSpan(buffer, offset, span);
        }

        public unsafe void CheckBufferCopies(IntPtr source, IntPtr destination, IntPtr regions, uint count, int stride, int sourceOffset, int destinationOffset, int sizeOffset)
        {
            for (uint k = 0; regions != IntPtr.Zero && k < count; k++)
            {
                IntPtr region = regions + (int)(k * (uint)stride);
                ulong size = *(ulong*)(region + sizeOffset);
                CheckBufferSpan(source, *(ulong*)(region + sourceOffset), size);
                CheckBufferSpan(destination, *(ulong*)(region + destinationOffset), size);
            }
        }

        public unsafe void CheckBufferBind(IntPtr device, IntPtr buffer, IntPtr memory, ulong offset)
        {
            if (memory == IntPtr.Zero)
                return;

            ulong* requirements = stackalloc ulong[3];
            BrovVulkApi.vkGetBufferMemoryRequirements(device, buffer, (IntPtr)requirements);
            CheckMemorySpan(memory, offset, requirements[0]);
        }

        public unsafe void CheckImageBind(IntPtr device, IntPtr image, IntPtr memory, ulong offset, uint planeAspect)
        {
            RefuseSwapchainImage(image);
            if (memory == IntPtr.Zero)
                return;

            ulong size;
            if (planeAspect == 0)
            {
                ulong* requirements = stackalloc ulong[3];
                BrovVulkApi.vkGetImageMemoryRequirements(device, image, (IntPtr)requirements);
                size = requirements[0];
            }
            else
            {
                byte* plane = stackalloc byte[PlaneInfoSize];
                byte* info = stackalloc byte[RequirementsInfoSize];
                byte* result = stackalloc byte[Requirements2Size];
                new Span<byte>(plane, PlaneInfoSize).Clear();
                new Span<byte>(info, RequirementsInfoSize).Clear();
                new Span<byte>(result, Requirements2Size).Clear();
                *(int*)plane = BrovVulkConstants.VK_STRUCTURE_TYPE_IMAGE_PLANE_MEMORY_REQUIREMENTS_INFO;
                *(uint*)(plane + PlaneInfoAspect) = planeAspect;
                *(int*)info = BrovVulkConstants.VK_STRUCTURE_TYPE_IMAGE_MEMORY_REQUIREMENTS_INFO_2;
                *(IntPtr*)(info + RequirementsInfoNext) = (IntPtr)plane;
                *(IntPtr*)(info + RequirementsInfoImage) = image;
                *(int*)result = BrovVulkConstants.VK_STRUCTURE_TYPE_MEMORY_REQUIREMENTS_2;
                BrovVulkApi.vkGetImageMemoryRequirements2(device, (IntPtr)info, (IntPtr)result);
                size = *(ulong*)(result + Requirements2Requirements);
            }

            CheckMemorySpan(memory, offset, size);
        }

        public unsafe void CheckBufferBinds(IntPtr device, IntPtr infos, uint count)
        {
            for (uint k = 0; infos != IntPtr.Zero && k < count; k++)
            {
                IntPtr info = infos + (int)(k * (uint)BindBufferInfoSize);
                CheckBufferBind(device, *(IntPtr*)(info + BindBufferInfoBuffer), *(IntPtr*)(info + BindBufferInfoMemory), *(ulong*)(info + BindBufferInfoOffset));
            }
        }

        public unsafe void CheckImageBinds(IntPtr device, IntPtr infos, uint count)
        {
            for (uint k = 0; infos != IntPtr.Zero && k < count; k++)
            {
                IntPtr info = infos + (int)(k * (uint)BindImageInfoSize);
                uint aspect = 0;
                for (IntPtr node = *(IntPtr*)(info + VkOffsets.NodePNext); node != IntPtr.Zero; node = *(IntPtr*)(node + VkOffsets.NodePNext))
                {
                    if (*(int*)node == BrovVulkConstants.VK_STRUCTURE_TYPE_BIND_IMAGE_PLANE_MEMORY_INFO)
                        aspect = *(uint*)(node + BindPlaneAspect);
                }
                CheckImageBind(device, *(IntPtr*)(info + BindImageInfoImage), *(IntPtr*)(info + BindImageInfoMemory), *(ulong*)(info + BindImageInfoOffset), aspect);
            }
        }

        public unsafe void CheckSparseBinds(IntPtr infos, uint count)
        {
            for (uint k = 0; infos != IntPtr.Zero && k < count; k++)
            {
                IntPtr info = infos + (int)(k * (uint)BindSparseSize);
                CheckSparseMemory(*(IntPtr*)(info + BindSparseBuffers), *(uint*)(info + BindSparseBufferCount), SparseBufferInfoSize, SparseBufferBinds, SparseBufferBindCount);
                CheckSparseMemory(*(IntPtr*)(info + BindSparseOpaque), *(uint*)(info + BindSparseOpaqueCount), SparseOpaqueInfoSize, SparseOpaqueBinds, SparseOpaqueBindCount);
            }
        }

        private unsafe void CheckSparseMemory(IntPtr infos, uint count, int infoSize, int bindsOffset, int bindCountOffset)
        {
            for (uint k = 0; infos != IntPtr.Zero && k < count; k++)
            {
                IntPtr info = infos + (int)(k * (uint)infoSize);
                IntPtr binds = *(IntPtr*)(info + bindsOffset);
                uint bindCount = *(uint*)(info + bindCountOffset);
                for (uint b = 0; binds != IntPtr.Zero && b < bindCount; b++)
                {
                    IntPtr bind = binds + (int)(b * (uint)SparseMemoryBindBytes);
                    CheckMemorySpan(*(IntPtr*)(bind + SparseMemoryBindMemory), *(ulong*)(bind + SparseMemoryBindMemoryOffset), *(ulong*)(bind + SparseMemoryBindSize));
                }
            }
        }

        internal readonly struct ImageExtent
        {
            public readonly int Type;
            public readonly int Format;
            public readonly uint Width;
            public readonly uint Height;
            public readonly uint Depth;
            public readonly uint Levels;
            public readonly uint Layers;

            public ImageExtent(int type, int format, uint width, uint height, uint depth, uint levels, uint layers)
            {
                Type = type;
                Format = format;
                Width = width;
                Height = height;
                Depth = depth;
                Levels = levels;
                Layers = layers;
            }
        }

        // Stand-ins can change the host format, including for BCn.
        public static unsafe ImageExtent ReadImage(IntPtr info)
        {
            if (info == IntPtr.Zero)
                return default;

            return new ImageExtent(*(int*)(info + ImageInfoType), *(int*)(info + ImageInfoFormat), *(uint*)(info + ImageInfoExtent),
                *(uint*)(info + ImageInfoExtent + 4), *(uint*)(info + ImageInfoExtent + 8), *(uint*)(info + ImageInfoLevels), *(uint*)(info + ImageInfoLayers));
        }

        public void SetImage(IntPtr image, in ImageExtent extent)
        {
            if (image != IntPtr.Zero && extent.Levels != 0)
                _images[image] = extent;
        }

        public unsafe void SetSwapchainExtent(IntPtr swapchain, IntPtr info)
        {
            if (swapchain == IntPtr.Zero || info == IntPtr.Zero)
                return;
            _swapchainExtents[swapchain] = new ImageExtent(BrovVulkConstants.VK_IMAGE_TYPE_2D, *(int*)(info + SwapchainInfoFormat),
                *(uint*)(info + SwapchainInfoExtent), *(uint*)(info + SwapchainInfoExtent + 4), 1, 1, *(uint*)(info + SwapchainInfoLayers));
            HoldFor(CallDevice, swapchain, "VkSwapchainKHR", *(IntPtr*)(info + SwapchainInfoSurface), "VkSurfaceKHR");
        }

        public unsafe void SetSwapchainImages(IntPtr swapchain, IntPtr images, uint count)
        {
            if (images == IntPtr.Zero || !_swapchainExtents.TryGetValue(swapchain, out ImageExtent extent))
                return;

            for (uint k = 0; k < count; k++)
                SetImage(*(IntPtr*)(images + (int)(k * 8)), extent);
        }

        public unsafe void CheckPresentIndices(IntPtr info)
        {
            if (info == IntPtr.Zero)
                return;

            uint count = *(uint*)(info + PresentInfoSwapchainCount);
            IntPtr swapchains = *(IntPtr*)(info + PresentInfoSwapchains);
            IntPtr indices = *(IntPtr*)(info + PresentInfoImageIndices);
            if (count != 0 && (swapchains == IntPtr.Zero || indices == IntPtr.Zero))
                throw new InvalidOperationException("BrovVulk generic: a present without its swapchains or image indices.");

            for (uint k = 0; k < count; k++)
                CheckImageIndex(((IntPtr*)swapchains)[k], ((uint*)indices)[k]);
        }

        public unsafe void CheckReleasedIndices(IntPtr info)
        {
            if (info == IntPtr.Zero)
                return;

            IntPtr swapchain = *(IntPtr*)(info + ReleaseInfoSwapchain);
            uint count = *(uint*)(info + ReleaseInfoIndexCount);
            IntPtr indices = *(IntPtr*)(info + ReleaseInfoImageIndices);
            if (count != 0 && indices == IntPtr.Zero)
                throw new InvalidOperationException("BrovVulk generic: a swapchain image release without its image indices.");

            for (uint k = 0; k < count; k++)
                CheckImageIndex(swapchain, ((uint*)indices)[k]);
        }

        private unsafe void CheckImageIndex(IntPtr swapchain, uint index)
        {
            if (!_swapchainImageCounts.TryGetValue(swapchain, out uint images))
            {
                if (!_handles.TryGetValue(IdOf(swapchain, "VkSwapchainKHR"), out HandleEntry entry)
                    || !_handles.TryGetValue(entry.Device, out HandleEntry device)
                    || BrovVulkApi.vkGetSwapchainImagesKHR(device.Ptr, swapchain, (IntPtr)(&images), IntPtr.Zero) < 0)
                    throw new InvalidOperationException("BrovVulk generic: a swapchain this layer cannot count the images of.");
                _swapchainImageCounts[swapchain] = images;
            }

            if (index >= images)
                throw new InvalidOperationException($"BrovVulk generic: image index {index} past the swapchain's {images} images.");
        }

        public unsafe void NoteShaderGroups(IntPtr pipelines, IntPtr infos, uint count, int infoSize, int groupCountOffset)
        {
            for (uint k = 0; pipelines != IntPtr.Zero && infos != IntPtr.Zero && k < count; k++)
            {
                IntPtr pipeline = ((IntPtr*)pipelines)[k];
                if (pipeline != IntPtr.Zero)
                    _shaderGroupCounts[pipeline] = *(uint*)(infos + (int)(k * (uint)infoSize) + groupCountOffset);
            }
        }

        public unsafe void CheckShaderGroupHandles(IntPtr device, IntPtr pipeline, uint firstGroup, uint groupCount, ulong dataSize)
        {
            if (!_shaderGroupCounts.TryGetValue(pipeline, out uint groups))
                throw new InvalidOperationException("BrovVulk generic: shader group handles of a pipeline that is not a ray tracing pipeline.");
            if (firstGroup > groups || groupCount > groups - firstGroup)
                throw new InvalidOperationException($"BrovVulk generic: shader groups {firstGroup} to {(ulong)firstGroup + groupCount} past the pipeline's {groups}.");
            if ((ulong)groupCount * ShaderGroupHandleSize(device) > dataSize)
                throw new InvalidOperationException($"BrovVulk generic: {groupCount} shader group handles do not fit {dataSize} bytes.");
        }

        private unsafe uint ShaderGroupHandleSize(IntPtr device)
        {
            if (_shaderGroupHandleSizes.TryGetValue(device, out uint size))
                return size;
            if (!_devicePhysical.TryGetValue(device, out IntPtr physicalDevice))
                throw new InvalidOperationException("BrovVulk generic: a device without a physical device.");

            byte* properties = stackalloc byte[PhysicalProperties2Size];
            byte* rayTracing = stackalloc byte[RayTracingPropertiesSize];
            new Span<byte>(properties, PhysicalProperties2Size).Clear();
            new Span<byte>(rayTracing, RayTracingPropertiesSize).Clear();
            *(int*)properties = BrovVulkConstants.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2;
            *(IntPtr*)(properties + VkOffsets.NodePNext) = (IntPtr)rayTracing;
            *(int*)rayTracing = BrovVulkConstants.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RAY_TRACING_PROPERTIES_NV;
            BrovVulkApi.vkGetPhysicalDeviceProperties2(physicalDevice, (IntPtr)properties);

            size = *(uint*)(rayTracing + RayTracingHandleSize);
            if (size == 0)
                throw new InvalidOperationException("BrovVulk generic: the device reports no shader group handle size.");
            _shaderGroupHandleSizes[device] = size;
            return size;
        }

        // The driver frees swapchain images with the swapchain.
        public void RefuseSwapchainImage(IntPtr image)
        {
            if (_handles.TryGetValue(IdOf(image, "VkImage"), out HandleEntry entry)
                && _handles.TryGetValue(entry.Parent, out HandleEntry parent) && parent.Type == "VkSwapchainKHR")
                throw new InvalidOperationException("BrovVulk generic: a swapchain image cannot be destroyed or bound to memory.");
        }

        private IntPtr SwapchainOfView(IntPtr view)
        {
            if (!_viewImages.TryGetValue(view, out (uint Id, ulong Serial) shown))
                return IntPtr.Zero;
            if (!_handles.TryGetValue(shown.Id, out HandleEntry image) || image.Serial != shown.Serial)
                throw new InvalidOperationException("BrovVulk generic: a descriptor names an image view whose image is gone.");
            return _handles.TryGetValue(image.Parent, out HandleEntry parent) && parent.Type == "VkSwapchainKHR"
                ? parent.Ptr : IntPtr.Zero;
        }

        // The driver frees swapchain images with the swapchain.
        private void ScrubSwapchain(IntPtr swapchain)
        {
            foreach (KeyValuePair<IntPtr, SetRecord> entry in _sets)
            {
                SetRecord set = entry.Value;
                if (set.Swapchains == null)
                    continue;
                _released.Clear();
                for (int slot = 0; slot < set.Swapchains.Length; slot++)
                {
                    if (set.Swapchains[slot] == swapchain)
                        Replace(set, (uint)slot, IntPtr.Zero, HeldGone, set.Samplers![slot], IntPtr.Zero);
                }
                if (_released.Count == 0)
                    continue;
                Retire.Unhold(set.Device, IntPtr.Zero, null, _released.ToArray());
                uint id = IdOf(entry.Key, "VkDescriptorSet");
                if (_handles.TryGetValue(id, out HandleEntry e))
                    _handles[id] = e with { Serial = ++_serial };
            }
        }

        private ImageExtent ImageOf(IntPtr image)
        {
            if (!_images.TryGetValue(image, out ImageExtent extent))
                throw new InvalidOperationException("BrovVulk generic: a region names an image this layer did not create.");
            return extent;
        }

        public unsafe void CheckImageRanges(IntPtr image, IntPtr ranges, uint count)
        {
            if (image == IntPtr.Zero)
                return;

            ImageExtent extent = ImageOf(image);
            for (uint k = 0; ranges != IntPtr.Zero && k < count; k++)
            {
                IntPtr range = ranges + (int)(k * (uint)RangeSize);
                CheckRange(extent, *(uint*)(range + RangeBaseLevel), *(uint*)(range + RangeLevels), *(uint*)(range + RangeBaseLayer), *(uint*)(range + RangeLayers), extent.Layers);
            }
        }

        public unsafe void CheckImageView(IntPtr info)
        {
            ImageExtent extent = ImageOf(*(IntPtr*)(info + ViewInfoImage));
            IntPtr range = info + ViewInfoRange;
            uint baseLevel = *(uint*)(range + RangeBaseLevel);
            CheckRange(extent, baseLevel, *(uint*)(range + RangeLevels), *(uint*)(range + RangeBaseLayer), *(uint*)(range + RangeLayers),
                ViewLayerLimit(extent, *(int*)(info + ViewInfoType), baseLevel));
        }

        // For a 2D view of a 3D image, layers are depth slices.
        private static uint ViewLayerLimit(in ImageExtent extent, int viewType, uint baseLevel) =>
            extent.Type == BrovVulkConstants.VK_IMAGE_TYPE_3D && (viewType == BrovVulkConstants.VK_IMAGE_VIEW_TYPE_2D || viewType == BrovVulkConstants.VK_IMAGE_VIEW_TYPE_2D_ARRAY)
                ? Math.Max(1u, extent.Depth >> (int)Math.Min(baseLevel, 31u)) : extent.Layers;

        public unsafe void SetView(IntPtr view, IntPtr info)
        {
            if (view == IntPtr.Zero || info == IntPtr.Zero)
                return;
            HoldFor(CallDevice, view, "VkImageView", *(IntPtr*)(info + ViewInfoImage), "VkImage");
            uint imageId = Retire.IsCpu(CallDevice) ? IdOf(*(IntPtr*)(info + ViewInfoImage), "VkImage") : 0;
            if (imageId != 0 && _handles.TryGetValue(imageId, out HandleEntry image))
                _viewImages[view] = (imageId, image.Serial);
            if (!_images.TryGetValue(*(IntPtr*)(info + ViewInfoImage), out ImageExtent extent))
                return;

            IntPtr range = info + ViewInfoRange;
            uint baseLevel = *(uint*)(range + RangeBaseLevel), layers = *(uint*)(range + RangeLayers);
            if (layers == uint.MaxValue)
                layers = ViewLayerLimit(extent, *(int*)(info + ViewInfoType), baseLevel) - *(uint*)(range + RangeBaseLayer);
            int shift = (int)Math.Min(baseLevel, 31u);
            _views[view] = (Math.Max(1u, extent.Width >> shift), Math.Max(1u, extent.Height >> shift), layers);
        }

        private static void CheckRange(in ImageExtent extent, uint baseLevel, uint levels, uint baseLayer, uint layers, uint layerLimit)
        {
            if (!Within(baseLevel, levels, extent.Levels) || !Within(baseLayer, layers, layerLimit))
                throw new InvalidOperationException($"BrovVulk generic: levels {baseLevel}+{levels} or layers {baseLayer}+{layers} are outside the image.");
        }

        private static bool Within(uint first, uint count, uint limit) =>
            count == uint.MaxValue ? first < limit : count != 0 && first <= limit && count <= limit - first;

        public unsafe void CheckImageCopies(IntPtr source, IntPtr destination, IntPtr regions, uint count, int stride, int sourceLayers, int sourceOffset, int destinationLayers, int destinationOffset, int extentOffset)
        {
            ImageExtent from = ImageOf(source);
            ImageExtent to = ImageOf(destination);
            for (uint k = 0; regions != IntPtr.Zero && k < count; k++)
            {
                IntPtr region = regions + (int)(k * (uint)stride);
                uint* size = (uint*)(region + extentOffset);
                IntPtr fromLayers = region + sourceLayers, toLayers = region + destinationLayers;
                (uint width, uint height, uint depth) = CopiedExtent(from, fromLayers, to, toLayers, size);
                CheckImageBox(from, fromLayers, (int*)(region + sourceOffset), size[0], size[1], size[2], to.Type == BrovVulkConstants.VK_IMAGE_TYPE_3D);
                CheckImageBox(to, toLayers, (int*)(region + destinationOffset), width, height, depth, from.Type == BrovVulkConstants.VK_IMAGE_TYPE_3D);
                if (CoveredLayers(from, fromLayers, size[2]) != CoveredLayers(to, toLayers, depth))
                    throw new InvalidOperationException("BrovVulk generic: the two sides of an image copy cover different layer or slice counts.");
            }
        }

        // Drivers can take the layer count from only one side.
        private static unsafe uint CoveredLayers(in ImageExtent extent, IntPtr layers, uint depth)
        {
            if (extent.Type == BrovVulkConstants.VK_IMAGE_TYPE_3D)
                return depth;
            uint count = *(uint*)(layers + LayersCount);
            return count == uint.MaxValue ? extent.Layers - *(uint*)(layers + LayersBase) : count;
        }

        // One uncompressed texel maps to one compressed block.
        private static unsafe (uint Width, uint Height, uint Depth) CopiedExtent(in ImageExtent from, IntPtr fromLayers, in ImageExtent to, IntPtr toLayers, uint* size)
        {
            (uint fromWidth, uint fromHeight, uint fromDepth) = BlockOf(from, fromLayers);
            (uint toWidth, uint toHeight, uint toDepth) = BlockOf(to, toLayers);
            return (Rescale(size[0], fromWidth, toWidth), Rescale(size[1], fromHeight, toHeight), Rescale(size[2], fromDepth, toDepth));
        }

        private static unsafe (uint Width, uint Height, uint Depth) BlockOf(in ImageExtent extent, IntPtr layers) =>
            *(uint*)(layers + LayersAspect) == BrovVulkConstants.VK_IMAGE_ASPECT_COLOR_BIT && BrovVulkFormats.TryGet(extent.Format, out BrovVulkFormat format)
                ? (Math.Max(1u, format.Width), Math.Max(1u, format.Height), Math.Max(1u, format.Depth)) : (1u, 1u, 1u);

        private static uint Rescale(uint texels, uint from, uint to) => from == to ? texels : (uint)Math.Min(uint.MaxValue, DivideUp(texels, from) * to);

        public unsafe void CheckImageBlits(IntPtr source, IntPtr destination, IntPtr regions, uint count, int stride, int sourceLayers, int sourceOffsets, int destinationLayers, int destinationOffsets)
        {
            ImageExtent from = ImageOf(source);
            ImageExtent to = ImageOf(destination);
            for (uint k = 0; regions != IntPtr.Zero && k < count; k++)
            {
                IntPtr region = regions + (int)(k * (uint)stride);
                CheckBlitCorners(from, region + sourceLayers, (int*)(region + sourceOffsets));
                CheckBlitCorners(to, region + destinationLayers, (int*)(region + destinationOffsets));
            }
        }

        private static unsafe void CheckBlitCorners(in ImageExtent extent, IntPtr layers, int* corners)
        {
            uint level = CheckLayers(extent, layers);
            (uint width, uint height, uint depth) = LevelSize(extent, level, *(uint*)(layers + LayersAspect));
            for (int corner = 0; corner < 2; corner++)
            {
                int* at = corners + corner * 3;
                if (at[0] < 0 || (uint)at[0] > width || at[1] < 0 || (uint)at[1] > height || at[2] < 0 || (uint)at[2] > depth)
                    throw new InvalidOperationException($"BrovVulk generic: blit corner {at[0]},{at[1]},{at[2]} is outside the image.");
            }
        }

        // Both region layouts match VkBufferImageCopy from bufferOffset onward.
        public unsafe void CheckBufferImageCopies(IntPtr buffer, IntPtr image, IntPtr regions, uint count, int stride, int first)
        {
            ImageExtent extent = ImageOf(image);
            for (uint k = 0; regions != IntPtr.Zero && k < count; k++)
            {
                IntPtr region = regions + (int)(k * (uint)stride) + first;
                uint* size = (uint*)(region + CopyExtent);
                IntPtr layers = region + CopyLayers;
                CheckImageBox(extent, layers, (int*)(region + CopyImageOffset), size[0], size[1], size[2], false);
                ulong bytes = BufferImageBytes(extent, layers, *(uint*)(region + CopyRowLength), *(uint*)(region + CopyImageHeight), size[0], size[1], size[2]);
                CheckBufferSpan(buffer, *(ulong*)(region + CopyBufferOffset), bytes);
            }
        }

        private static unsafe void CheckImageBox(in ImageExtent extent, IntPtr layers, int* offset, uint width, uint height, uint depth, bool depthIsLayers)
        {
            uint level = CheckLayers(extent, layers);
            (uint levelWidth, uint levelHeight, uint levelDepth) = LevelSize(extent, level, *(uint*)(layers + LayersAspect));
            bool volume = extent.Type == BrovVulkConstants.VK_IMAGE_TYPE_3D;
            if (width == 0 || height == 0 || depth == 0 || offset[0] < 0 || offset[1] < 0 || offset[2] < 0
                || width > levelWidth || (uint)offset[0] > levelWidth - width
                || height > levelHeight || (uint)offset[1] > levelHeight - height
                || (volume ? depth > levelDepth || (uint)offset[2] > levelDepth - depth : offset[2] != 0 || (!depthIsLayers && depth != 1)))
                throw new InvalidOperationException($"BrovVulk generic: region {offset[0]},{offset[1]},{offset[2]} + {width}x{height}x{depth} is outside the image.");
        }

        private static unsafe uint CheckLayers(in ImageExtent extent, IntPtr layers)
        {
            uint level = *(uint*)(layers + LayersLevel);
            if (level >= extent.Levels || !Within(*(uint*)(layers + LayersBase), *(uint*)(layers + LayersCount), extent.Layers))
                throw new InvalidOperationException($"BrovVulk generic: level {level} or its layers are outside the image.");
            return level;
        }

        private static (uint Width, uint Height, uint Depth) LevelSize(in ImageExtent extent, uint level, uint aspect)
        {
            int shift = (int)Math.Min(level, 31u);
            uint width = Math.Max(1u, extent.Width >> shift), height = Math.Max(1u, extent.Height >> shift), depth = Math.Max(1u, extent.Depth >> shift);
            if (!BrovVulkFormats.TryGet(extent.Format, out BrovVulkFormat format))
                return (width, height, depth);

            int plane = PlaneOf(aspect);
            if (plane >= 0 && format.Planes != null && plane * 3 + 2 < format.Planes.Length)
                return ((uint)DivideUp(width, format.Planes[plane * 3 + 1]), (uint)DivideUp(height, format.Planes[plane * 3 + 2]), depth);

            return (RoundUp(width, format.Width), RoundUp(height, format.Height), RoundUp(depth, format.Depth));
        }

        private static int PlaneOf(uint aspect) => aspect switch
        {
            (uint)BrovVulkConstants.VK_IMAGE_ASPECT_PLANE_0_BIT => 0,
            (uint)BrovVulkConstants.VK_IMAGE_ASPECT_PLANE_1_BIT => 1,
            (uint)BrovVulkConstants.VK_IMAGE_ASPECT_PLANE_2_BIT => 2,
            _ => -1,
        };

        private static uint RoundUp(uint value, uint block) => block <= 1 ? value : (uint)Math.Min(uint.MaxValue, ((ulong)value + block - 1) / block * block);

        private static unsafe ulong BufferImageBytes(in ImageExtent extent, IntPtr layers, uint rowLength, uint imageHeight, uint width, uint height, uint depth)
        {
            if (!BrovVulkFormats.TryGet(extent.Format, out BrovVulkFormat format))
                throw new InvalidOperationException($"BrovVulk generic: format {extent.Format} has no copy layout this layer knows.");

            uint aspect = *(uint*)(layers + LayersAspect);
            uint blockBytes = format.Bytes, blockWidth = format.Width, blockHeight = format.Height, blockDepth = format.Depth;
            int plane = PlaneOf(aspect);
            if (aspect == BrovVulkConstants.VK_IMAGE_ASPECT_DEPTH_BIT)
                blockBytes = format.DepthBytes;
            else if (aspect == BrovVulkConstants.VK_IMAGE_ASPECT_STENCIL_BIT)
                blockBytes = format.StencilBytes;
            else if (plane >= 0 && format.Planes != null && plane * 3 < format.Planes.Length)
                blockBytes = format.Planes[plane * 3];
            else if (aspect != BrovVulkConstants.VK_IMAGE_ASPECT_COLOR_BIT)
                blockBytes = 0;
            if (blockBytes == 0)
                throw new InvalidOperationException($"BrovVulk generic: aspect {aspect} cannot be copied to or from a buffer for format {extent.Format}.");
            if (aspect != BrovVulkConstants.VK_IMAGE_ASPECT_COLOR_BIT)
                blockWidth = blockHeight = blockDepth = 1;

            uint rows = rowLength == 0 ? width : rowLength;
            uint slices = imageHeight == 0 ? height : imageHeight;
            if (rows < width || slices < height)
                throw new InvalidOperationException("BrovVulk generic: a buffer row length or image height is smaller than the copy.");

            uint layerCount = *(uint*)(layers + LayersCount);
            ulong layerTotal = extent.Type == BrovVulkConstants.VK_IMAGE_TYPE_3D ? 1u
                : layerCount == uint.MaxValue ? extent.Layers - *(uint*)(layers + LayersBase) : layerCount;
            UInt128 rowBlocks = DivideUp(rows, blockWidth), heightBlocks = DivideUp(slices, blockHeight);
            UInt128 planes = (UInt128)DivideUp(depth, blockDepth) * layerTotal;
            UInt128 last = (planes - 1) * heightBlocks * rowBlocks + (DivideUp(height, blockHeight) - 1) * rowBlocks + DivideUp(width, blockWidth);
            UInt128 bytes = last * blockBytes;
            if (bytes > ulong.MaxValue)
                throw new InvalidOperationException("BrovVulk generic: a buffer-image copy spans more than 2^64 bytes.");
            return (ulong)bytes;
        }

        private void CheckMemorySpan(IntPtr memory, ulong offset, ulong size)
        {
            if (memory != IntPtr.Zero && !IsMemoryRangeInsideAllocation(IdOf(memory, "VkDeviceMemory"), offset, size))
                throw new InvalidOperationException($"BrovVulk generic: {size} bytes at memory offset {offset} are outside the allocation.");
        }

        public static unsafe uint QueryResultValues(IntPtr info)
        {
            int type = *(int*)(info + QueryPoolType);
            switch (type)
            {
                case BrovVulkConstants.VK_QUERY_TYPE_RESULT_STATUS_ONLY_KHR:
                    return 0;
                case BrovVulkConstants.VK_QUERY_TYPE_OCCLUSION:
                case BrovVulkConstants.VK_QUERY_TYPE_TIMESTAMP:
                case BrovVulkConstants.VK_QUERY_TYPE_PRIMITIVES_GENERATED_EXT:
                case BrovVulkConstants.VK_QUERY_TYPE_MESH_PRIMITIVES_GENERATED_EXT:
                case BrovVulkConstants.VK_QUERY_TYPE_ACCELERATION_STRUCTURE_COMPACTED_SIZE_KHR:
                case BrovVulkConstants.VK_QUERY_TYPE_ACCELERATION_STRUCTURE_SERIALIZATION_SIZE_KHR:
                case BrovVulkConstants.VK_QUERY_TYPE_ACCELERATION_STRUCTURE_SIZE_KHR:
                case BrovVulkConstants.VK_QUERY_TYPE_ACCELERATION_STRUCTURE_SERIALIZATION_BOTTOM_LEVEL_POINTERS_KHR:
                case BrovVulkConstants.VK_QUERY_TYPE_ACCELERATION_STRUCTURE_COMPACTED_SIZE_NV:
                case BrovVulkConstants.VK_QUERY_TYPE_MICROMAP_SERIALIZATION_SIZE_EXT:
                case BrovVulkConstants.VK_QUERY_TYPE_MICROMAP_COMPACTED_SIZE_EXT:
                    return 1;
                case BrovVulkConstants.VK_QUERY_TYPE_TRANSFORM_FEEDBACK_STREAM_EXT:
                    return 2;
                case BrovVulkConstants.VK_QUERY_TYPE_PIPELINE_STATISTICS:
                    return (uint)System.Numerics.BitOperations.PopCount(*(uint*)(info + QueryPoolStatistics));
                case BrovVulkConstants.VK_QUERY_TYPE_VIDEO_ENCODE_FEEDBACK_KHR:
                    byte* feedback = FindNode(info, BrovVulkConstants.VK_STRUCTURE_TYPE_QUERY_POOL_VIDEO_ENCODE_FEEDBACK_CREATE_INFO_KHR);
                    if (feedback == null)
                        throw new InvalidOperationException("BrovVulk generic: a video encode feedback query pool needs its feedback create info.");
                    return (uint)System.Numerics.BitOperations.PopCount(*(uint*)(feedback + FeedbackFlags));
                default:
                    throw new InvalidOperationException($"BrovVulk generic: query type {type} has no result size this layer can bound.");
            }
        }

        public void SetQueryPool(IntPtr pool, uint count, uint values)
        {
            if (pool != IntPtr.Zero)
                _queryPools[pool] = (count, values);
        }

        public void CheckQueryRange(IntPtr pool, uint first, uint count) => QueryValues(pool, first, count);

        public void CheckQueryResults(IntPtr pool, uint first, uint count, ulong stride, uint flags, ulong available)
        {
            uint values = QueryValues(pool, first, count);
            if (count == 0)
                return;

            ulong width = (flags & BrovVulkConstants.VK_QUERY_RESULT_64_BIT) != 0 ? 8u : 4u;
            uint extra = (uint)System.Numerics.BitOperations.PopCount(flags & (uint)(BrovVulkConstants.VK_QUERY_RESULT_WITH_AVAILABILITY_BIT | BrovVulkConstants.VK_QUERY_RESULT_WITH_STATUS_BIT_KHR));
            ulong record = (values + extra) * width;
            if (record > available || (count > 1 && stride > (available - record) / (count - 1)))
                throw new InvalidOperationException($"BrovVulk generic: {count} query results {stride} bytes apart exceed {available} bytes.");
        }

        public void CheckQueryCopy(IntPtr pool, uint first, uint count, IntPtr buffer, ulong offset, ulong stride, uint flags)
        {
            ulong size = BufferSize(buffer);
            if (offset > size)
                throw new InvalidOperationException($"BrovVulk generic: query copy offset {offset} is past the buffer's {size} bytes.");

            CheckQueryResults(pool, first, count, stride, flags, size - offset);
        }

        // A multiview query takes one slot per view.
        public uint QueryViews(IntPtr commandBuffer) =>
            _recordings.TryGetValue(commandBuffer, out Recording? rec) ? rec.Views : 1u;

        internal sealed class RenderPassShape
        {
            public uint Attachments;
            public uint ClearValues;
            public uint ViewMask;
            public uint[] Colors = Array.Empty<uint>();
            public uint[]? Views;
            public uint DensityMap = uint.MaxValue;
            public (uint Attachment, uint TexelWidth, uint TexelHeight)[]? ShadingRate;
        }

        internal sealed class FramebufferExtent
        {
            public uint Width, Height, Layers, Attachments;
            public IntPtr[]? Views;
        }

        internal enum RecordingState : byte { Initial, Recording, Executable, Invalid }

        internal enum BoundKind : byte { Pipeline, Set, Buffer, RenderPass, Framebuffer, View }

        private const int BoundPoints = BindPoints + 1;

        private static int BoundPoint(int bindPoint) => BindPointIndex(bindPoint) is int index && index >= 0 ? index : BindPoints;

        private readonly HashSet<Recording> _openRecordings = new HashSet<Recording>();

        // Lower bound on the oldest open recording, recomputed on demand.
        private ulong _oldestOpen;
        private bool _oldestLeft;

        private bool MayBeBound(ulong named)
        {
            if (named < _oldestOpen)
                return false;
            if (!_oldestLeft)
                return true;
            _oldestLeft = false;
            _oldestOpen = ulong.MaxValue;
            foreach (Recording rec in _openRecordings)
                _oldestOpen = Math.Min(_oldestOpen, rec.Generation);
            return named >= _oldestOpen;
        }

        // Callers must check first + count against device limits.
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        private static unsafe void CopyBound(ref IntPtr[]? slots, uint first, uint count, IntPtr handles)
        {
            IntPtr[]? target = slots;
            if (target == null || first + count > (uint)target.Length)
                target = GrowBound(ref slots, first + count);
            if (handles == IntPtr.Zero)
                Array.Clear(target, (int)first, (int)count);
            else if (count == 1)
                target[first] = *(IntPtr*)handles;
            else
                new ReadOnlySpan<IntPtr>((void*)handles, (int)count).CopyTo(target.AsSpan((int)first));
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
        private static IntPtr[] GrowBound(ref IntPtr[]? slots, uint end)
        {
            Array.Resize(ref slots, (int)Math.Max(end, Math.Max(8u, (uint)(slots?.Length ?? 0) * 2)));
            return slots;
        }

        private static void NoteView(Recording rec, IntPtr view)
        {
            if (view == IntPtr.Zero)
                return;
            if (rec.BoundViews == null || rec.ViewsBound == (uint)rec.BoundViews.Length)
                GrowBound(ref rec.BoundViews, rec.ViewsBound + 1);
            rec.BoundViews![rec.ViewsBound++] = view;
        }

        private void ClearBound(Recording rec)
        {
            if (!_openRecordings.Remove(rec))
                return;
            _oldestLeft = true;
            Array.Clear(rec.BoundPipelines);
            foreach (IntPtr[]? sets in rec.BoundSetHandles)
            {
                if (sets != null)
                    Array.Clear(sets);
            }
            if (rec.BoundVertex != null)
                Array.Clear(rec.BoundVertex);
            rec.BoundIndex = rec.BoundRenderPass = rec.BoundFramebuffer = IntPtr.Zero;
            rec.ViewsBound = 0;
        }

        private bool Binds(Recording rec, IntPtr ptr, BoundKind kind)
        {
            switch (kind)
            {
                case BoundKind.Pipeline:
                    return Array.IndexOf(rec.BoundPipelines, ptr) >= 0;
                case BoundKind.Set:
                    foreach (IntPtr[]? sets in rec.BoundSetHandles)
                    {
                        if (sets != null && Array.IndexOf(sets, ptr) >= 0)
                            return true;
                    }
                    return false;
                case BoundKind.Buffer:
                    return rec.BoundIndex == ptr || (rec.BoundVertex != null && Array.IndexOf(rec.BoundVertex, ptr) >= 0);
                case BoundKind.RenderPass:
                    return rec.BoundRenderPass == ptr;
                case BoundKind.Framebuffer:
                    return rec.BoundFramebuffer == ptr;
                default:
                    if (rec.BoundViews != null && Array.IndexOf(rec.BoundViews, ptr, 0, (int)rec.ViewsBound) >= 0)
                        return true;
                    return rec.BoundFramebuffer != IntPtr.Zero && _framebuffers.TryGetValue(rec.BoundFramebuffer, out FramebufferExtent? fb)
                        && fb.Views != null && Array.IndexOf(fb.Views, ptr) >= 0;
            }
        }

        // Later commands can use bound objects without naming them.
        private void InvalidateBound(IntPtr ptr, string type, ulong named)
        {
            BoundKind kind;
            switch (type)
            {
                case "VkPipeline": kind = BoundKind.Pipeline; break;
                case "VkDescriptorSet": kind = BoundKind.Set; break;
                case "VkBuffer": kind = BoundKind.Buffer; break;
                case "VkRenderPass": kind = BoundKind.RenderPass; break;
                case "VkFramebuffer": kind = BoundKind.Framebuffer; break;
                case "VkImageView": kind = BoundKind.View; break;
                default: return;
            }

            List<Recording>? hit = null;
            foreach (Recording rec in _openRecordings)
            {
                if (rec.Generation <= named && Binds(rec, ptr, kind))
                    (hit ??= new List<Recording>()).Add(rec);
            }
            for (int k = 0; hit != null && k < hit.Count; k++)
            {
                ClearBound(hit[k]);
                hit[k].State = RecordingState.Invalid;
                Utils.LogError($"[!] BrovVulk(gen): a {type} was destroyed while a command buffer being recorded had it bound. That command buffer is refused until it is begun again or reset.");
            }
        }

        public void NoteVertexBuffers(uint first, uint count, IntPtr buffers)
        {
            if (_callCommand != null && count != 0)
                CopyBound(ref _callCommand.BoundVertex, first, count, buffers);
        }

        public void NoteIndexBuffer(IntPtr buffer)
        {
            if (_callCommand != null)
                _callCommand.BoundIndex = buffer;
        }

        // A secondary's clear bounds are checked against the primary's render area.
        internal sealed class Recording
        {
            public IntPtr Device;
            public IntPtr Pool;
            public bool Secondary;
            public bool Cpu;
            public IntPtr Handle;
            public RecordingState State;
            public bool Continues;
            public ulong Generation;
            public bool Inside;
            public RenderPassShape? Pass;
            public uint Subpass;
            public uint Views = 1;
            public uint Colors;
            public bool AreaKnown;
            public long Left, Top, Right, Bottom;
            public uint Layers;
            public long NeedRight, NeedBottom;
            public uint NeedLayers, NeedColors;
            public Dictionary<IntPtr, ulong>? Executed;
            public Dictionary<IntPtr, uint[]>? Offsets;
            public HashSet<IntPtr>? UsedPools;
            public Dictionary<uint, ulong>? Notes;
            public readonly Dictionary<uint, SetLayoutShape>?[] Reads = new Dictionary<uint, SetLayoutShape>?[BindPoints];
            public readonly SetLayoutShape?[]?[] BoundSets = new SetLayoutShape?[]?[BindPoints];
            public HashSet<SetLayoutShape>? PushedLayouts;
            public BrovVulkRetire.Stamp Stamp;
            public readonly IntPtr[] BoundPipelines = new IntPtr[BoundPoints];
            public readonly IntPtr[]?[] BoundSetHandles = new IntPtr[]?[BoundPoints];
            public IntPtr[]? BoundVertex;
            public IntPtr BoundIndex;
            public IntPtr BoundRenderPass;
            public IntPtr BoundFramebuffer;
            public IntPtr[]? BoundViews;
            public uint ViewsBound;

            public void EndInstance()
            {
                Inside = AreaKnown = false;
                Pass = null;
                Subpass = Colors = Layers = 0;
                Views = 1;
            }

            // Submissions of the prior recording can still be in flight.
            public void Restart(ulong generation, RecordingState state)
            {
                Generation = generation;
                State = state;
                Continues = false;
                EndInstance();
                NeedRight = NeedBottom = 0;
                NeedLayers = NeedColors = 0;
                Executed?.Clear();
                Offsets?.Clear();
                UsedPools?.Clear();
                Notes?.Clear();
                Array.Clear(Reads);
                Array.Clear(BoundSets);
                PushedLayouts?.Clear();
            }
        }

        public unsafe void AddRecordings(IntPtr device, IntPtr info, IntPtr buffers, uint count)
        {
            if (info == IntPtr.Zero || buffers == IntPtr.Zero)
                return;

            bool secondary = *(int*)(info + AllocateLevel) == BrovVulkConstants.VK_COMMAND_BUFFER_LEVEL_SECONDARY;
            bool cpu = (DeviceStandIns(device) & VulkanStandIns.HostCpuDeviceBit) != 0;
            IntPtr pool = *(IntPtr*)(info + AllocatePool);
            for (uint k = 0; k < count; k++)
            {
                IntPtr buffer = ((IntPtr*)buffers)[k];
                _recordings[buffer] = new Recording { Handle = buffer, Device = device, Pool = pool, Secondary = secondary, Cpu = cpu };
            }
        }

        private VulkanStandIns.DeviceGaps? DeviceGapsOf(IntPtr device) =>
            _devicePhysical.TryGetValue(device, out IntPtr physical) ? VulkanStandIns.Gaps(physical) : null;

        internal bool TryGetRecording(IntPtr commandBuffer, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out Recording? rec) =>
            _recordings.TryGetValue(commandBuffer, out rec);

        private Recording RecordingOf(IntPtr commandBuffer) =>
            _recordings.TryGetValue(commandBuffer, out Recording? rec) ? rec : throw new InvalidOperationException("BrovVulk generic: a command buffer this layer did not allocate.");

        private Recording OpenRecording(IntPtr commandBuffer)
        {
            Recording rec = RecordingOf(commandBuffer);
            if (rec.State != RecordingState.Recording)
                throw new InvalidOperationException("BrovVulk generic: a command for a command buffer that is not recording.");
            return rec;
        }

        public void ResetRecording(IntPtr commandBuffer)
        {
            if (!_recordings.TryGetValue(commandBuffer, out Recording? rec))
                return;
            LetGo(commandBuffer, "VkCommandBuffer");
            ClearBound(rec);
            rec.Restart(++_recordingGeneration, RecordingState.Initial);
        }

        public void ResetPoolRecordings(uint poolId)
        {
            if (!_children.TryGetValue(poolId, out HashSet<uint>? children))
                return;

            foreach (uint child in children)
            {
                if (_handles.TryGetValue(child, out HandleEntry e) && e.Type == "VkCommandBuffer")
                    ResetRecording(e.Ptr);
            }
        }

        private RenderPassShape PassOf(IntPtr pass) =>
            _renderPasses.TryGetValue(pass, out RenderPassShape? shape) ? shape : throw new InvalidOperationException("BrovVulk generic: a render pass this layer did not create.");

        private static int Member(string type, string member) => BrovVulkLayout.MemberOffset[type + "." + member];

        private sealed class PassLayout
        {
            public readonly int AttachmentCount, Attachments, SubpassCount, Subpasses, DependencyCount, Dependencies, Next;
            public readonly int AttachmentSize, LoadOp, StencilLoadOp;
            public readonly int SubpassSize, InputCount, Inputs, ColorCount, Colors, Resolves, DepthStencil, PreserveCount, Preserves, ViewMask, SubpassNext;
            public readonly int ReferenceSize, ReferenceAttachment;
            public readonly int DependencySize, Source, Target;

            public PassLayout(bool version2)
            {
                string info = version2 ? "VkRenderPassCreateInfo2" : "VkRenderPassCreateInfo";
                string sub = version2 ? "VkSubpassDescription2" : "VkSubpassDescription";
                string att = version2 ? "VkAttachmentDescription2" : "VkAttachmentDescription";
                string dep = version2 ? "VkSubpassDependency2" : "VkSubpassDependency";
                string reference = version2 ? "VkAttachmentReference2" : "VkAttachmentReference";
                AttachmentCount = Member(info, "attachmentCount");
                Attachments = Member(info, "pAttachments");
                SubpassCount = Member(info, "subpassCount");
                Subpasses = Member(info, "pSubpasses");
                DependencyCount = Member(info, "dependencyCount");
                Dependencies = Member(info, "pDependencies");
                Next = Member(info, "pNext");
                AttachmentSize = BrovVulkLayout.StructSize[att];
                LoadOp = Member(att, "loadOp");
                StencilLoadOp = Member(att, "stencilLoadOp");
                SubpassSize = BrovVulkLayout.StructSize[sub];
                InputCount = Member(sub, "inputAttachmentCount");
                Inputs = Member(sub, "pInputAttachments");
                ColorCount = Member(sub, "colorAttachmentCount");
                Colors = Member(sub, "pColorAttachments");
                Resolves = Member(sub, "pResolveAttachments");
                DepthStencil = Member(sub, "pDepthStencilAttachment");
                PreserveCount = Member(sub, "preserveAttachmentCount");
                Preserves = Member(sub, "pPreserveAttachments");
                ViewMask = version2 ? Member(sub, "viewMask") : -1;
                SubpassNext = version2 ? Member(sub, "pNext") : -1;
                ReferenceSize = BrovVulkLayout.StructSize[reference];
                ReferenceAttachment = Member(reference, "attachment");
                DependencySize = BrovVulkLayout.StructSize[dep];
                Source = Member(dep, "srcSubpass");
                Target = Member(dep, "dstSubpass");
            }
        }

        private static readonly PassLayout Pass1 = new PassLayout(false), Pass2 = new PassLayout(true);
        private static readonly int DepthStencilResolveReference = Member("VkSubpassDescriptionDepthStencilResolve", "pDepthStencilResolveAttachment");
        private static readonly int SubpassRateReference = Member("VkFragmentShadingRateAttachmentInfoKHR", "pFragmentShadingRateAttachment");
        private static readonly int SubpassRateTexel = Member("VkFragmentShadingRateAttachmentInfoKHR", "shadingRateAttachmentTexelSize");
        private static readonly int MultiviewSubpasses = Member("VkRenderPassMultiviewCreateInfo", "subpassCount");
        private static readonly int MultiviewDependencies = Member("VkRenderPassMultiviewCreateInfo", "dependencyCount");
        private static readonly int MultiviewMasks = Member("VkRenderPassMultiviewCreateInfo", "pViewMasks");
        private static readonly int AspectReferenceCount = Member("VkRenderPassInputAttachmentAspectCreateInfo", "aspectReferenceCount");
        private static readonly int AspectReferences = Member("VkRenderPassInputAttachmentAspectCreateInfo", "pAspectReferences");
        private static readonly int AspectReferenceSize = BrovVulkLayout.StructSize["VkInputAttachmentAspectReference"];
        private static readonly int AspectReferenceSubpass = Member("VkInputAttachmentAspectReference", "subpass");
        private static readonly int AspectReferenceInput = Member("VkInputAttachmentAspectReference", "inputAttachmentIndex");
        private static readonly int DensityMapReference = Member("VkRenderPassFragmentDensityMapCreateInfoEXT", "fragmentDensityMapAttachment");

        public unsafe RenderPassShape? ReadRenderPass(IntPtr info, bool version2)
        {
            if (info == IntPtr.Zero)
                return null;

            PassLayout l = version2 ? Pass2 : Pass1;
            uint maxColors = DeviceGapsOf(CallDevice)?.MaxColorAttachments ?? 0;
            byte* p = (byte*)info;

            RenderPassShape shape = new RenderPassShape { Attachments = *(uint*)(p + l.AttachmentCount) };
            byte* attachments = *(byte**)(p + l.Attachments);
            for (uint a = 0; attachments != null && a < shape.Attachments; a++)
            {
                byte* d = attachments + (long)a * l.AttachmentSize;
                if (*(int*)(d + l.LoadOp) == BrovVulkConstants.VK_ATTACHMENT_LOAD_OP_CLEAR || *(int*)(d + l.StencilLoadOp) == BrovVulkConstants.VK_ATTACHMENT_LOAD_OP_CLEAR)
                    shape.ClearValues = a + 1;
            }

            uint subpasses = *(uint*)(p + l.SubpassCount);
            byte* subs = *(byte**)(p + l.Subpasses);
            shape.Colors = new uint[subpasses];
            uint[] inputs = new uint[subpasses];
            uint[] masks = new uint[subpasses];
            bool[] used = new bool[shape.Attachments];
            List<(uint Attachment, uint TexelWidth, uint TexelHeight)>? rates = null;
            for (uint s = 0; subs != null && s < subpasses; s++)
            {
                byte* d = subs + (long)s * l.SubpassSize;
                inputs[s] = *(uint*)(d + l.InputCount);
                shape.Colors[s] = *(uint*)(d + l.ColorCount);
                if (shape.Colors[s] > maxColors)
                    throw new InvalidOperationException($"BrovVulk generic: subpass {s} has {shape.Colors[s]} color attachments of {maxColors}.");
                CheckReferences(shape, *(byte**)(d + l.Inputs), inputs[s], l.ReferenceSize, l.ReferenceAttachment, used);
                CheckReferences(shape, *(byte**)(d + l.Colors), shape.Colors[s], l.ReferenceSize, l.ReferenceAttachment, used);
                CheckReferences(shape, *(byte**)(d + l.Resolves), shape.Colors[s], l.ReferenceSize, l.ReferenceAttachment, used);
                CheckReferences(shape, *(byte**)(d + l.DepthStencil), 1, l.ReferenceSize, l.ReferenceAttachment, used);
                CheckReferences(shape, *(byte**)(d + l.Preserves), *(uint*)(d + l.PreserveCount), sizeof(uint), 0, null);
                if (!version2)
                    continue;

                masks[s] = *(uint*)(d + l.ViewMask);
                for (byte* node = *(byte**)(d + l.SubpassNext); node != null; node = *(byte**)(node + VkOffsets.NodePNext))
                {
                    if (*(int*)node == BrovVulkConstants.VK_STRUCTURE_TYPE_SUBPASS_DESCRIPTION_DEPTH_STENCIL_RESOLVE)
                        CheckReferences(shape, *(byte**)(node + DepthStencilResolveReference), 1, l.ReferenceSize, l.ReferenceAttachment, used);
                    else if (*(int*)node == BrovVulkConstants.VK_STRUCTURE_TYPE_FRAGMENT_SHADING_RATE_ATTACHMENT_INFO_KHR)
                    {
                        byte* rate = *(byte**)(node + SubpassRateReference);
                        CheckReferences(shape, rate, 1, l.ReferenceSize, l.ReferenceAttachment, null);
                        if (rate == null || *(uint*)(rate + l.ReferenceAttachment) == uint.MaxValue)
                            continue;
                        uint* texel = (uint*)(node + SubpassRateTexel);
                        (rates ??= new List<(uint, uint, uint)>()).Add((*(uint*)(rate + l.ReferenceAttachment), texel[0], texel[1]));
                    }
                }
            }

            uint dependencies = *(uint*)(p + l.DependencyCount);
            byte* deps = *(byte**)(p + l.Dependencies);
            for (uint k = 0; deps != null && k < dependencies; k++)
            {
                uint from = *(uint*)(deps + (long)k * l.DependencySize + l.Source), to = *(uint*)(deps + (long)k * l.DependencySize + l.Target);
                if ((from != uint.MaxValue && from >= subpasses) || (to != uint.MaxValue && to >= subpasses))
                    throw new InvalidOperationException($"BrovVulk generic: a dependency names subpass {from} or {to} of {subpasses}.");
            }

            for (byte* node = *(byte**)(p + l.Next); node != null; node = *(byte**)(node + VkOffsets.NodePNext))
            {
                int type = *(int*)node;
                if (type == BrovVulkConstants.VK_STRUCTURE_TYPE_RENDER_PASS_MULTIVIEW_CREATE_INFO && !version2)
                {
                    uint count = *(uint*)(node + MultiviewSubpasses);
                    uint offsets = *(uint*)(node + MultiviewDependencies);
                    if ((count != 0 && count != subpasses) || (offsets != 0 && offsets != dependencies))
                        throw new InvalidOperationException("BrovVulk generic: the multiview counts differ from the render pass.");
                    uint* list = *(uint**)(node + MultiviewMasks);
                    for (uint s = 0; list != null && s < count; s++)
                        masks[s] = list[s];
                }
                else if (type == BrovVulkConstants.VK_STRUCTURE_TYPE_RENDER_PASS_INPUT_ATTACHMENT_ASPECT_CREATE_INFO && !version2)
                {
                    uint count = *(uint*)(node + AspectReferenceCount);
                    byte* list = *(byte**)(node + AspectReferences);
                    for (uint k = 0; list != null && k < count; k++)
                    {
                        uint s = *(uint*)(list + (long)k * AspectReferenceSize + AspectReferenceSubpass);
                        uint index = *(uint*)(list + (long)k * AspectReferenceSize + AspectReferenceInput);
                        if (s >= subpasses || index >= inputs[s])
                            throw new InvalidOperationException($"BrovVulk generic: an aspect reference names input {index} of subpass {s}.");
                    }
                }
                else if (type == BrovVulkConstants.VK_STRUCTURE_TYPE_RENDER_PASS_FRAGMENT_DENSITY_MAP_CREATE_INFO_EXT)
                {
                    byte* map = node + DensityMapReference;
                    CheckReferences(shape, map, 1, Pass1.ReferenceSize, Pass1.ReferenceAttachment, null);
                    shape.DensityMap = *(uint*)(map + Pass1.ReferenceAttachment);
                }
            }

            if (shape.DensityMap != uint.MaxValue && used[shape.DensityMap])
                shape.DensityMap = uint.MaxValue;
            if (rates != null)
            {
                rates.RemoveAll(rate => used[rate.Attachment]);
                shape.ShadingRate = rates.Count != 0 ? rates.ToArray() : null;
            }

            bool multiview = false;
            for (uint s = 0; s < subpasses; s++)
            {
                shape.ViewMask |= masks[s];
                masks[s] = ViewCount(masks[s]);
                multiview |= masks[s] > 1;
            }
            shape.Views = multiview ? masks : null;
            return shape;
        }

        private static unsafe void CheckReferences(RenderPassShape shape, byte* references, uint count, int stride, int attachment, bool[]? used)
        {
            for (uint k = 0; references != null && k < count; k++)
            {
                uint index = *(uint*)(references + (long)k * stride + attachment);
                if (index == uint.MaxValue)
                    continue;
                if (index >= shape.Attachments)
                    throw new InvalidOperationException($"BrovVulk generic: attachment reference {index} is past the render pass's {shape.Attachments} attachments.");
                if (used != null)
                    used[index] = true;
            }
        }

        public void SetRenderPass(IntPtr pass, RenderPassShape? shape)
        {
            if (pass != IntPtr.Zero && shape != null)
                _renderPasses[pass] = shape;
        }

        public void CheckSubpass(IntPtr pass, uint subpass)
        {
            if (pass != IntPtr.Zero && subpass >= (uint)PassOf(pass).Colors.Length)
                throw new InvalidOperationException($"BrovVulk generic: subpass {subpass} is past the render pass's last.");
        }

        public unsafe FramebufferExtent? ReadFramebuffer(IntPtr info)
        {
            if (info == IntPtr.Zero)
                return null;

            byte* p = (byte*)info;
            FramebufferExtent fb = new FramebufferExtent
            {
                Width = *(uint*)(p + FramebufferWidth), Height = *(uint*)(p + FramebufferHeight),
                Layers = *(uint*)(p + FramebufferLayers), Attachments = *(uint*)(p + FramebufferAttachmentCount),
            };
            if (fb.Attachments != PassOf(*(IntPtr*)(p + FramebufferPass)).Attachments)
                throw new InvalidOperationException("BrovVulk generic: the framebuffer's attachment count differs from its render pass.");

            if ((*(uint*)(p + FramebufferFlags) & BrovVulkConstants.VK_FRAMEBUFFER_CREATE_IMAGELESS_BIT) == 0)
            {
                IntPtr* views = *(IntPtr**)(p + FramebufferAttachments);
                fb.Views = new IntPtr[fb.Attachments];
                for (uint a = 0; views != null && a < fb.Attachments; a++)
                    fb.Views[a] = views[a];
                return fb;
            }

            for (byte* node = *(byte**)(p + VkOffsets.NodePNext); node != null; node = *(byte**)(node + VkOffsets.NodePNext))
            {
                if (*(int*)node == BrovVulkConstants.VK_STRUCTURE_TYPE_FRAMEBUFFER_ATTACHMENTS_CREATE_INFO
                    && *(uint*)(node + FramebufferImageInfoCount) == fb.Attachments)
                    return fb;
            }
            throw new InvalidOperationException("BrovVulk generic: an imageless framebuffer needs an image info for each attachment.");
        }

        public void SetFramebuffer(IntPtr framebuffer, FramebufferExtent? extent)
        {
            if (framebuffer == IntPtr.Zero || extent == null)
                return;

            _framebuffers[framebuffer] = extent;
            foreach (IntPtr view in extent.Views ?? Array.Empty<IntPtr>())
            {
                HoldFor(CallDevice, framebuffer, "VkFramebuffer", view, "VkImageView");
                ref HandleEntry entry = ref CollectionsMarshal.GetValueRefOrNullRef(_handles, IdOf(view, "VkImageView"));
                if (!System.Runtime.CompilerServices.Unsafe.IsNullRef(ref entry))
                    entry.Named = ulong.MaxValue;
            }
        }

        public unsafe void BeginRenderPass(IntPtr commandBuffer, IntPtr info)
        {
            Recording rec = OpenRecording(commandBuffer);
            if (rec.Inside || info == IntPtr.Zero)
                throw new InvalidOperationException("BrovVulk generic: a render pass instance is already open.");

            byte* p = (byte*)info;
            RenderPassShape pass = PassOf(*(IntPtr*)(p + BeginPass));
            if (!_framebuffers.TryGetValue(*(IntPtr*)(p + BeginFramebuffer), out FramebufferExtent? fb))
                throw new InvalidOperationException("BrovVulk generic: a framebuffer this layer did not create.");
            if (fb.Attachments != pass.Attachments)
                throw new InvalidOperationException("BrovVulk generic: the framebuffer's attachments differ from the render pass's.");

            IntPtr* views = null;
            byte* group = null;
            for (byte* node = *(byte**)(p + VkOffsets.NodePNext); node != null; node = *(byte**)(node + VkOffsets.NodePNext))
            {
                if (*(int*)node == BrovVulkConstants.VK_STRUCTURE_TYPE_RENDER_PASS_ATTACHMENT_BEGIN_INFO && *(uint*)(node + AttachmentBeginCount) == fb.Attachments)
                    views = *(IntPtr**)(node + AttachmentBeginViews);
                else if (*(int*)node == BrovVulkConstants.VK_STRUCTURE_TYPE_DEVICE_GROUP_RENDER_PASS_BEGIN_INFO)
                    group = node;
            }
            if (fb.Views == null && views == null && fb.Attachments != 0)
                throw new InvalidOperationException("BrovVulk generic: an imageless framebuffer needs one view for each attachment at begin.");

            for (uint a = 0; a < fb.Attachments; a++)
                CheckPassAttachment(pass, a, fb.Views != null ? fb.Views[a] : views[a], fb.Width, fb.Height, fb.Layers);
            ReadArea(p + BeginArea, group, fb.Width, fb.Height, out long left, out long top, out long right, out long bottom);
            PadClearValues(p, pass.ClearValues);

            rec.Inside = rec.AreaKnown = true;
            rec.Left = left;
            rec.Top = top;
            rec.Right = right;
            rec.Bottom = bottom;
            rec.Pass = pass;
            rec.Subpass = 0;
            rec.Views = pass.Views != null ? pass.Views[0] : 1u;
            rec.Colors = pass.Colors.Length != 0 ? pass.Colors[0] : 0u;
            rec.Layers = pass.ViewMask != 0 ? 1u : fb.Layers;

            rec.BoundRenderPass = *(IntPtr*)(p + BeginPass);
            rec.BoundFramebuffer = *(IntPtr*)(p + BeginFramebuffer);
            for (uint a = 0; fb.Views == null && a < fb.Attachments; a++)
                NoteView(rec, views[a]);
        }

        private unsafe void PadClearValues(byte* info, uint needed)
        {
            uint given = *(uint*)(info + BeginClearCount);
            if (given >= needed)
                return;

            int bytes = BrovVulkGenStruct.CheckedBytes(needed, ClearValueSize);
            IntPtr values = Alloc(bytes);
            byte* old = *(byte**)(info + BeginClearValues);
            if (old != null && given != 0)
                Buffer.MemoryCopy(old, (void*)values, bytes, (long)given * ClearValueSize);
            *(uint*)(info + BeginClearCount) = needed;
            *(IntPtr*)(info + BeginClearValues) = values;
        }

        // Drivers may still read renderArea when device group areas replace it.
        private static unsafe void ReadArea(byte* area, byte* group, ulong width, ulong height, out long left, out long top, out long right, out long bottom)
        {
            left = top = long.MaxValue;
            right = bottom = 0;
            AddArea(area, width, height, ref left, ref top, ref right, ref bottom);
            uint count = group != null ? *(uint*)(group + GroupAreaCount) : 0;
            byte* areas = group != null ? *(byte**)(group + GroupAreas) : null;
            for (uint k = 0; areas != null && k < count; k++)
                AddArea(areas + (long)k * Rect2DSize, width, height, ref left, ref top, ref right, ref bottom);
        }

        private static unsafe void AddArea(byte* area, ulong width, ulong height, ref long left, ref long top, ref long right, ref long bottom)
        {
            int* r = (int*)area;
            long x = r[0], y = r[1], w = (uint)r[2], h = (uint)r[3];
            if (x < 0 || y < 0 || (ulong)(x + w) > width || (ulong)(y + h) > height)
                throw new InvalidOperationException($"BrovVulk generic: render area {x},{y} + {w}x{h} is outside the attachments.");
            left = Math.Min(left, x);
            top = Math.Min(top, y);
            right = Math.Max(right, x + w);
            bottom = Math.Max(bottom, y + h);
        }

        private void CheckPassAttachment(RenderPassShape pass, uint index, IntPtr view, ulong width, ulong height, uint layers)
        {
            if (pass.ViewMask != 0)
                layers = ViewLayers(pass.ViewMask);
            if (index == pass.DensityMap)
            {
                CheckAttachment(view, 0, 0, 0, false);
                return;
            }

            bool rate = false;
            foreach ((uint attachment, uint texelWidth, uint texelHeight) in pass.ShadingRate ?? Array.Empty<(uint, uint, uint)>())
            {
                if (attachment != index)
                    continue;
                CheckAttachment(view, DivideUp(width, texelWidth), DivideUp(height, texelHeight), layers, true);
                rate = true;
            }
            if (!rate)
                CheckAttachment(view, width, height, layers, false);
        }

        private static ulong DivideUp(ulong value, uint divisor) => divisor <= 1 ? value : (value + divisor - 1) / divisor;

        private static uint ViewCount(uint mask) => Math.Max(1u, (uint)System.Numerics.BitOperations.PopCount(mask));

        private static uint ViewLayers(uint mask) => 32u - (uint)System.Numerics.BitOperations.LeadingZeroCount(mask);

        private void CheckAttachment(IntPtr view, ulong width, ulong height, uint layers, bool oneLayerServes)
        {
            if (!_views.TryGetValue(view, out (uint Width, uint Height, uint Layers) v))
                throw new InvalidOperationException("BrovVulk generic: an attachment names an image view this layer did not create.");
            if (v.Width < width || v.Height < height || (v.Layers < layers && !(oneLayerServes && v.Layers == 1)))
                throw new InvalidOperationException($"BrovVulk generic: a {v.Width}x{v.Height} attachment with {v.Layers} layers is smaller than {width}x{height} with {layers} layers.");
        }

        public void NextSubpass(IntPtr commandBuffer)
        {
            Recording rec = OpenRecording(commandBuffer);
            if (rec.Pass == null || rec.Secondary || rec.Subpass + 1 >= (uint)rec.Pass.Colors.Length)
                throw new InvalidOperationException("BrovVulk generic: the render pass has no next subpass.");

            rec.Subpass++;
            rec.Views = rec.Pass.Views != null ? rec.Pass.Views[rec.Subpass] : 1u;
            rec.Colors = rec.Pass.Colors[rec.Subpass];
        }

        public void EndInstance(IntPtr commandBuffer, bool renderPass)
        {
            Recording rec = OpenRecording(commandBuffer);
            if (!rec.Inside || !rec.AreaKnown || (rec.Pass != null) != renderPass)
                throw new InvalidOperationException("BrovVulk generic: no render pass instance of that kind is open.");
            rec.EndInstance();
            rec.BoundRenderPass = rec.BoundFramebuffer = IntPtr.Zero;
            rec.ViewsBound = 0;
        }

        public unsafe void BeginRendering(IntPtr commandBuffer, IntPtr info)
        {
            Recording rec = OpenRecording(commandBuffer);
            if (rec.Inside || info == IntPtr.Zero)
                throw new InvalidOperationException("BrovVulk generic: a render pass instance is already open.");

            byte* p = (byte*)info;
            uint colors = *(uint*)(p + RenderingColorCount);
            CheckColorCount(colors);
            uint mask = *(uint*)(p + RenderingViewMask);
            uint layers = mask != 0 ? ViewLayers(mask) : *(uint*)(p + RenderingLayerCount);
            byte* group = null, rate = null;
            for (byte* node = *(byte**)(p + VkOffsets.NodePNext); node != null; node = *(byte**)(node + VkOffsets.NodePNext))
            {
                if (*(int*)node == BrovVulkConstants.VK_STRUCTURE_TYPE_DEVICE_GROUP_RENDER_PASS_BEGIN_INFO)
                    group = node;
                else if (*(int*)node == BrovVulkConstants.VK_STRUCTURE_TYPE_RENDERING_FRAGMENT_SHADING_RATE_ATTACHMENT_INFO_KHR)
                    rate = node;
            }

            ReadArea(p + RenderingArea, group, ulong.MaxValue, ulong.MaxValue, out long left, out long top, out long right, out long bottom);
            byte* list = *(byte**)(p + RenderingColors);
            for (uint k = 0; list != null && k < colors; k++)
                CheckRenderingAttachment(list + (long)k * RenderingAttachmentSize, (ulong)right, (ulong)bottom, layers);
            CheckRenderingAttachment(*(byte**)(p + RenderingDepth), (ulong)right, (ulong)bottom, layers);
            CheckRenderingAttachment(*(byte**)(p + RenderingStencil), (ulong)right, (ulong)bottom, layers);
            if (rate != null && *(IntPtr*)(rate + RateView) != IntPtr.Zero)
                CheckAttachment(*(IntPtr*)(rate + RateView), DivideUp((ulong)right, *(uint*)(rate + RateTexel)), DivideUp((ulong)bottom, *(uint*)(rate + RateTexel + 4)), layers, true);

            rec.Inside = rec.AreaKnown = true;
            rec.Left = left;
            rec.Top = top;
            rec.Right = right;
            rec.Bottom = bottom;
            rec.Pass = null;
            rec.Views = ViewCount(mask);
            rec.Colors = colors;
            rec.Layers = mask != 0 ? 1u : *(uint*)(p + RenderingLayerCount);

            for (uint k = 0; list != null && k < colors; k++)
                NoteRenderingAttachment(rec, list + (long)k * RenderingAttachmentSize);
            NoteRenderingAttachment(rec, *(byte**)(p + RenderingDepth));
            NoteRenderingAttachment(rec, *(byte**)(p + RenderingStencil));
            if (rate != null)
                NoteView(rec, *(IntPtr*)(rate + RateView));
        }

        private static unsafe void NoteRenderingAttachment(Recording rec, byte* attachment)
        {
            if (attachment == null)
                return;
            NoteView(rec, *(IntPtr*)(attachment + RenderingAttachmentView));
            if (*(int*)(attachment + RenderingAttachmentResolveMode) != 0)
                NoteView(rec, *(IntPtr*)(attachment + RenderingAttachmentResolveView));
        }

        private unsafe void CheckRenderingAttachment(byte* attachment, ulong width, ulong height, uint layers)
        {
            if (attachment == null)
                return;

            IntPtr view = *(IntPtr*)(attachment + RenderingAttachmentView);
            if (view != IntPtr.Zero)
                CheckAttachment(view, width, height, layers, false);
            IntPtr resolve = *(IntPtr*)(attachment + RenderingAttachmentResolveView);
            if (resolve != IntPtr.Zero && *(int*)(attachment + RenderingAttachmentResolveMode) != 0)
                CheckAttachment(resolve, width, height, layers, false);
        }

        public unsafe void BeginRecording(IntPtr commandBuffer, IntPtr beginInfo, bool commit)
        {
            Recording rec = RecordingOf(commandBuffer);
            bool continues = rec.Secondary && beginInfo != IntPtr.Zero
                && (*(uint*)(beginInfo + BeginInfoFlags) & BrovVulkConstants.VK_COMMAND_BUFFER_USAGE_RENDER_PASS_CONTINUE_BIT) != 0;
            RenderPassShape? pass = null;
            uint subpass = 0, colors = 0, views = 1;
            if (continues)
            {
                byte* inheritance = *(byte**)(beginInfo + BeginInfoInheritance);
                if (inheritance == null)
                    throw new InvalidOperationException("BrovVulk generic: a secondary that continues a render pass needs its inheritance info.");

                IntPtr handle = *(IntPtr*)(inheritance + InheritancePass);
                if (handle != IntPtr.Zero)
                {
                    pass = PassOf(handle);
                    subpass = *(uint*)(inheritance + InheritanceSubpass);
                    if (subpass >= (uint)pass.Colors.Length)
                        throw new InvalidOperationException($"BrovVulk generic: inherited subpass {subpass} is past the render pass's last.");
                    colors = pass.Colors[subpass];
                    views = pass.Views != null ? pass.Views[subpass] : 1u;
                }
                else
                {
                    byte* rendering = FindNode((IntPtr)inheritance, BrovVulkConstants.VK_STRUCTURE_TYPE_COMMAND_BUFFER_INHERITANCE_RENDERING_INFO);
                    if (rendering != null)
                    {
                        colors = *(uint*)(rendering + InheritanceColors);
                        views = ViewCount(*(uint*)(rendering + InheritanceViewMask));
                    }
                    if (colors > CallColorLimit)
                        throw new InvalidOperationException($"BrovVulk generic: {colors} inherited color attachments of {CallColorLimit}.");
                }
            }

            if (!commit)
                return;
            LetGo(commandBuffer, "VkCommandBuffer");
            ClearBound(rec);
            rec.Restart(++_recordingGeneration, RecordingState.Recording);
            if (_openRecordings.Count == 0)
            {
                _oldestOpen = rec.Generation;
                _oldestLeft = false;
            }
            _openRecordings.Add(rec);
            if (!continues)
                return;
            rec.Inside = rec.Continues = true;
            rec.Pass = pass;
            rec.Subpass = subpass;
            rec.Colors = colors;
            rec.Views = views;
        }

        public void EndRecording(IntPtr commandBuffer)
        {
            Recording rec = OpenRecording(commandBuffer);
            if (rec.Inside && !rec.Continues)
                throw new InvalidOperationException("BrovVulk generic: a render pass instance is still open at the end of the recording.");
            rec.State = RecordingState.Executable;
            ClearBound(rec);
        }

        public unsafe void CheckClearAttachments(IntPtr commandBuffer, uint count, IntPtr attachments, uint rectCount, IntPtr rects)
        {
            Recording rec = OpenRecording(commandBuffer);
            if (!rec.Inside)
                throw new InvalidOperationException("BrovVulk generic: vkCmdClearAttachments outside a render pass instance.");

            for (uint k = 0; attachments != IntPtr.Zero && k < count; k++)
            {
                byte* a = (byte*)attachments + (long)k * ClearAttachmentSize;
                if ((*(uint*)(a + ClearAttachmentAspect) & BrovVulkConstants.VK_IMAGE_ASPECT_COLOR_BIT) == 0)
                    continue;
                uint index = *(uint*)(a + ClearAttachmentIndex);
                if (index >= rec.Colors)
                    throw new InvalidOperationException($"BrovVulk generic: color attachment {index} of {rec.Colors} cleared.");
                rec.NeedColors = Math.Max(rec.NeedColors, index + 1);
            }

            for (uint k = 0; rects != IntPtr.Zero && k < rectCount; k++)
            {
                byte* rect = (byte*)rects + (long)k * ClearRectSize;
                long x = *(int*)rect, y = *(int*)(rect + 4), right = x + *(uint*)(rect + 8), bottom = y + *(uint*)(rect + 12);
                ulong top = (ulong)*(uint*)(rect + ClearRectBaseLayer) + *(uint*)(rect + ClearRectLayers);
                if (x < 0 || y < 0 || *(uint*)(rect + ClearRectLayers) == 0
                    || (rec.AreaKnown && (x < rec.Left || y < rec.Top || right > rec.Right || bottom > rec.Bottom || top > rec.Layers)))
                    throw new InvalidOperationException($"BrovVulk generic: clear rect {x},{y} to {right},{bottom} with layers to {top} is outside the render area.");
                rec.NeedRight = Math.Max(rec.NeedRight, right);
                rec.NeedBottom = Math.Max(rec.NeedBottom, bottom);
                rec.NeedLayers = (uint)Math.Max(rec.NeedLayers, Math.Min(top, uint.MaxValue));
            }
        }

        public unsafe void ExecuteCommands(IntPtr commandBuffer, uint count, IntPtr buffers)
        {
            Recording rec = OpenRecording(commandBuffer);
            for (uint k = 0; buffers != IntPtr.Zero && k < count; k++)
            {
                IntPtr buffer = ((IntPtr*)buffers)[k];
                Recording inner = RecordingOf(buffer);
                if (!inner.Secondary || inner.State != RecordingState.Executable || inner.Continues != rec.Inside
                    || (inner.Continues && inner.Views != rec.Views))
                    throw new InvalidOperationException("BrovVulk generic: a secondary runs where it was not recorded to run.");

                if (rec.AreaKnown)
                {
                    if (inner.NeedRight > rec.Right || inner.NeedBottom > rec.Bottom || inner.NeedLayers > rec.Layers || inner.NeedColors > rec.Colors)
                        throw new InvalidOperationException("BrovVulk generic: a secondary clears outside the render area that runs it.");
                }
                else
                {
                    rec.NeedRight = Math.Max(rec.NeedRight, inner.NeedRight);
                    rec.NeedBottom = Math.Max(rec.NeedBottom, inner.NeedBottom);
                    rec.NeedLayers = Math.Max(rec.NeedLayers, inner.NeedLayers);
                    rec.NeedColors = Math.Max(rec.NeedColors, inner.NeedColors);
                }

                rec.Executed ??= new Dictionary<IntPtr, ulong>();
                rec.Executed[buffer] = rec.Executed.TryGetValue(buffer, out ulong seen) && seen != inner.Generation ? 0 : inner.Generation;
            }

            // Vulkan leaves the primary's bindings undefined after executing secondaries.
            Array.Clear(rec.Reads);
            Array.Clear(rec.BoundSets);
        }

        public void BeginSubmitBatch()
        {
            _submitScratch.Clear();
            _submitPath.Clear();
        }

        public void CollectSubmitted(IntPtr commandBuffer, List<IntPtr> into) => Collect(commandBuffer, into, 0);

        private void Collect(IntPtr commandBuffer, List<IntPtr> into, int depth)
        {
            if (!_recordings.TryGetValue(commandBuffer, out Recording? rec) || rec.State != RecordingState.Executable || (depth == 0 && rec.Secondary))
                throw new InvalidOperationException("BrovVulk generic: a submitted command buffer is not an executable primary.");
            if (_submitPath.Contains(commandBuffer))
                throw new InvalidOperationException("BrovVulk generic: command buffers run each other in a cycle.");
            if (!_submitScratch.Add(commandBuffer))
                return;

            into.Add(commandBuffer);
            CheckNotes(rec);
            CheckOffsets(rec);
            if (rec.Executed == null || rec.Executed.Count == 0)
                return;
            if (depth >= MaxSecondaryNesting)
                throw new InvalidOperationException("BrovVulk generic: secondaries nest deeper than this layer checks.");

            _submitPath.Add(commandBuffer);
            foreach (KeyValuePair<IntPtr, ulong> entry in rec.Executed)
            {
                if (!_recordings.TryGetValue(entry.Key, out Recording? inner) || inner.Generation != entry.Value)
                    throw new InvalidOperationException("BrovVulk generic: a secondary was reset, recorded again or freed after a primary ran it.");
                Collect(entry.Key, into, depth + 1);
            }
            _submitPath.RemoveAt(_submitPath.Count - 1);
        }

        private void NoteHandle(uint id, IntPtr ptr, string type, ulong serial)
        {
            if (IsDispatchable(type) || UnrecordedTypes.Contains(type))
                return;

            Recording rec = _callRecording!;
            rec.Notes ??= new Dictionary<uint, ulong>();
            if (!rec.Notes.TryAdd(id, serial))
                return;
            if (type == "VkImageView")
                NoteViewImage(rec, ptr);
            else if (type == "VkFramebuffer" && _holdsOf.TryGetValue((ptr, type), out (IntPtr Device, List<(IntPtr Ptr, string Type)> Objects) held))
            {
                foreach ((IntPtr Ptr, string Type) obj in held.Objects)
                    NoteObject(rec, obj.Ptr, obj.Type);
            }
            IntPtr pool = type == "VkQueryPool" ? ptr : type == "VkDescriptorSet" ? PoolOfSet(ptr) : IntPtr.Zero;
            if (pool != IntPtr.Zero)
                (rec.UsedPools ??= new HashSet<IntPtr>()).Add(pool);
        }

        private void NoteObject(Recording rec, IntPtr ptr, string type)
        {
            uint id = IdOf(ptr, type);
            if (id == 0 || !_handles.TryGetValue(id, out HandleEntry e))
                throw new InvalidOperationException($"BrovVulk generic: a recording names a view whose {type} is gone.");
            if (rec.Notes!.TryAdd(id, e.Serial) && type == "VkImageView")
                NoteViewImage(rec, ptr);
        }

        private void NoteViewImage(Recording rec, IntPtr view)
        {
            if (!_viewImages.TryGetValue(view, out (uint Id, ulong Serial) shown))
                return;
            if (!_handles.TryGetValue(shown.Id, out HandleEntry image) || image.Serial != shown.Serial)
                throw new InvalidOperationException("BrovVulk generic: a recording names a view whose image is gone.");
            rec.Notes!.TryAdd(shown.Id, shown.Serial);
        }

        // CPU drivers can follow recorded handles at submit time.
        private void CheckNotes(Recording rec)
        {
            if (rec.Notes == null)
                return;

            foreach (KeyValuePair<uint, ulong> note in rec.Notes)
            {
                if (!_handles.TryGetValue(note.Key, out HandleEntry e) || e.Serial != note.Value)
                    throw new InvalidOperationException("BrovVulk generic: a recording names an object that was destroyed after it was recorded.");
            }
        }

        private void CheckOffsets(Recording rec)
        {
            if (rec.Offsets == null)
                return;

            foreach (KeyValuePair<IntPtr, uint[]> entry in rec.Offsets)
            {
                if (!_sets.TryGetValue(entry.Key, out SetRecord? set) || set.Limits == null || set.Limits.Length != entry.Value.Length)
                    throw new InvalidOperationException("BrovVulk generic: a descriptor set bound with dynamic offsets was freed.");
                for (int j = 0; j < entry.Value.Length; j++)
                {
                    if (entry.Value[j] > set.Limits[j])
                        throw new InvalidOperationException("BrovVulk generic: a descriptor set changed after a recording bound it with dynamic offsets.");
                }
            }
        }

        internal sealed class SetLayoutShape
        {
            internal readonly record struct Binding(uint Number, uint Count, uint Type, uint FirstDynamic);

            public Binding[] Bindings = Array.Empty<Binding>();
            public uint Dynamic;
            public bool VariableLast;
            public uint[]?[]? Mutable;
            public uint[] First = Array.Empty<uint>();
            public ulong Total;
            public ulong InlineBytes;
            public IntPtr[]?[]? Immutable;
            public bool Push;
            public bool AfterBindPool;
            // Sampler descriptors contain no address, so a torn read stays in bounds.
            public bool[]? WhilePending;
            public uint DynamicUniform;
            public uint DynamicStorage;

            public int IndexOf(uint number)
            {
                for (int k = 0; k < Bindings.Length; k++)
                {
                    if (Bindings[k].Number == number)
                        return k;
                }
                return -1;
            }
        }

        public unsafe SetLayoutShape? ReadSetLayout(IntPtr info)
        {
            if (info == IntPtr.Zero)
                return null;

            byte* p = (byte*)info;
            uint count = *(uint*)(p + SetLayoutBindingCount);
            byte* list = *(byte**)(p + SetLayoutBindings);
            if (list == null && count != 0)
                throw new InvalidOperationException("BrovVulk generic: a set layout with bindings and no binding array.");

            uint* flags = null;
            uint flagCount = 0, mutableCount = 0;
            byte* mutableLists = null;
            for (byte* node = *(byte**)(p + VkOffsets.NodePNext); node != null; node = *(byte**)(node + VkOffsets.NodePNext))
            {
                if (*(int*)node == BrovVulkConstants.VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_BINDING_FLAGS_CREATE_INFO)
                {
                    flagCount = *(uint*)(node + BindingFlagsCount);
                    flags = *(uint**)(node + BindingFlagsList);
                }
                else if (*(int*)node == BrovVulkConstants.VK_STRUCTURE_TYPE_MUTABLE_DESCRIPTOR_TYPE_CREATE_INFO_EXT)
                {
                    mutableCount = *(uint*)(node + MutableListCount);
                    mutableLists = *(byte**)(node + MutableLists);
                }
            }
            if (flagCount != 0 && (flagCount != count || flags == null))
                throw new InvalidOperationException("BrovVulk generic: the binding flags do not match the bindings.");

            uint[] numbers = new uint[count];
            int[] order = new int[count];
            for (uint k = 0; k < count; k++)
            {
                numbers[k] = *(uint*)(list + (long)k * SetLayoutBindingSize + BindingNumber);
                order[k] = (int)k;
            }
            Array.Sort(numbers, order);

            VulkanStandIns.DeviceGaps? gaps = DeviceGapsOf(CallDevice);
            ulong maxDynamic = gaps != null ? (ulong)gaps.MaxUniformBuffersDynamic + gaps.MaxStorageBuffersDynamic : 0;
            uint layoutFlags = *(uint*)(p + SetLayoutFlags);
            SetLayoutShape shape = new SetLayoutShape
            {
                Bindings = new SetLayoutShape.Binding[count], First = new uint[count],
                Push = (layoutFlags & BrovVulkConstants.VK_DESCRIPTOR_SET_LAYOUT_CREATE_PUSH_DESCRIPTOR_BIT) != 0,
                AfterBindPool = (layoutFlags & BrovVulkConstants.VK_DESCRIPTOR_SET_LAYOUT_CREATE_UPDATE_AFTER_BIND_POOL_BIT) != 0,
            };
            for (int k = 0; k < order.Length; k++)
            {
                if (k != 0 && numbers[k] == numbers[k - 1])
                    throw new InvalidOperationException($"BrovVulk generic: binding {numbers[k]} appears twice in the set layout.");

                byte* binding = list + (long)order[k] * SetLayoutBindingSize;
                uint descriptors = *(uint*)(binding + BindingCount);
                int type = *(int*)(binding + BindingType);
                bool dynamic = type == BrovVulkConstants.VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC || type == BrovVulkConstants.VK_DESCRIPTOR_TYPE_STORAGE_BUFFER_DYNAMIC;
                bool variable = flagCount != 0 && (flags[order[k]] & BrovVulkConstants.VK_DESCRIPTOR_BINDING_VARIABLE_DESCRIPTOR_COUNT_BIT) != 0;
                if (dynamic && shape.Dynamic + (ulong)descriptors > maxDynamic)
                    throw new InvalidOperationException($"BrovVulk generic: the set layout has more dynamic descriptors than the device's {maxDynamic}.");
                if (variable && (dynamic || k != order.Length - 1))
                    throw new InvalidOperationException("BrovVulk generic: only the highest binding may take a variable count, and not a dynamic one.");
                if (dynamic && (shape.Push || shape.AfterBindPool))
                    throw new InvalidOperationException("BrovVulk generic: a push descriptor or update-after-bind set layout with a dynamic binding.");
                if (type == BrovVulkConstants.VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC)
                    shape.DynamicUniform += descriptors;
                else if (type == BrovVulkConstants.VK_DESCRIPTOR_TYPE_STORAGE_BUFFER_DYNAMIC)
                    shape.DynamicStorage += descriptors;
                if (flagCount != 0 && (flags[order[k]] & (BrovVulkConstants.VK_DESCRIPTOR_BINDING_UPDATE_AFTER_BIND_BIT | BrovVulkConstants.VK_DESCRIPTOR_BINDING_UPDATE_UNUSED_WHILE_PENDING_BIT)) != 0
                    && type == BrovVulkConstants.VK_DESCRIPTOR_TYPE_SAMPLER)
                    (shape.WhilePending ??= new bool[count])[k] = true;

                shape.Bindings[k] = new SetLayoutShape.Binding(numbers[k], descriptors, (uint)type, dynamic ? shape.Dynamic : uint.MaxValue);
                if (dynamic)
                    shape.Dynamic += descriptors;
                shape.VariableLast |= variable;
                bool inline = type == BrovVulkConstants.VK_DESCRIPTOR_TYPE_INLINE_UNIFORM_BLOCK;
                if (inline && (descriptors > (gaps?.MaxInlineUniformBlockSize ?? 0) || (descriptors & 3) != 0))
                    throw new InvalidOperationException($"BrovVulk generic: an inline uniform block of {descriptors} bytes.");
                shape.First[k] = inline || shape.Total > uint.MaxValue ? uint.MaxValue : (uint)shape.Total;
                if (!inline)
                    shape.Total += descriptors;
                else
                    shape.InlineBytes += descriptors;
                IntPtr* immutable = *(IntPtr**)(binding + BindingImmutable);
                if (immutable != null && descriptors != 0
                    && (type == BrovVulkConstants.VK_DESCRIPTOR_TYPE_SAMPLER || type == BrovVulkConstants.VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER))
                    (shape.Immutable ??= new IntPtr[]?[count])[k] = new ReadOnlySpan<IntPtr>(immutable, (int)Math.Min(descriptors, int.MaxValue)).ToArray();

                if (type != BrovVulkConstants.VK_DESCRIPTOR_TYPE_MUTABLE_EXT)
                    continue;
                uint[] allowed = Array.Empty<uint>();
                if (mutableLists != null && (uint)order[k] < mutableCount)
                {
                    byte* entry = mutableLists + (long)order[k] * MutableListSize;
                    uint types = *(uint*)(entry + MutableTypeCount);
                    uint* values = *(uint**)(entry + MutableTypes);
                    allowed = new uint[values != null ? types : 0];
                    for (int i = 0; i < allowed.Length; i++)
                    {
                        allowed[i] = values[i];
                        if (allowed[i] == BrovVulkConstants.VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC || allowed[i] == BrovVulkConstants.VK_DESCRIPTOR_TYPE_STORAGE_BUFFER_DYNAMIC
                            || allowed[i] == BrovVulkConstants.VK_DESCRIPTOR_TYPE_INLINE_UNIFORM_BLOCK || allowed[i] == BrovVulkConstants.VK_DESCRIPTOR_TYPE_MUTABLE_EXT)
                            throw new InvalidOperationException($"BrovVulk generic: a mutable descriptor may not take type {allowed[i]}.");
                    }
                }
                (shape.Mutable ??= new uint[]?[count])[k] = allowed;
            }

            if (shape.Total + shape.InlineBytes > MaxCpuSetDescriptors && Retire.IsCpu(CallDevice))
                throw new InvalidOperationException($"BrovVulk generic: a CPU device set layout with {shape.Total} descriptors and {shape.InlineBytes} inline bytes.");
            if (shape.Push && shape.Total > (gaps?.MaxPushDescriptors ?? 0))
                throw new InvalidOperationException($"BrovVulk generic: a push descriptor set layout with {shape.Total} descriptors of {gaps?.MaxPushDescriptors ?? 0}.");
            return shape;
        }

        public unsafe void CheckPipelineLayout(IntPtr info)
        {
            VulkanStandIns.DeviceGaps? gaps = DeviceGapsOf(CallDevice);
            uint count = *(uint*)(info + PipelineLayoutSetCount);
            IntPtr* layouts = *(IntPtr**)(info + PipelineLayoutSets);
            if (count > (gaps?.MaxBoundDescriptorSets ?? 0))
                throw new InvalidOperationException($"BrovVulk generic: a pipeline layout with {count} sets of the device's {gaps?.MaxBoundDescriptorSets ?? 0}.");
            ulong uniform = 0, storage = 0;
            int push = 0;
            for (uint k = 0; layouts != null && k < count; k++)
            {
                if (!_setLayouts.TryGetValue(layouts[k], out SetLayoutShape? shape))
                    continue;
                uniform += shape.DynamicUniform;
                storage += shape.DynamicStorage;
                push += shape.Push ? 1 : 0;
            }
            if (uniform > (gaps?.MaxUniformBuffersDynamic ?? 0) || storage > (gaps?.MaxStorageBuffersDynamic ?? 0) || push > 1)
                throw new InvalidOperationException("BrovVulk generic: the pipeline layout's dynamic or push descriptors exceed the device's limits.");

            uint ranges = *(uint*)(info + PipelineLayoutRangeCount);
            byte* range = *(byte**)(info + PipelineLayoutRanges);
            for (uint k = 0; range != null && k < ranges; k++)
            {
                uint offset = *(uint*)(range + (long)k * PushRangeSize + PushRangeOffset), size = *(uint*)(range + (long)k * PushRangeSize + PushRangeBytes);
                uint limit = gaps?.MaxPushConstantsSize ?? 0;
                if (offset > limit || size > limit - offset)
                    throw new InvalidOperationException($"BrovVulk generic: push constants {offset}+{size} past the device's {limit} bytes.");
            }
        }

        private SetLayoutShape? ShapeAt(IntPtr layout, uint set) =>
            _layoutSets.TryGetValue(layout, out SetLayoutShape?[]? shapes) && set < (uint)shapes.Length ? shapes[set] : null;

        public bool LayoutBinding(IntPtr layout, uint set, uint binding, out long count, out int type)
        {
            count = -1;
            type = -1;
            if (ShapeAt(layout, set) is not SetLayoutShape shape)
                return false;
            int index = shape.IndexOf(binding);
            if (index < 0)
                return false;
            count = shape.Bindings[index].Count;
            type = (int)shape.Bindings[index].Type;
            return true;
        }

        public void SetSetLayout(IntPtr layout, SetLayoutShape? shape)
        {
            if (layout == IntPtr.Zero || shape == null)
                return;

            _setLayouts[layout] = shape;
            for (int k = 0; shape.Immutable != null && k < shape.Immutable.Length; k++)
            {
                foreach (IntPtr sampler in shape.Immutable[k] ?? Array.Empty<IntPtr>())
                    HoldFor(CallDevice, layout, "VkDescriptorSetLayout", sampler, "VkSampler");
            }
        }

        private void HoldFor(IntPtr device, IntPtr holder, string holderType, IntPtr obj, string objType)
        {
            if (holder == IntPtr.Zero || obj == IntPtr.Zero || !Retire.IsCpu(device))
                return;

            if (!_holdsOf.TryGetValue((holder, holderType), out (IntPtr Device, List<(IntPtr Ptr, string Type)> Objects) held))
            {
                held = (device, new List<(IntPtr, string)>());
                _holdsOf[(holder, holderType)] = held;
            }
            held.Objects.Add((obj, objType));
            Retire.Hold(device, obj, objType);
        }

        private void LetGo(IntPtr holder, string holderType)
        {
            if (_holdsOf.Count != 0 && _holdsOf.Remove((holder, holderType), out (IntPtr Device, List<(IntPtr Ptr, string Type)> Objects) held))
                Retire.Unhold(held.Device, IntPtr.Zero, null, held.Objects.ToArray());
        }

        public unsafe void SetBufferView(IntPtr view, IntPtr info)
        {
            if (info != IntPtr.Zero)
                HoldFor(CallDevice, view, "VkBufferView", *(IntPtr*)(info + BufferViewInfoBuffer), "VkBuffer");
        }

        public void HoldMemory(IntPtr device, IntPtr resource, string type, IntPtr memory) => HoldFor(device, resource, type, memory, "VkDeviceMemory");

        public unsafe void HoldMemories(IntPtr device, IntPtr infos, uint count, bool images)
        {
            int size = images ? BindImageInfoSize : BindBufferInfoSize;
            int resource = images ? BindImageInfoImage : BindBufferInfoBuffer;
            int memory = images ? BindImageInfoMemory : BindBufferInfoMemory;
            for (uint k = 0; infos != IntPtr.Zero && k < count; k++)
            {
                byte* info = (byte*)infos + (long)k * size;
                HoldFor(device, *(IntPtr*)(info + resource), images ? "VkImage" : "VkBuffer", *(IntPtr*)(info + memory), "VkDeviceMemory");
            }
        }

        private sealed class SetRecord
        {
            public SetLayoutShape Layout = null!;
            public uint Variable;
            public uint[]? Limits;
            public IntPtr Device;
            public bool Cpu;
            public IntPtr[]? Resources;
            public IntPtr[]? Samplers;
            public byte[]? Kinds;
            public int Gone;
            public IntPtr[]? Swapchains;
        }

        private const byte HeldBuffer = 1, HeldImageView = 2, HeldBufferView = 3, HeldGone = 4;

        private static string HeldType(byte kind) => kind switch
        {
            HeldBuffer => "VkBuffer",
            HeldImageView => "VkImageView",
            _ => "VkBufferView",
        };

        private static unsafe byte* FindNode(IntPtr info, int sType)
        {
            for (byte* node = *(byte**)(info + VkOffsets.NodePNext); node != null; node = *(byte**)(node + VkOffsets.NodePNext))
            {
                if (*(int*)node == sType)
                    return node;
            }
            return null;
        }

        // CPU shaders clamp to the layout count. Guest writes use the requested count.
        public unsafe void ForceVariableCounts(IntPtr device, IntPtr info)
        {
            _guestVariableCounts = null;
            if (info == IntPtr.Zero || !Retire.IsCpu(device))
                return;

            uint count = *(uint*)(info + AllocateSetCount);
            IntPtr* layouts = *(IntPtr**)(info + AllocateSetLayouts);
            bool variable = false;
            for (uint k = 0; layouts != null && k < count; k++)
                variable |= _setLayouts.TryGetValue(layouts[k], out SetLayoutShape? shape) && shape.VariableLast;
            if (!variable)
                return;

            byte* node = FindNode(info, BrovVulkConstants.VK_STRUCTURE_TYPE_DESCRIPTOR_SET_VARIABLE_DESCRIPTOR_COUNT_ALLOCATE_INFO);
            uint given = node != null ? *(uint*)(node + VariableSetCount) : 0;
            uint* old = node != null ? *(uint**)(node + VariableCountsList) : null;
            _guestVariableCounts = new uint[count];
            uint* counts = (uint*)Alloc(BrovVulkGenStruct.CheckedBytes(count, sizeof(uint)));
            for (uint k = 0; k < count; k++)
            {
                _guestVariableCounts[k] = old != null && k < given ? old[k] : 0;
                counts[k] = layouts != null && _setLayouts.TryGetValue(layouts[k], out SetLayoutShape? shape) && shape.VariableLast
                    ? shape.Bindings[^1].Count : 0;
            }

            if (node == null)
            {
                node = (byte*)Alloc(VariableCountsSize);
                *(int*)node = BrovVulkConstants.VK_STRUCTURE_TYPE_DESCRIPTOR_SET_VARIABLE_DESCRIPTOR_COUNT_ALLOCATE_INFO;
                *(IntPtr*)(node + VkOffsets.NodePNext) = *(IntPtr*)(info + VkOffsets.NodePNext);
                *(IntPtr*)(info + VkOffsets.NodePNext) = (IntPtr)node;
            }
            *(uint*)(node + VariableSetCount) = count;
            *(uint**)(node + VariableCountsList) = counts;
        }

        public unsafe void AddSets(IntPtr device, IntPtr info, IntPtr sets, uint count)
        {
            if (info == IntPtr.Zero || sets == IntPtr.Zero)
                return;

            IntPtr* layouts = *(IntPtr**)(info + AllocateSetLayouts);
            byte* node = FindNode(info, BrovVulkConstants.VK_STRUCTURE_TYPE_DESCRIPTOR_SET_VARIABLE_DESCRIPTOR_COUNT_ALLOCATE_INFO);
            uint* variable = node != null ? *(uint**)(node + VariableCountsList) : null;
            uint variableCount = node != null ? *(uint*)(node + VariableSetCount) : 0;
            uint[]? guest = _guestVariableCounts;
            _guestVariableCounts = null;

            bool cpu = Retire.IsCpu(device);
            for (uint k = 0; layouts != null && k < count; k++)
            {
                if (!_setLayouts.TryGetValue(layouts[k], out SetLayoutShape? shape))
                    continue;
                _sets[((IntPtr*)sets)[k]] = new SetRecord
                {
                    Layout = shape,
                    Variable = !shape.VariableLast ? 0 : guest != null ? (k < guest.Length ? guest[k] : 0) : variable != null && k < variableCount ? variable[k] : 0,
                    Limits = shape.Dynamic != 0 ? new uint[shape.Dynamic] : null,
                    Device = device,
                    Cpu = cpu,
                };
                for (int b = 0; cpu && shape.Immutable != null && b < shape.Immutable.Length; b++)
                {
                    foreach (IntPtr sampler in shape.Immutable[b] ?? Array.Empty<IntPtr>())
                    {
                        if (sampler != IntPtr.Zero)
                            Retire.Hold(device, sampler, "VkSampler");
                    }
                }
            }
        }

        private void ReleaseSet(IntPtr handle)
        {
            if (!_sets.Remove(handle, out SetRecord? set) || !set.Cpu)
                return;

            _released.Clear();
            for (int b = 0; set.Layout.Immutable != null && b < set.Layout.Immutable.Length; b++)
            {
                foreach (IntPtr sampler in set.Layout.Immutable[b] ?? Array.Empty<IntPtr>())
                {
                    if (sampler != IntPtr.Zero)
                        _released.Add((sampler, "VkSampler"));
                }
            }
            if (set.Resources != null)
            {
                for (int slot = 0; slot < set.Resources.Length; slot++)
                {
                    if (set.Resources[slot] != IntPtr.Zero)
                        _released.Add((set.Resources[slot], HeldType(set.Kinds![slot])));
                    if (set.Samplers![slot] != IntPtr.Zero)
                        _released.Add((set.Samplers[slot], "VkSampler"));
                }
                _heldDescriptors -= set.Resources.Length;
            }
            if (_released.Count != 0)
                Retire.Unhold(set.Device, IntPtr.Zero, null, _released.ToArray());
        }

        // Vulkan updates can span consecutive bindings of the same type.
        private struct DescriptorCursor
        {
            private readonly SetLayoutShape _layout;
            private readonly uint _variable;
            private int _index;
            private uint _element;

            public DescriptorCursor(SetLayoutShape layout, uint variable, uint binding, uint element)
            {
                _layout = layout;
                _variable = variable;
                _element = element;
                _index = layout.IndexOf(binding);
                if (_index < 0)
                    throw new InvalidOperationException($"BrovVulk generic: binding {binding} is not in the set layout.");
                Type = layout.Bindings[_index].Type;
            }

            public uint Type { get; }

            public int Index => _index;

            private uint CountAt(int index)
            {
                uint count = _layout.Bindings[index].Count;
                return _layout.VariableLast && index == _layout.Bindings.Length - 1 ? Math.Min(count, _variable) : count;
            }

            public uint Available()
            {
                while (_element >= CountAt(_index))
                {
                    _element -= CountAt(_index);
                    do
                    {
                        if (++_index >= _layout.Bindings.Length)
                            throw new InvalidOperationException("BrovVulk generic: a descriptor update runs past its bindings.");
                    }
                    while (CountAt(_index) == 0);
                    if (_layout.Bindings[_index].Type != Type)
                        throw new InvalidOperationException("BrovVulk generic: a descriptor update runs into a binding of another type.");
                }
                return CountAt(_index) - _element;
            }

            public uint Slot(uint offset)
            {
                uint first = _layout.Bindings[_index].FirstDynamic;
                return first == uint.MaxValue ? uint.MaxValue : first + _element + offset;
            }

            public uint Descriptor(uint offset)
            {
                uint first = _layout.First[_index];
                return first == uint.MaxValue ? uint.MaxValue : first + _element + offset;
            }

            public bool Immutable => _layout.Immutable?[_index] != null;

            public IntPtr ImmutableSampler(uint offset)
            {
                IntPtr[]? samplers = _layout.Immutable?[_index];
                return samplers != null && _element + offset < (uint)samplers.Length ? samplers[_element + offset] : IntPtr.Zero;
            }

            public void Advance(uint count) => _element += count;
        }

        // Drivers can use the pNext count instead of descriptorCount.
        private static unsafe void CheckWriteCount(int type, byte* write)
        {
            int sType, member;
            switch (type)
            {
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_SAMPLER:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_STORAGE_IMAGE:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_UNIFORM_TEXEL_BUFFER:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_STORAGE_TEXEL_BUFFER:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_STORAGE_BUFFER:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_STORAGE_BUFFER_DYNAMIC:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_INPUT_ATTACHMENT:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_SAMPLE_WEIGHT_IMAGE_QCOM:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_BLOCK_MATCH_IMAGE_QCOM:
                    return;
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_INLINE_UNIFORM_BLOCK:
                    sType = BrovVulkConstants.VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET_INLINE_UNIFORM_BLOCK;
                    member = InlineWriteBytes;
                    break;
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_ACCELERATION_STRUCTURE_KHR:
                    sType = BrovVulkConstants.VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET_ACCELERATION_STRUCTURE_KHR;
                    member = AccelerationWriteCount;
                    break;
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_ACCELERATION_STRUCTURE_NV:
                    sType = BrovVulkConstants.VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET_ACCELERATION_STRUCTURE_NV;
                    member = AccelerationWriteCountNv;
                    break;
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_PARTITIONED_ACCELERATION_STRUCTURE_NV:
                    sType = BrovVulkConstants.VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET_PARTITIONED_ACCELERATION_STRUCTURE_NV;
                    member = PartitionedWriteCount;
                    break;
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_TENSOR_ARM:
                    sType = BrovVulkConstants.VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET_TENSOR_ARM;
                    member = TensorWriteCount;
                    break;
                default:
                    throw new InvalidOperationException($"BrovVulk generic: a descriptor write of type {type}, which this layer does not know.");
            }

            for (byte* node = *(byte**)(write + VkOffsets.NodePNext); node != null; node = *(byte**)(node + VkOffsets.NodePNext))
            {
                if (*(int*)node == sType && *(uint*)(node + member) == *(uint*)(write + WriteCount))
                    return;
            }
            throw new InvalidOperationException($"BrovVulk generic: a type {type} write without the structure that gives its {*(uint*)(write + WriteCount)} items.");
        }

        private static bool Accepts(SetLayoutShape layout, int index, uint bindingType, int type)
        {
            if ((uint)type == bindingType)
                return true;
            uint[]? allowed = bindingType == BrovVulkConstants.VK_DESCRIPTOR_TYPE_MUTABLE_EXT ? layout.Mutable?[index] : null;
            return allowed != null && Array.IndexOf(allowed, (uint)type) >= 0;
        }

        public unsafe bool CheckDescriptorUpdates(uint writeCount, IntPtr writes, uint copyCount, IntPtr copies)
        {
            for (int pass = 0; pass < 2; pass++)
            {
                bool apply = pass == 1;
                _released.Clear();
                for (uint k = 0; writes != IntPtr.Zero && k < writeCount; k++)
                {
                    byte* write = (byte*)writes + (long)k * WriteSize;
                    IntPtr handle = *(IntPtr*)(write + WriteSet);
                    if (!_sets.TryGetValue(handle, out SetRecord? set))
                        throw new InvalidOperationException("BrovVulk generic: a write to a descriptor set this layer did not allocate.");
                    if (!apply && !WritableNow(set, handle, *(uint*)(write + WriteBinding), *(uint*)(write + WriteElement), *(uint*)(write + WriteCount)))
                        return false;
                    ApplyWrite(set.Layout, set, write, apply);
                }
                for (uint k = 0; copies != IntPtr.Zero && k < copyCount; k++)
                {
                    byte* copy = (byte*)copies + (long)k * CopySize;
                    IntPtr handle = *(IntPtr*)(copy + CopyDstSet);
                    if (!apply && _sets.TryGetValue(handle, out SetRecord? to)
                        && !WritableNow(to, handle, *(uint*)(copy + CopyDstBinding), *(uint*)(copy + CopyDstElement), *(uint*)(copy + CopyCount)))
                        return false;
                    ApplyCopy(copy, apply);
                }
            }

            if (_released.Count != 0)
                Retire.Unhold(CallDevice, IntPtr.Zero, null, _released.ToArray());
            return true;
        }

        private bool WritableNow(SetRecord set, IntPtr handle, uint binding, uint element, uint count)
        {
            if (!set.Cpu || !Retire.Active)
                return true;
            IntPtr pool = PoolOfSet(handle);
            if (pool == IntPtr.Zero || Retire.PoolIdle(pool))
                return true;
            if (set.Layout.WhilePending == null)
                return false;

            DescriptorCursor cursor = new DescriptorCursor(set.Layout, set.Variable, binding, element);
            for (uint done = 0; done < count;)
            {
                uint take = Math.Min(cursor.Available(), count - done);
                if (!set.Layout.WhilePending[cursor.Index])
                    return false;
                cursor.Advance(take);
                done += take;
            }
            return true;
        }

        private unsafe void ApplyCopy(byte* copy, bool apply)
        {
            if (!_sets.TryGetValue(*(IntPtr*)(copy + CopySrcSet), out SetRecord? from) || !_sets.TryGetValue(*(IntPtr*)(copy + CopyDstSet), out SetRecord? to))
                throw new InvalidOperationException("BrovVulk generic: a copy between descriptor sets this layer did not allocate.");

            DescriptorCursor source = new DescriptorCursor(from.Layout, from.Variable, *(uint*)(copy + CopySrcBinding), *(uint*)(copy + CopySrcElement));
            DescriptorCursor target = new DescriptorCursor(to.Layout, to.Variable, *(uint*)(copy + CopyDstBinding), *(uint*)(copy + CopyDstElement));
            if (source.Type != target.Type)
                throw new InvalidOperationException($"BrovVulk generic: a copy from type {source.Type} descriptors into type {target.Type}.");
            uint count = *(uint*)(copy + CopyCount);
            for (uint done = 0; done < count;)
            {
                uint take = Math.Min(Math.Min(source.Available(), target.Available()), count - done);
                if (to.Cpu && target.Descriptor(0) != uint.MaxValue)
                    Slots(to);
                for (uint j = 0; apply && j < take; j++)
                {
                    uint slot = target.Slot(j), read = source.Slot(j);
                    if (to.Limits != null && slot != uint.MaxValue)
                        to.Limits[slot] = read != uint.MaxValue && from.Limits != null ? from.Limits[read] : 0;
                    uint into = target.Descriptor(j), at = source.Descriptor(j);
                    if (!to.Cpu || into == uint.MaxValue)
                        continue;
                    bool known = from.Resources != null && at != uint.MaxValue;
                    IntPtr sampler = source.ImmutableSampler(j) is IntPtr fixedSampler && fixedSampler != IntPtr.Zero ? fixedSampler : known ? from.Samplers![at] : IntPtr.Zero;
                    Replace(to, into, known ? from.Resources![at] : IntPtr.Zero, known ? from.Kinds![at] : (byte)0, sampler,
                        known && from.Swapchains != null ? from.Swapchains[at] : IntPtr.Zero);
                }
                source.Advance(take);
                target.Advance(take);
                done += take;
            }
        }

        public unsafe void CheckPushDescriptors(uint bindPoints, IntPtr layout, uint set, uint writeCount, IntPtr writes)
        {
            if (ShapeAt(layout, set) is not SetLayoutShape shape || !shape.Push)
                throw new InvalidOperationException($"BrovVulk generic: push descriptors for set {set}, which is not a push descriptor set of the pipeline layout.");

            for (uint k = 0; writes != IntPtr.Zero && k < writeCount; k++)
                ApplyWrite(shape, null, (byte*)writes + (long)k * WriteSize, false);

            Recording? rec = _callCommand;
            if (rec == null || !rec.Cpu)
                return;
            MarkBound(rec, bindPoints, set, shape);
            if (shape.Immutable == null || !(rec.PushedLayouts ??= new HashSet<SetLayoutShape>()).Add(shape))
                return;
            foreach (IntPtr[]? samplers in shape.Immutable)
            {
                foreach (IntPtr sampler in samplers ?? Array.Empty<IntPtr>())
                    HoldFor(rec.Device, rec.Handle, "VkCommandBuffer", sampler, "VkSampler");
            }
        }

        private static bool SameShape(SetLayoutShape a, SetLayoutShape b)
        {
            if (ReferenceEquals(a, b))
                return true;
            return a.VariableLast == b.VariableLast && a.Push == b.Push && a.Bindings.AsSpan().SequenceEqual(b.Bindings);
        }

        private const int BindPoints = 2;

        public static int BindPointIndex(int bindPoint) => bindPoint == BrovVulkConstants.VK_PIPELINE_BIND_POINT_GRAPHICS ? 0
            : bindPoint == BrovVulkConstants.VK_PIPELINE_BIND_POINT_COMPUTE ? 1 : -1;

        public static uint BindPointMask(int bindPoint) => BindPointIndex(bindPoint) is int index && index >= 0 ? 1u << index : 0u;

        public static uint StageMask(uint stages) => ((stages & (uint)(BrovVulkConstants.VK_SHADER_STAGE_ALL_GRAPHICS | BrovVulkConstants.VK_SHADER_STAGE_TASK_BIT_EXT | BrovVulkConstants.VK_SHADER_STAGE_MESH_BIT_EXT)) != 0 ? 1u : 0u)
            | ((stages & (uint)BrovVulkConstants.VK_SHADER_STAGE_COMPUTE_BIT) != 0 ? 2u : 0u);

        private void MarkBound(Recording rec, uint bindPoints, uint set, SetLayoutShape? shape)
        {
            for (int point = 0; point < BindPoints; point++)
            {
                if ((bindPoints & (1u << point)) == 0)
                    continue;
                SetLayoutShape?[] bound = rec.BoundSets[point] ??= new SetLayoutShape?[Math.Max(1u, DeviceGapsOf(rec.Device)?.MaxBoundDescriptorSets ?? 0)];
                if (set < (uint)bound.Length)
                    bound[set] = shape;
            }
        }

        public const int PipelineGraphics = 0, PipelineCompute = 1, PipelineLibrary = 2;

        private sealed class PipelineReads
        {
            public int Kind;
            public readonly Dictionary<uint, SetLayoutShape> Reads = new Dictionary<uint, SetLayoutShape>();
        }

        private sealed class PendingPipeline
        {
            public readonly PipelineReads Record = new PipelineReads();
            public IntPtr Layout;
            public readonly HashSet<uint> Sets = new HashSet<uint>();
        }

        // The driver uses the pipeline's own kind to bind it.
        public void NotePipelineBind(int bindPoint, IntPtr pipeline)
        {
            Recording? rec = _callCommand;
            if (rec == null)
                return;
            if (rec.Cpu)
            {
                int index = BindPointIndex(bindPoint);
                if (index < 0 || !_pipelines.TryGetValue(pipeline, out PipelineReads? record) || record.Kind != (index == 0 ? PipelineGraphics : PipelineCompute))
                    throw new InvalidOperationException("BrovVulk generic: a pipeline bound where its kind does not run.");
                rec.Reads[index] = record.Reads;
            }
            rec.BoundPipelines[BoundPoint(bindPoint)] = pipeline;
        }

        public void RefuseOnCpu()
        {
            if (_callCommand != null && _callCommand.Cpu)
                throw new InvalidOperationException("BrovVulk generic: a command that runs shaders this layer cannot check on a CPU device.");
        }

        public void CheckBoundSets(int point)
        {
            Recording? rec = _callCommand;
            if (rec == null || !rec.Cpu)
                return;
            Dictionary<uint, SetLayoutShape>? reads = rec.Reads[point];
            if (reads == null)
                throw new InvalidOperationException("BrovVulk generic: a draw or dispatch with no pipeline this layer made bound.");
            SetLayoutShape?[]? bound = rec.BoundSets[point];
            foreach (KeyValuePair<uint, SetLayoutShape> read in reads)
            {
                SetLayoutShape? shape = bound != null && read.Key < (uint)bound.Length ? bound[read.Key] : null;
                if (shape == null || !SameShape(shape, read.Value))
                    throw new InvalidOperationException($"BrovVulk generic: set {read.Key} is not bound with the layout the pipeline reads it by.");
            }
        }

        public void BeginPipelines(uint count)
        {
            _pendingPipelines.Clear();
            for (uint k = 0; k < count; k++)
                _pendingPipelines.Add(null);
        }

        public HashSet<uint> PipelineUse(int index, IntPtr layout, int kind)
        {
            if (index >= _pendingPipelines.Count)
                throw new InvalidOperationException("BrovVulk generic: too many pipelines in one call.");
            PendingPipeline pending = new PendingPipeline { Layout = layout };
            pending.Record.Kind = kind;
            _pendingPipelines[index] = pending;
            return pending.Sets;
        }

        // Linked stages keep the set layouts of their libraries.
        public void UseLibrary(int index, IntPtr library)
        {
            if (!_pipelines.TryGetValue(library, out PipelineReads? record) || record.Kind != PipelineLibrary)
                throw new InvalidOperationException("BrovVulk generic: a pipeline library this layer did not make.");
            foreach (KeyValuePair<uint, SetLayoutShape> read in record.Reads)
                AddRead(_pendingPipelines[index]!.Record.Reads, read.Key, read.Value);
        }

        public void ResolvePipelineUse(int index)
        {
            PendingPipeline pending = _pendingPipelines[index]!;
            if (pending.Sets.Count == 0)
                return;
            if (!_layoutSets.TryGetValue(pending.Layout, out SetLayoutShape?[]? shapes))
                throw new InvalidOperationException("BrovVulk generic: pipeline stages read sets with no pipeline layout this layer made.");
            foreach (uint set in pending.Sets)
            {
                if (set >= (uint)shapes.Length || shapes[set] == null)
                    throw new InvalidOperationException($"BrovVulk generic: pipeline stages read set {set}, which the pipeline layout does not have.");
                AddRead(pending.Record.Reads, set, shapes[set]!);
            }
        }

        private static void AddRead(Dictionary<uint, SetLayoutShape> reads, uint set, SetLayoutShape shape)
        {
            if (reads.TryGetValue(set, out SetLayoutShape? existing) && !SameShape(existing, shape))
                throw new InvalidOperationException($"BrovVulk generic: linked stages read set {set} by different set layouts.");
            reads[set] = shape;
        }

        public unsafe void NotePipelines(IntPtr pipelines, uint count)
        {
            for (uint k = 0; pipelines != IntPtr.Zero && k < count && k < (uint)_pendingPipelines.Count; k++)
            {
                IntPtr pipeline = ((IntPtr*)pipelines)[k];
                if (pipeline != IntPtr.Zero && _pendingPipelines[(int)k] is PendingPipeline pending)
                    _pipelines[pipeline] = pending.Record;
            }
            DropPendingPipelines();
        }

        public void DropPendingPipelines() => _pendingPipelines.Clear();

        private unsafe void ApplyWrite(SetLayoutShape layout, SetRecord? set, byte* write, bool apply)
        {
            int type = *(int*)(write + WriteType);
            CheckWriteCount(type, write);
            DescriptorCursor cursor = new DescriptorCursor(layout, set?.Variable ?? 0, *(uint*)(write + WriteBinding), *(uint*)(write + WriteElement));
            byte* infos = type == BrovVulkConstants.VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC || type == BrovVulkConstants.VK_DESCRIPTOR_TYPE_STORAGE_BUFFER_DYNAMIC
                ? *(byte**)(write + WriteBuffers) : null;
            bool holds = set != null && set.Cpu;
            uint count = *(uint*)(write + WriteCount);
            for (uint done = 0; done < count;)
            {
                uint take = Math.Min(cursor.Available(), count - done);
                if (!Accepts(layout, cursor.Index, cursor.Type, type))
                    throw new InvalidOperationException($"BrovVulk generic: a type {type} write into a binding of type {cursor.Type}.");
                if (holds && cursor.Descriptor(0) != uint.MaxValue)
                    Slots(set!);
                for (uint j = 0; (apply || holds) && j < take; j++)
                {
                    uint slot = cursor.Slot(j);
                    if (apply && set?.Limits != null && slot != uint.MaxValue)
                        set.Limits[slot] = infos != null ? DynamicLimit(infos + (long)(done + j) * DescriptorBufferInfoSize) : 0;
                    uint descriptor = cursor.Descriptor(j);
                    if (!holds || descriptor == uint.MaxValue)
                        continue;
                    DescriptorObjects(type, write, done + j, cursor.Immutable, out IntPtr resource, out byte kind, out IntPtr sampler);
                    IntPtr swapchain = kind == HeldImageView ? SwapchainOfView(resource) : IntPtr.Zero;
                    if (apply)
                        Replace(set!, descriptor, resource, kind, sampler, swapchain);
                }
                cursor.Advance(take);
                done += take;
            }
        }

        private void Slots(SetRecord set)
        {
            if (set.Resources != null)
                return;

            long total = (long)set.Layout.Total;
            uint last = set.Layout.Bindings.Length != 0 ? set.Layout.Bindings[^1].Count : 0;
            if (set.Layout.VariableLast && set.Layout.First.Length != 0 && set.Layout.First[^1] != uint.MaxValue)
                total -= last - Math.Min(last, set.Variable);
            if (total > MemoryBudget.VulkanHeldDescriptors - _heldDescriptors)
            {
                if (!_holdRefusalLogged)
                {
                    _holdRefusalLogged = true;
                    Utils.LogError($"[!] BrovVulk(gen): descriptors that CPU device sets name reached {MemoryBudget.VulkanHeldDescriptors}; further writes are refused.");
                }
                throw new InvalidOperationException("BrovVulk generic: no room to keep what the set's descriptors name.");
            }

            set.Resources = new IntPtr[total];
            set.Samplers = new IntPtr[total];
            set.Kinds = new byte[total];
            _heldDescriptors += total;
        }

        // Take the new hold first in case the slot still names the same object.
        private void Replace(SetRecord set, uint slot, IntPtr resource, byte kind, IntPtr sampler, IntPtr swapchain)
        {
            if (resource != IntPtr.Zero)
                Retire.Hold(set.Device, resource, HeldType(kind));
            if (sampler != IntPtr.Zero)
                Retire.Hold(set.Device, sampler, "VkSampler");
            if (set.Resources![slot] != IntPtr.Zero)
                _released.Add((set.Resources[slot], HeldType(set.Kinds![slot])));
            if (set.Samplers![slot] != IntPtr.Zero)
                _released.Add((set.Samplers[slot], "VkSampler"));
            set.Gone += (kind == HeldGone ? 1 : 0) - (set.Kinds![slot] == HeldGone ? 1 : 0);
            set.Resources[slot] = resource;
            set.Kinds![slot] = kind;
            set.Samplers[slot] = sampler;
            if (swapchain != IntPtr.Zero)
                set.Swapchains ??= new IntPtr[set.Resources.Length];
            if (set.Swapchains != null)
                set.Swapchains[slot] = swapchain;
        }

        private static unsafe void DescriptorObjects(int type, byte* write, uint i, bool immutable, out IntPtr resource, out byte kind, out IntPtr sampler)
        {
            resource = sampler = IntPtr.Zero;
            kind = 0;
            byte* images = *(byte**)(write + WriteImages);
            switch (type)
            {
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_SAMPLER:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_STORAGE_IMAGE:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_INPUT_ATTACHMENT:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_SAMPLE_WEIGHT_IMAGE_QCOM:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_BLOCK_MATCH_IMAGE_QCOM:
                    if (images == null)
                        return;
                    byte* image = images + (long)i * ImageInfoSize;
                    if (type != BrovVulkConstants.VK_DESCRIPTOR_TYPE_SAMPLER)
                    {
                        resource = *(IntPtr*)(image + ImageInfoView);
                        kind = HeldImageView;
                    }
                    if (!immutable && (type == BrovVulkConstants.VK_DESCRIPTOR_TYPE_SAMPLER || type == BrovVulkConstants.VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER))
                        sampler = *(IntPtr*)(image + ImageInfoSampler);
                    return;
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_UNIFORM_TEXEL_BUFFER:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_STORAGE_TEXEL_BUFFER:
                    IntPtr* views = *(IntPtr**)(write + WriteTexelViews);
                    if (views != null)
                    {
                        resource = views[i];
                        kind = HeldBufferView;
                    }
                    return;
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_STORAGE_BUFFER:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC:
                case BrovVulkConstants.VK_DESCRIPTOR_TYPE_STORAGE_BUFFER_DYNAMIC:
                    byte* buffers = *(byte**)(write + WriteBuffers);
                    if (buffers != null)
                    {
                        resource = *(IntPtr*)(buffers + (long)i * DescriptorBufferInfoSize + BrovVulkStructMeta.DescriptorBufferInfoBuffer);
                        kind = HeldBuffer;
                    }
                    return;
            }
        }

        private unsafe uint DynamicLimit(byte* info)
        {
            IntPtr buffer = *(IntPtr*)(info + BrovVulkStructMeta.DescriptorBufferInfoBuffer);
            if (buffer == IntPtr.Zero)
                return uint.MaxValue;

            ulong offset = *(ulong*)(info + BrovVulkStructMeta.DescriptorBufferInfoOffset), range = *(ulong*)(info + BrovVulkStructMeta.DescriptorBufferInfoRange);
            if (!_bufferSizes.TryGetValue(buffer, out ulong size) || range == WholeSize || offset > size || range > size - offset)
                return 0;
            return (uint)Math.Min(size - offset - range, uint.MaxValue);
        }

        public unsafe void CheckBindDescriptorSets(IntPtr commandBuffer, uint bindPoints, IntPtr layout, uint firstSet, uint setCount, IntPtr sets, uint offsetCount, IntPtr offsets)
        {
            Recording rec = OpenRecording(commandBuffer);
            if (!_layoutSets.TryGetValue(layout, out SetLayoutShape?[]? shapes))
                throw new InvalidOperationException("BrovVulk generic: a descriptor set bind needs a pipeline layout this layer created.");
            if ((ulong)firstSet + setCount > (ulong)shapes.Length)
                throw new InvalidOperationException($"BrovVulk generic: descriptor sets {firstSet}+{setCount} exceed the pipeline layout's {shapes.Length}.");

            uint used = 0;
            for (uint s = 0; s < setCount; s++)
            {
                uint need = shapes[firstSet + s]?.Dynamic ?? 0;
                IntPtr set = sets != IntPtr.Zero ? ((IntPtr*)sets)[s] : IntPtr.Zero;
                if (set == IntPtr.Zero)
                {
                    if (need != 0)
                        throw new InvalidOperationException("BrovVulk generic: a null descriptor set where the pipeline layout has dynamic descriptors.");
                    if (rec.Cpu)
                        MarkBound(rec, bindPoints, firstSet + s, null);
                    continue;
                }
                if (!_sets.TryGetValue(set, out SetRecord? bound) || shapes[firstSet + s] == null || !SameShape(bound.Layout, shapes[firstSet + s]!))
                    throw new InvalidOperationException("BrovVulk generic: a set's layout differs from the pipeline layout's at its index.");
                if (bound.Gone != 0)
                    throw new InvalidOperationException("BrovVulk generic: a set names an image view of a destroyed swapchain.");
                if (rec.Cpu)
                    MarkBound(rec, bindPoints, firstSet + s, bound.Layout);
                if (need == 0)
                    continue;
                if (need > offsetCount - used)
                    throw new InvalidOperationException($"BrovVulk generic: {offsetCount} dynamic offsets for more dynamic descriptors.");

                uint* given = (uint*)offsets + used;
                for (uint j = 0; j < need; j++)
                {
                    if (given[j] > bound.Limits![j])
                        throw new InvalidOperationException($"BrovVulk generic: dynamic offset {given[j]} moves a descriptor past its buffer.");
                }
                if (rec.Cpu)
                    NoteOffsets(rec, set, given, need);
                used += need;
            }

            if (used != offsetCount)
                throw new InvalidOperationException($"BrovVulk generic: {offsetCount} dynamic offsets for {used} dynamic descriptors.");

            for (uint points = bindPoints != 0 ? bindPoints : 1u << BindPoints; points != 0 && setCount != 0; points &= points - 1)
                CopyBound(ref rec.BoundSetHandles[System.Numerics.BitOperations.TrailingZeroCount(points)], firstSet, setCount, sets);
        }

        private static unsafe void NoteOffsets(Recording rec, IntPtr set, uint* given, uint count)
        {
            rec.Offsets ??= new Dictionary<IntPtr, uint[]>();
            if (!rec.Offsets.TryGetValue(set, out uint[]? most))
            {
                most = new uint[count];
                rec.Offsets[set] = most;
            }
            for (uint j = 0; j < count && j < (uint)most.Length; j++)
                most[j] = Math.Max(most[j], given[j]);
        }

        private uint QueryValues(IntPtr pool, uint first, uint count)
        {
            if (!_queryPools.TryGetValue(pool, out (uint Count, uint Values) p) || first > p.Count || count > p.Count - first)
                throw new InvalidOperationException($"BrovVulk generic: queries {first}+{count} are outside the query pool.");

            return p.Values;
        }

        public bool HasMapping(uint id) => _mappings.ContainsKey(id);

        public void SetMemorySize(uint id, ulong size) => _memorySizes[id] = size;

        public bool IsMemoryRangeInsideAllocation(uint id, ulong offset, ulong size)
        {
            if (!_memorySizes.TryGetValue(id, out ulong allocated))
                return false;

            return offset <= allocated && size <= allocated - offset;
        }

        public void MarkImported(uint id, IGuestMemory memory, IntPtr pin)
        {
            _importMemory = memory;
            _importedMem[id] = pin;
        }

        public bool IsImportedMemory(uint id) => _importedMem.ContainsKey(id);

        public void EnableWin32Memory(IntPtr device) => _win32MemoryDevices.Add(device);

        public bool HasWin32Memory(IntPtr device) => _win32MemoryDevices.Contains(device);

        public void SetExportTypes(uint id, uint handleTypes)
        {
            if (handleTypes != 0)
                _exportTypes[id] = handleTypes;
        }

        public uint ExportTypes(uint id) => _exportTypes.TryGetValue(id, out uint types) ? types : 0;

        public bool TryGetKmtToken(uint id, out uint token) => _kmtTokenOfMemory.TryGetValue(id, out token);

        // Host share handles can name objects in other processes.
        public bool TryAddKmtShare(uint id, IntPtr hostShare, out uint token)
        {
            token = 0;
            uint slot;
            if (_freeKmtSlots.Count != 0)
                slot = _freeKmtSlots.Pop();
            else if (_nextKmtSlot < MaxKmtSlots)
                slot = _nextKmtSlot++;
            else
                return false;

            token = KmtTokenBase + (slot << KmtTokenShift);
            _kmtTokenOfMemory[id] = token;
            _kmtHostShares[token] = hostShare;
            return true;
        }

        public bool TryGetKmtHostShare(uint token, out IntPtr hostShare) => _kmtHostShares.TryGetValue(token, out hostShare);

        public void SetDeviceImport(IntPtr device, DeviceImport import) => _deviceImports[device] = import;

        public bool TryGetDeviceImport(IntPtr device, out DeviceImport import) => _deviceImports.TryGetValue(device, out import);

        public void SetDevicePhysical(IntPtr device, IntPtr physicalDevice)
        {
            if (device != IntPtr.Zero && physicalDevice != IntPtr.Zero)
                _devicePhysical[device] = physicalDevice;
        }

        public bool TryGetDevicePhysical(IntPtr device, out IntPtr physicalDevice) => _devicePhysical.TryGetValue(device, out physicalDevice);

        public void SetDeviceStandIns(IntPtr device, int bits)
        {
            if (device != IntPtr.Zero)
                _deviceStandIns[device] = bits;
        }

        public int DeviceStandIns(IntPtr device) => _deviceStandIns.TryGetValue(device, out int bits) ? bits : 0;

        public int CommandBufferStandIns(IntPtr commandBuffer) => StandIns.CommandBuffers.TryGetValue(commandBuffer, out CommandBufferRecord? record) ? record.Bits : 0;

        public ulong BufferSize(IntPtr buffer) => _bufferSizes.TryGetValue(buffer, out ulong size) ? size : 0;

        public void AddMapping(uint id, IntPtr hostPtr, ulong guestVa, ulong mapOffset, ulong size, bool imported, bool shared) =>
            _mappings[id] = new MapEntry(hostPtr, guestVa, mapOffset, size, imported, shared);

        public bool TryGetMapping(uint id, out MapEntry entry) => _mappings.TryGetValue(id, out entry);

        public void RemoveMapping(uint id) => _mappings.Remove(id);

        public void ClearMappings() => _mappings.Clear();

        public Dictionary<uint, MapEntry>.ValueCollection Mappings => _mappings.Values;

        public IntPtr Alloc(int size) => _arena.Alloc(size);

        public void FreeCallAllocs()
        {
            _chainDepth = 0;
            _callDevice = IntPtr.Zero;
            _callRecording = null;
            _callCommand = null;
            _callOwner = 0;
            _arena.FreeCallAllocs();
        }

        public void FailCall()
        {
            if (_callCommand != null && _callCommand.State == RecordingState.Recording)
            {
                _callCommand.State = RecordingState.Invalid;
                ClearBound(_callCommand);
            }
        }

        public IntPtr CallDevice
        {
            get
            {
                if (_callDevice == IntPtr.Zero && _callOwner != 0 && _handles.TryGetValue(_callOwner, out HandleEntry device))
                    _callDevice = device.Ptr;
                return _callDevice;
            }
        }

        public void SetCallDevice(IntPtr device) => _callDevice = device;

        public void BeginCommand(IntPtr commandBuffer)
        {
            _callCommand = OpenRecording(commandBuffer);
            _callRecording = _callCommand.Cpu && Retire.Active ? _callCommand : null;
        }

        private uint CallColorLimit => DeviceGapsOf(CallDevice)?.MaxColorAttachments ?? 0;

        public void CheckColorCount(uint count)
        {
            uint limit = CallColorLimit;
            if (count > limit)
                throw new InvalidOperationException($"BrovVulk generic: {count} color attachments of {limit}.");
        }

        public void CheckColorRange(uint first, uint count) => CheckSlots(first, count, CallColorLimit, "color attachments");

        public void CheckViewportRange(uint first, uint count) => CheckSlots(first, count, DeviceGapsOf(CallDevice)?.MaxViewports ?? 0, "viewports");

        public void CheckVertexBindingRange(uint first, uint count) => CheckSlots(first, count, DeviceGapsOf(CallDevice)?.MaxVertexInputBindings ?? 0, "vertex bindings");

        public void CheckFeedbackBufferRange(uint first, uint count) => CheckSlots(first, count, DeviceGapsOf(CallDevice)?.MaxTransformFeedbackBuffers ?? 0, "transform feedback buffers");

        public void CheckPushConstants(uint offset, uint size) => CheckSlots(offset, size, DeviceGapsOf(CallDevice)?.MaxPushConstantsSize ?? 0, "push constant bytes");

        public unsafe void CheckVertexInput(uint bindingCount, IntPtr bindings, uint attributeCount, IntPtr attributes)
        {
            VulkanStandIns.DeviceGaps? gaps = DeviceGapsOf(CallDevice);
            uint maxBindings = gaps?.MaxVertexInputBindings ?? 0, maxAttributes = gaps?.MaxVertexInputAttributes ?? 0;
            for (uint k = 0; bindings != IntPtr.Zero && k < bindingCount; k++)
                CheckSlots(*(uint*)((byte*)bindings + (long)k * VertexBindingSize + VertexBindingNumber), 1, maxBindings, "vertex bindings");
            for (uint k = 0; attributes != IntPtr.Zero && k < attributeCount; k++)
            {
                byte* attribute = (byte*)attributes + (long)k * VertexAttributeSize;
                CheckSlots(*(uint*)(attribute + VertexAttributeLocation), 1, maxAttributes, "vertex attributes");
                CheckSlots(*(uint*)(attribute + VertexAttributeBinding), 1, maxBindings, "vertex bindings");
            }
        }

        private static void CheckSlots(uint first, uint count, uint limit, string what)
        {
            if (first > limit || count > limit - first)
                throw new InvalidOperationException($"BrovVulk generic: {what} {first}+{count} of {limit}.");
        }

        public void RetainChains() => _arena.ArmRetain();

        public void EnterChain()
        {
            if (++_chainDepth > MaxChainDepth)
                throw new InvalidOperationException("BrovVulk generic: pNext chain deeper than the structures it may hold.");

            _arena.EnterChain();
        }

        public void LeaveChain()
        {
            _chainDepth--;
            _arena.LeaveChain();
        }

        public bool RetainFits()
        {
            if (_retainedBytes + _arena.PendingRetainedBytes <= MemoryBudget.VulkanRetainedBytes)
                return true;

            if (!_retainRefusalLogged)
            {
                _retainRefusalLogged = true;
                Utils.LogError($"[!] BrovVulk(gen): kept create-info chains reached {MemoryBudget.VulkanRetainedBytes} bytes; further creates fail.");
            }
            return false;
        }

        public void KeepRetained(uint id)
        {
            if (id == 0)
                return;

            IntPtr[]? blocks = _arena.TakeRetained(out long bytes);
            if (blocks == null)
                return;

            _retained[id] = (blocks, bytes);
            _retainedBytes += bytes;
        }

        internal void FreeRetained((IntPtr[] Blocks, long Bytes) kept)
        {
            foreach (IntPtr block in kept.Blocks)
                Marshal.FreeHGlobal(block);
            _retainedBytes -= kept.Bytes;
        }

        public void Dispose()
        {
            foreach (IntPtr ownerKey in _ownerKeys.Values)
                BrovVulkProc.RemoveOwner(ownerKey);
            _ownerKeys.Clear();
            if (!Retire.Drain(this, RetireDrainMilliseconds))
                return;
            foreach ((IntPtr[] Blocks, long Bytes) kept in _retained.Values)
                FreeRetained(kept);
            _retained.Clear();
            _retainedBytes = 0;
            _arena.FreeAll();
        }

    }
}
