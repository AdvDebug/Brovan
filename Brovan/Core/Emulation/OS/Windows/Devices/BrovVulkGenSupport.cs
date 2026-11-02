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
                new Span<byte>((void*)p, size).Clear();
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

        private readonly Dictionary<uint, (IntPtr Ptr, string Type, uint Parent)> _handles = new Dictionary<uint, (IntPtr, string, uint)>();
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
        private readonly Dictionary<IntPtr, uint> _layoutSets = new Dictionary<IntPtr, uint>();
        private readonly Dictionary<IntPtr, ulong> _bufferSizes = new Dictionary<IntPtr, ulong>();
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
            _handles[id] = (ptr, type, parent);
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
            if (_handles.TryGetValue(deviceId, out (IntPtr Ptr, string Type, uint Parent) e) && e.Type == "VkDevice")
                _lostDevices.Add(deviceId);
        }

        public bool IsDeviceLost(uint handleId)
        {
            uint id = handleId;
            for (int depth = 0; depth < 4 && id != 0; depth++)
            {
                if (!_handles.TryGetValue(id, out (IntPtr Ptr, string Type, uint Parent) e))
                    return false;
                if (e.Type == "VkDevice")
                    return _lostDevices.Contains(id);
                id = e.Parent;
            }

            return false;
        }

        public uint RegisterQueried(IntPtr ptr, string type, uint parent)
        {
            if (ptr != IntPtr.Zero && _ids.TryGetValue((ptr, type), out uint id)
                && _handles.TryGetValue(id, out (IntPtr Ptr, string Type, uint Parent) e) && e.Parent == parent)
                return id;

            return Register(ptr, type, parent);
        }

        public uint IdOf(IntPtr ptr, string type) => ptr != IntPtr.Zero && _ids.TryGetValue((ptr, type), out uint id) ? id : 0;

        public IntPtr InstanceOfDevice(IntPtr device)
        {
            uint id = IdOf(device, "VkDevice");
            for (int depth = 0; depth < 2 && id != 0; depth++)
                id = _handles.TryGetValue(id, out (IntPtr Ptr, string Type, uint Parent) e) ? e.Parent : 0;

            return id != 0 && _handles.TryGetValue(id, out (IntPtr Ptr, string Type, uint Parent) instance) && instance.Type == "VkInstance"
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
            if (_handles.TryGetValue(id, out (IntPtr Ptr, string Type, uint Parent) e) && e.Type == type)
                return e.Ptr;
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
            while (_forgetting.Count != 0)
            {
                uint next = _forgetting.Pop();
                if (_handles.Remove(next, out (IntPtr Ptr, string Type, uint Parent) e))
                {
                    if (e.Type == "VkPipelineLayout")
                        _layoutSets.Remove(e.Ptr);
                    else if (e.Type == "VkBuffer")
                        _bufferSizes.Remove(e.Ptr);
                    else if (e.Type == "VkDevice")
                    {
                        _devicePhysical.Remove(e.Ptr);
                        _deviceImports.Remove(e.Ptr);
                        _deviceStandIns.Remove(e.Ptr);
                        _win32MemoryDevices.Remove(e.Ptr);
                        _lostDevices.Remove(next);
                    }
                    else if (e.Type == "VkSwapchainKHR" || e.Type == "VkSurfaceKHR")
                        Wsi.Forget(e.Ptr, e.Type);

                    if (_ids.TryGetValue((e.Ptr, e.Type), out uint mapped) && mapped == next)
                        _ids.Remove((e.Ptr, e.Type));

                    if (e.Parent != 0 && _children.TryGetValue(e.Parent, out HashSet<uint>? siblings))
                        siblings.Remove(next);
                }

                _mappings.Remove(next);
                if (_ownerKeys.Count != 0 && _ownerKeys.Remove(next, out IntPtr ownerKey))
                    BrovVulkProc.RemoveOwner(ownerKey);
                if (_retained.Count != 0 && _retained.Remove(next, out (IntPtr[] Blocks, long Bytes) kept))
                    FreeRetained(kept);
                if (_importedMem.Remove(next, out IntPtr pin))
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

        public void SetPipelineLayoutSets(IntPtr layout, uint setLayoutCount)
        {
            if (layout != IntPtr.Zero)
                _layoutSets[layout] = setLayoutCount;
        }

        public void CheckDescriptorSetRange(IntPtr layout, uint firstSet, uint setCount)
        {
            if (!_layoutSets.TryGetValue(layout, out uint declared))
                return;

            if ((ulong)firstSet + setCount > declared)
                throw new InvalidOperationException($"BrovVulk generic: descriptor sets {firstSet}+{setCount} exceed the pipeline layout's {declared}.");
        }

        public void SetBufferSize(IntPtr buffer, ulong size)
        {
            if (buffer != IntPtr.Zero)
                _bufferSizes[buffer] = size;
        }

        public void CheckBufferRange(IntPtr buffer, ulong offset, ulong range)
        {
            if (buffer == IntPtr.Zero || !_bufferSizes.TryGetValue(buffer, out ulong size))
                return;

            if (offset > size || (range != WholeSize && range > size - offset))
                throw new InvalidOperationException($"BrovVulk generic: descriptor range {offset}+{range} exceeds the buffer's {size} bytes.");
        }

        public bool HasMapping(uint id) => _mappings.ContainsKey(id);

        public void SetMemorySize(uint id, ulong size) => _memorySizes[id] = size;

        // vkMapMemory returns base + offset with no bound of its own.
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

        // The guest gets a token, because a host global share handle names objects of other host processes.
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
            _arena.FreeCallAllocs();
        }

        public IntPtr CallDevice => _callDevice;

        public void SetCallDevice(IntPtr device) => _callDevice = device;

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

        private void FreeRetained((IntPtr[] Blocks, long Bytes) kept)
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
            foreach ((IntPtr[] Blocks, long Bytes) kept in _retained.Values)
                FreeRetained(kept);
            _retained.Clear();
            _retainedBytes = 0;
            _arena.FreeAll();
        }

    }
}
