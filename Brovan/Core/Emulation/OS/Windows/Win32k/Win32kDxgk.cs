using System.Buffers.Binary;
using System.Text;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal enum DxgkAdapterKind
    {
        Display,
        BasicRender,
    }

    internal sealed class AdapterIdentity
    {
        internal uint VendorId { get; init; }
        internal uint DeviceId { get; init; }
        internal string Description { get; init; }
        internal string ProviderName { get; init; }
        internal string DriverVersion { get; init; }
        internal string HardwareId { get; init; }
        internal string InstanceId { get; init; }
        internal string DeviceInterface { get; init; }
        internal byte[] DeviceUuid { get; init; }
        internal bool HasLocation { get; init; }
        internal uint Bus { get; init; }
        internal ushort Device { get; init; }
        internal ushort Function { get; init; }

        internal const string DisplayInterfaceClass = "{1024e4c9-47c9-48d3-b4a8-f9df78523b53}";

        // Subsystem and revision are 0, as the guest's DXGI reports them.
        internal static AdapterIdentity ForPci(uint VendorId, uint DeviceId, string Description, string ProviderName,
            string DriverVersion, byte[] DeviceUuid, bool HasLocation, uint Bus, ushort Device, ushort Function)
        {
            string HardwareId = $@"PCI\VEN_{VendorId:X4}&DEV_{DeviceId:X4}&SUBSYS_00000000&REV_00";
            return new AdapterIdentity
            {
                VendorId = VendorId,
                DeviceId = DeviceId,
                Description = Description,
                ProviderName = ProviderName,
                DriverVersion = DriverVersion,
                HardwareId = HardwareId,
                InstanceId = HardwareId + @"\0",
                DeviceInterface = @"\\?\" + HardwareId.Replace('\\', '#') + "#0#" + DisplayInterfaceClass,
                DeviceUuid = DeviceUuid,
                HasLocation = HasLocation,
                Bus = Bus,
                Device = Device,
                Function = Function,
            };
        }

        internal static readonly AdapterIdentity Synthetic = ForPci(0, 0, "Brovan Display Adapter", "Brovan", null, null, false, 0, 0, 0);
    }

    internal sealed class DxgkAdapter
    {
        private AdapterIdentity _identity;

        internal DxgkAdapterKind Kind { get; init; }
        internal uint LuidLowPart { get; init; }
        internal int LuidHighPart { get; init; }
        internal uint SourceCount { get; init; }
        internal uint AdapterType { get; init; }
        internal uint BusType { get; init; }
        internal string UniqueId { get; init; }
        internal ulong DedicatedVideoMemory { get; init; }

        internal AdapterIdentity Identity
        {
            get => Volatile.Read(ref _identity);
            init => _identity = value;
        }

        internal string DriverKeyPath { get; set; }

        internal bool TryPublishIdentity(AdapterIdentity Value) => Interlocked.CompareExchange(ref _identity, Value, null) == null;

        internal bool MatchesLuid(uint LowPart, int HighPart) => LowPart == LuidLowPart && HighPart == LuidHighPart;

        internal ulong Luid => LuidLowPart | ((ulong)(uint)LuidHighPart << 32);
    }

    internal sealed class GuestGpuDriver
    {
        internal string FileName { get; init; }
        internal string PathValue { get; init; }
        internal int PathType { get; init; }
        internal (string Name, uint Value)[] Dwords { get; init; } = Array.Empty<(string, uint)>();
    }

    /// <summary>
    /// BrovVulk draws through the display adapter. It has no Windows D3D driver, so D3D renders on Basic Render.
    /// </summary>
    internal static class Win32kDxgk
    {
        internal const uint WddmVersion = 0xC80;

        private const uint RenderSupported = 0x1;
        private const uint DisplaySupported = 0x2;
        private const uint SoftwareDevice = 0x4;
        private const uint AcgSupported = 0x100;

        // A guest that sizes its pools from the kernel view gets the same answer on every host, because the
        // number is not the host GPU's. DXGI reports the real device through BrovVulk.
        private const ulong DisplayDedicatedVideoMemory = 4UL << 30;

        // NT: the shared segment of every adapter is half of physical memory.
        internal static ulong SharedSegmentSize => MemoryBudget.GuestPhysicalBytes / 2;

        // NT: an enumeration with no array reports the most adapters it can list.
        internal const uint MaxEnumAdapters = 34;

        // NT: StartGPU in BasicRender.sys.
        private const uint MinWarpNodes = 3;
        private const uint MaxWarpNodes = 62;

        internal static uint WarpNodeCount(BinaryEmulator Instance) => Math.Clamp((uint)Instance.WinHelper.ProcessorCount + 1, MinWarpNodes, MaxWarpNodes);

        // D3DKMT_ADAPTERINFO: hAdapter, LUID, NumOfSources, bPrecisePresentRegionsPreferred.
        internal const int AdapterInfoSize = 20;

        internal const string DisplayClass = "{4d36e968-e325-11ce-bfc1-08002be10318}";
        private const string DisplayClassKey = DeviceNodes.ControlSet + @"Control\Class\" + DisplayClass;
        private const int MaxClassInstances = 10000;
        internal const string WowSuffix = "Wow";
        internal const string OpenGlDriverNameValue = "OpenGLDriverName";
        internal const string OpenGlVersionValue = "OpenGLVersion";
        internal const string OpenGlFlagsValue = "OpenGLFlags";
        private const string OpenClDriverNameValue = "OpenCLDriverName";

        private const string DisplayVideoRoot = DeviceNodes.ControlSet + @"Control\Video\{7E2C1F4A-5B3D-4E8A-9C61-2D4B8F0A1E35}";
        internal const string DisplayVideoKey = DisplayVideoRoot + @"\0000";
        private const string DisplayVideoSubKey = DisplayVideoRoot + @"\Video";

        private const int ProbeShutdownWaitMilliseconds = 2000;
        private static Task<AdapterIdentity> DisplayProbe;
        private static int ProbeEnded;

        internal static readonly GuestGpuDriver[] GuestDrivers =
        {
            new()
            {
                FileName = "libgallium_wgl.dll",
                PathValue = OpenGlDriverNameValue,
                PathType = WinSysHelper.RegMultiSz,
                Dwords = new[] { (OpenGlVersionValue, 1u), (OpenGlFlagsValue, 3u) },
            },
            new()
            {
                FileName = "clvk.dll",
                PathValue = OpenClDriverNameValue,
                PathType = WinSysHelper.RegSz,
            },
        };

        internal static readonly DxgkAdapter Display = new()
        {
            Kind = DxgkAdapterKind.Display,
            LuidLowPart = 0xB00F,
            LuidHighPart = 1,
            SourceCount = 1,
            AdapterType = DisplaySupported,
            BusType = 1,
            UniqueId = "{B73ADCCD-99F6-4B2B-831E-47E106405C20}",
            DedicatedVideoMemory = DisplayDedicatedVideoMemory,
        };

        internal static readonly DxgkAdapter BasicRender = new()
        {
            Kind = DxgkAdapterKind.BasicRender,
            LuidLowPart = 0xB010,
            LuidHighPart = 1,
            SourceCount = 0,
            AdapterType = RenderSupported | SoftwareDevice | AcgSupported,
            BusType = 3,
            UniqueId = "{FD011EF1-249B-4D83-AA9C-CC5C9FDADA67}",
            Identity = new AdapterIdentity
            {
                VendorId = 0x1414,
                DeviceId = 0x8C,
                Description = "Microsoft Basic Render Driver",
                HardwareId = @"ROOT\BasicRender",
                InstanceId = @"ROOT\BasicRender\0000",
                DeviceInterface = @"\\?\ROOT#BasicRender#0000#" + AdapterIdentity.DisplayInterfaceClass,
            },
        };

        private static readonly DxgkAdapter[] Adapters = { Display, BasicRender };

        internal static DxgkAdapter FindByLuid(ReadOnlySpan<byte> Luid)
        {
            uint LowPart = BinaryPrimitives.ReadUInt32LittleEndian(Luid);
            int HighPart = BinaryPrimitives.ReadInt32LittleEndian(Luid.Slice(4));
            foreach (DxgkAdapter Adapter in Adapters)
            {
                if (Adapter.MatchesLuid(LowPart, HighPart))
                    return Adapter;
            }

            return null;
        }

        internal static bool TryGetDriverKey(WinSysHelper WinHelper, DxgkAdapter Adapter, out string DriverKey)
        {
            DriverKey = null;
            string Driver = Adapter.DriverKeyPath;
            if (Driver == null && (Adapter.Identity is not { } Identity
                || !WinHelper.TryReadRegistryString(DeviceNodes.EnumKeyPath(Identity.InstanceId), "Driver", out Driver) || Driver.Length == 0))
                return false;

            DriverKey = DeviceNodes.ClassKeyPath(Driver);
            return true;
        }

        // Windows hosts share the host hive, so Brovan needs its own class instance.
        internal static void PublishDriverKey(WinSysHelper WinHelper)
        {
            string Instance = FirstFreeClassInstance(WinHelper);
            if (Instance == null)
                return;

            string DriverKey = DisplayClassKey + "\\" + Instance;
            if (!WinHelper.CreateRegistryKeyPath(DriverKey, true, out _))
                return;

            Display.DriverKeyPath = DisplayClass + "\\" + Instance;
            foreach (GuestGpuDriver Driver in GuestDrivers)
            {
                PublishDriverValues(WinHelper, DriverKey, Driver, "System32", string.Empty);
                PublishDriverValues(WinHelper, DriverKey, Driver, "SysWOW64", WowSuffix);
            }
        }

        private static void PublishDriverValues(WinSysHelper WinHelper, string DriverKey, GuestGpuDriver Driver, string Directory, string Suffix)
        {
            string GuestPath = WindowsVersionInfo.SystemRoot + "\\" + Directory + "\\" + Driver.FileName;
            string HostPath = GeneralHelper.IO.ResolveVirtualHostPath(GuestPath, BinaryFormat.PE, NativeSystemView: true);
            if (HostPath == null || !GeneralHelper.IO.HostPathExists(HostPath))
                return;

            string Terminator = Driver.PathType == WinSysHelper.RegMultiSz ? "\0\0" : "\0";
            WinHelper.SetRegistryValue(DriverKey, Driver.PathValue + Suffix, Driver.PathType, Encoding.Unicode.GetBytes(GuestPath + Terminator));
            foreach ((string Name, uint Value) in Driver.Dwords)
                WinHelper.SetRegistryValue(DriverKey, Name + Suffix, WinSysHelper.RegDword, BitConverter.GetBytes(Value));
        }

        // The first process of a session asks the host, and later ones read the record it leaves.
        internal static void StartDisplayIdentity(WinSysHelper WinHelper, BinaryEmulator Emulator)
        {
            if (HostDisplayGpu.Disabled)
            {
                PublishDisplayIdentity(WinHelper, AdapterIdentity.Synthetic);
                return;
            }

            if (HostDisplayGpu.TryReadSessionRecord(out AdapterIdentity Recorded))
            {
                PublishDisplayIdentity(WinHelper, Recorded);
                return;
            }

            Task<AdapterIdentity> Probe = Task.Factory.StartNew(RunProbe, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            Volatile.Write(ref DisplayProbe, Probe);
            Probe.ContinueWith(_ =>
            {
                if (Volatile.Read(ref ProbeEnded) == 0)
                    Emulator.WakeSignal.Bump();
            }, TaskContinuationOptions.ExecuteSynchronously);
        }

        private static AdapterIdentity RunProbe()
        {
            AdapterIdentity Found = null;
            try
            {
                Found = HostDisplayGpu.Probe(out string Reason);
                if (Found == null)
                    Utils.LogError($"[Win32kDxgk] The display adapter keeps the synthetic identity: {Reason}");
            }
            catch (Exception Error)
            {
                Utils.LogError($"[Win32kDxgk] The host display GPU probe failed: {Error.Message}");
            }

            if (Found != null && Volatile.Read(ref ProbeEnded) == 0)
                HostDisplayGpu.WriteSessionRecord(Found);
            return Found;
        }

        internal static void EndDisplayProbe()
        {
            Volatile.Write(ref ProbeEnded, 1);
            Volatile.Read(ref DisplayProbe)?.Wait(ProbeShutdownWaitMilliseconds);
        }

        internal static bool HasUnpublishedProbe => Display.Identity == null && Volatile.Read(ref DisplayProbe) is { IsCompleted: true };

        internal static void PublishProbeResult(WinSysHelper WinHelper)
        {
            Task<AdapterIdentity> Probe = Volatile.Read(ref DisplayProbe);
            AdapterIdentity Found = Probe is { IsCompletedSuccessfully: true } ? Probe.Result : null;
            PublishDisplayIdentity(WinHelper, Found ?? AdapterIdentity.Synthetic);
        }

        // Call it before any output or callback, because a parked call starts again from the top.
        internal static bool TryGetIdentity(BinaryEmulator Instance, DxgkAdapter Adapter, out AdapterIdentity Identity, out NTSTATUS Parked)
        {
            Parked = NTSTATUS.STATUS_SUCCESS;
            Identity = Adapter.Identity;
            if (Identity != null)
                return true;

            Task<AdapterIdentity> Probe = Volatile.Read(ref DisplayProbe);
            if (Probe == null || Probe.IsCompleted)
            {
                PublishProbeResult(Instance.WinHelper);
                Identity = Adapter.Identity;
                return true;
            }

            if (Instance.WinHelper.TryRetrySyscallWhenDone(Probe))
            {
                Parked = NTSTATUS.STATUS_PENDING;
                return false;
            }

            Identity = AdapterIdentity.Synthetic;
            return true;
        }

        private static void PublishDisplayIdentity(WinSysHelper WinHelper, AdapterIdentity Identity)
        {
            if (!Display.TryPublishIdentity(Identity))
                return;

            WriteVideoKeys(WinHelper, Identity);
            if (!string.IsNullOrEmpty(Identity.DriverVersion) && TryGetDriverKey(WinHelper, Display, out string DriverKey))
                SetString(WinHelper, DriverKey, "DriverVersion", Identity.DriverVersion);
            WinHelper.DeviceNodes.TryAdd(WinHelper, BuildDisplayNode(WinHelper.DeviceNodes.Root, Identity));
        }

        private static DeviceNode BuildDisplayNode(DeviceNode Root, AdapterIdentity Identity)
        {
            DeviceNode Node = new DeviceNode
            {
                InstanceId = Identity.InstanceId,
                Parent = Root,
                Status = DeviceNodes.StatusNtEnumerator | DeviceNodes.StatusNtDriver | DeviceNodes.StatusDisableable
                    | DeviceNodes.StatusStarted | DeviceNodes.StatusDriverLoaded,
            };

            Node.SetString(DeviceNodes.DeviceDesc, Identity.Description);
            Node.SetStringList(DeviceNodes.HardwareIds, Identity.HardwareId);
            Node.SetString(DeviceNodes.Class, "Display");
            Node.SetGuid(DeviceNodes.ClassGuid, new Guid(DisplayClass));
            if (Display.DriverKeyPath != null)
                Node.SetString(DeviceNodes.Driver, Display.DriverKeyPath);
            if (!string.IsNullOrEmpty(Identity.ProviderName))
            {
                Node.SetString(DeviceNodes.Manufacturer, Identity.ProviderName);
                Node.SetString(DeviceNodes.DriverProvider, Identity.ProviderName);
            }
            if (!string.IsNullOrEmpty(Identity.DriverVersion))
                Node.SetString(DeviceNodes.DriverVersion, Identity.DriverVersion);

            Node.SetUInt64(DeviceNodes.AdapterLuid, Display.Luid);
            if (Identity.HasLocation)
            {
                Node.SetUInt32(DeviceNodes.BusNumber, Identity.Bus);
                Node.SetUInt32(DeviceNodes.Address, ((uint)Identity.Device << 16) | Identity.Function);
            }

            return Node;
        }

        private static void WriteVideoKeys(WinSysHelper WinHelper, AdapterIdentity Identity)
        {
            if (!WinHelper.CreateRegistryKeyPath(DisplayVideoKey, true, out _) || !WinHelper.CreateRegistryKeyPath(DisplayVideoSubKey, true, out _))
                return;

            SetString(WinHelper, DisplayVideoKey, "ProviderName", Identity.ProviderName ?? string.Empty);
            SetString(WinHelper, DisplayVideoKey, "DriverDesc", Identity.Description);
            if (!string.IsNullOrEmpty(Identity.DriverVersion))
                SetString(WinHelper, DisplayVideoKey, "DriverVersion", Identity.DriverVersion);
            if (Display.DriverKeyPath != null)
                SetString(WinHelper, DisplayVideoSubKey, "Driver", Display.DriverKeyPath);
            SetString(WinHelper, DisplayVideoSubKey, "DeviceDesc", Identity.Description);
        }

        private static void SetString(WinSysHelper WinHelper, string Key, string Name, string Value) =>
            WinHelper.SetRegistryValue(Key, Name, WinSysHelper.RegSz, Encoding.Unicode.GetBytes(Value + "\0"));

        private static string FirstFreeClassInstance(WinSysHelper WinHelper)
        {
            WinRegKey Class = WinHelper.ResolveRegistryKey(DisplayClassKey);
            HashSet<string> Taken = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (Class != null && WinHelper.TryCollectRegistrySubKeyNames(Class, out List<string> Names))
                Taken.UnionWith(Names);

            for (int Index = 0; Index < MaxClassInstances; Index++)
            {
                string Name = Index.ToString("D4");
                if (!Taken.Contains(Name))
                    return Name;
            }

            return null;
        }

        internal static bool TryReadHandleArgument(BinaryEmulator Instance, out uint Handle)
        {
            Handle = 0;
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            return ArgumentsPtr != 0 && Instance.WinHelper.TryReadUInt32(ArgumentsPtr, out Handle);
        }

        internal static bool TryGetHandleArgument<T>(BinaryEmulator Instance, out T Object) where T : class
        {
            Object = null;
            return TryReadHandleArgument(Instance, out uint Handle) && Instance.WinHelper.DxgkProcess.TryGet(Handle, out Object);
        }

        internal static void WriteLuid(Span<byte> Destination, DxgkAdapter Adapter)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0, 4), Adapter.LuidLowPart);
            BinaryPrimitives.WriteInt32LittleEndian(Destination.Slice(4, 4), Adapter.LuidHighPart);
        }

        // D3DKMT_ENUMADAPTERS2 and 3: pAdapters follows NumAdapters on the guest pointer alignment.
        internal static NTSTATUS EnumerateToArray(BinaryEmulator Instance, int OffsetNumAdapters)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            int PointerSize = Instance.WinHelper.PointerSize;
            Span<byte> Arguments = stackalloc byte[24];
            Arguments = Arguments.Slice(0, OffsetNumAdapters + 2 * PointerSize);
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Capacity = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetNumAdapters));
            ulong AdaptersPtr = WinSysHelper.ReadPointerField(Arguments.Slice(OffsetNumAdapters + PointerSize), 0, (uint)PointerSize);
            return Enumerate(Instance, ArgumentsPtr + (ulong)OffsetNumAdapters, AdaptersPtr, Capacity);
        }

        internal static NTSTATUS Enumerate(BinaryEmulator Instance, ulong CountPtr, ulong ArrayPtr, uint Capacity)
        {
            uint Count = MaxEnumAdapters;
            if (ArrayPtr != 0)
            {
                NTSTATUS Status = TryEnumerate(Instance, ArrayPtr, Capacity, out Count);
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;
            }

            return Instance.WinHelper.WriteUInt32(CountPtr, Count) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;
        }

        // NT: every enumeration call opens new adapter handles.
        private static NTSTATUS TryEnumerate(BinaryEmulator Instance, ulong ArrayPtr, uint Capacity, out uint Count)
        {
            Count = (uint)Adapters.Length;
            if (Capacity < Count)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            int Size = Adapters.Length * AdapterInfoSize;
            Span<byte> Infos = Instance.WinHelper.Shared.GetSpan((ulong)Size).Slice(0, Size);
            Infos.Clear();

            for (int Index = 0; Index < Adapters.Length; Index++)
            {
                if (!Process.TryAdd(Adapters[Index], out uint Handle))
                {
                    CloseWritten(Process, Infos, Index);
                    return NTSTATUS.STATUS_NO_MEMORY;
                }

                Span<byte> Info = Infos.Slice(Index * AdapterInfoSize, AdapterInfoSize);
                BinaryPrimitives.WriteUInt32LittleEndian(Info, Handle);
                WriteLuid(Info.Slice(4, 8), Adapters[Index]);
                BinaryPrimitives.WriteUInt32LittleEndian(Info.Slice(12, 4), Adapters[Index].SourceCount);
            }

            if (Instance.WriteMemory(ArrayPtr, Infos))
                return NTSTATUS.STATUS_SUCCESS;

            CloseWritten(Process, Infos, Adapters.Length);
            return NTSTATUS.STATUS_INVALID_PARAMETER;
        }

        private static void CloseWritten(DxgkProcess Process, ReadOnlySpan<byte> Infos, int Opened)
        {
            for (int Index = 0; Index < Opened; Index++)
                Process.TryRemove<DxgkAdapter>(BinaryPrimitives.ReadUInt32LittleEndian(Infos.Slice(Index * AdapterInfoSize)));
        }

        internal const int HybridQuerySize = 20;
        internal const int OffsetHybridQueryType = 16;
        internal const uint HybridQueryAdapter = 0;
        internal const uint HybridQueryProcess1 = 1;
        internal const uint HybridQueryProcess2 = 2;

        internal const uint PropertyDefaultHighPerformanceAdapter = 2;
        private const uint PropertyPresentDurationPlane = 3;
        private const uint PropertyPresentStatsDwm2 = 4;
        private const uint PropertyBoostedVSyncEligible = 5;

        internal static bool TryReadProperties(BinaryEmulator Instance, ulong ArgumentsPtr, bool Set, out uint Type, out ulong DataPtr)
        {
            Type = 0;
            DataPtr = 0;

            // NT: Get checks only the low half of Reserved, and wow64win passes a 32-bit Get its pointer at 12.
            bool Wide = Instance.WinHelper.PointerSize == 8;
            Span<byte> Arguments = stackalloc byte[24];
            Arguments = Arguments.Slice(0, Wide ? 24 : 20);
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return false;

            Type = BinaryPrimitives.ReadUInt32LittleEndian(Arguments);
            uint Size = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(4));
            ulong Reserved = Set ? BinaryPrimitives.ReadUInt64LittleEndian(Arguments.Slice(8)) : BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(8));
            DataPtr = WinSysHelper.ReadPointerField(Arguments.Slice(Wide || Set ? 16 : 12), 0, (uint)Instance.WinHelper.PointerSize);

            uint MinimumSize = Type switch
            {
                PropertyPresentDurationPlane => 32,
                PropertyPresentStatsDwm2 when !Set => 88,
                <= PropertyDefaultHighPerformanceAdapter or PropertyBoostedVSyncEligible => 16,
                _ => uint.MaxValue,
            };

            return DataPtr != 0 && Size != 0 && Reserved == 0 && Size >= MinimumSize;
        }
    }
}
