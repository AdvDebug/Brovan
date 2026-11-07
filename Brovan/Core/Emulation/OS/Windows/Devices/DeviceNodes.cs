using System.Buffers.Binary;
using System.Text;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal readonly record struct DevicePropertyKey(Guid Category, uint Id);

    internal readonly record struct DeviceProperty(uint Type, byte[] Data);

    internal sealed class DeviceNode
    {
        internal string InstanceId { get; init; }
        internal DeviceNode Parent { get; init; }
        internal uint Status { get; init; }
        internal uint Problem { get; init; }
        internal readonly List<DeviceNode> Children = new List<DeviceNode>();
        internal readonly Dictionary<DevicePropertyKey, DeviceProperty> Properties = new Dictionary<DevicePropertyKey, DeviceProperty>();

        internal void SetString(DevicePropertyKey Key, string Value) =>
            Properties[Key] = new DeviceProperty(DeviceNodes.TypeString, Encoding.Unicode.GetBytes(Value + "\0"));

        internal void SetStringList(DevicePropertyKey Key, string Value) =>
            Properties[Key] = new DeviceProperty(DeviceNodes.TypeStringList, Encoding.Unicode.GetBytes(Value + "\0\0"));

        internal void SetGuid(DevicePropertyKey Key, Guid Value) =>
            Properties[Key] = new DeviceProperty(DeviceNodes.TypeGuid, Value.ToByteArray());

        internal void SetUInt32(DevicePropertyKey Key, uint Value)
        {
            byte[] Data = new byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(Data, Value);
            Properties[Key] = new DeviceProperty(DeviceNodes.TypeUInt32, Data);
        }

        internal void SetUInt64(DevicePropertyKey Key, ulong Value)
        {
            byte[] Data = new byte[8];
            BinaryPrimitives.WriteUInt64LittleEndian(Data, Value);
            Properties[Key] = new DeviceProperty(DeviceNodes.TypeUInt64, Data);
        }
    }

    // Only Brovan code adds nodes, under KernelLock, once the device a node describes exists.
    internal sealed class DeviceNodes
    {
        internal const string RootId = @"HTREE\ROOT\0";
        internal const string ControlSet = @"\Registry\Machine\System\CurrentControlSet\";

        internal const uint TypeUInt32 = 0x7;
        internal const uint TypeUInt64 = 0x9;
        internal const uint TypeGuid = 0xD;
        internal const uint TypeString = 0x12;
        internal const uint TypeStringList = 0x2012;

        internal const uint StatusDriverLoaded = 0x2;
        internal const uint StatusStarted = 0x8;
        internal const uint StatusDisableable = 0x2000;
        internal const uint StatusNtEnumerator = 0x00800000;
        internal const uint StatusNtDriver = 0x01000000;

        internal static readonly Guid DeviceCategory = new Guid("a45c254e-df1c-4efd-8020-67d146a850e0");
        internal static readonly DevicePropertyKey DeviceDesc = new(DeviceCategory, 2);
        internal static readonly DevicePropertyKey HardwareIds = new(DeviceCategory, 3);
        internal static readonly DevicePropertyKey Class = new(DeviceCategory, 9);
        internal static readonly DevicePropertyKey ClassGuid = new(DeviceCategory, 10);
        internal static readonly DevicePropertyKey Driver = new(DeviceCategory, 11);
        internal static readonly DevicePropertyKey Manufacturer = new(DeviceCategory, 13);
        internal static readonly DevicePropertyKey BusNumber = new(DeviceCategory, 23);
        internal static readonly DevicePropertyKey Address = new(DeviceCategory, 30);
        internal static readonly DevicePropertyKey AdapterLuid = new(new Guid("60b193cb-5276-4d0f-96fc-f173abad3ec6"), 2);
        internal static readonly Guid DriverCategory = new Guid("a8b865dd-2e3d-4094-ad97-e593a70c75d6");
        internal static readonly DevicePropertyKey DriverVersion = new(DriverCategory, 3);
        internal static readonly DevicePropertyKey DriverProvider = new(DriverCategory, 9);

        // NT reads these CM_DRP codes from Enum\<id> values, but BUSNUMBER from the live devnode (CmGetDeviceRegPropWorker).
        private static readonly (uint Code, DevicePropertyKey Key, int RegType, string ValueName)[] RegistryProperties =
        {
            (0x01, DeviceDesc, WinSysHelper.RegSz, "DeviceDesc"),
            (0x02, HardwareIds, WinSysHelper.RegMultiSz, "HardwareID"),
            (0x08, Class, WinSysHelper.RegSz, "Class"),
            (0x09, ClassGuid, WinSysHelper.RegSz, "ClassGUID"),
            (0x0A, Driver, WinSysHelper.RegSz, "Driver"),
            (0x0C, Manufacturer, WinSysHelper.RegSz, "Mfg"),
            (0x16, BusNumber, WinSysHelper.RegDword, null),
            (0x1D, Address, WinSysHelper.RegDword, "Address"),
        };

        internal const uint EnumeratorNameCode = 0x17;

        private readonly Dictionary<string, DeviceNode> ById = new Dictionary<string, DeviceNode>(StringComparer.OrdinalIgnoreCase);
        private readonly List<DeviceNode> Ordered = new List<DeviceNode>();

        internal DeviceNode Root { get; }

        internal IReadOnlyList<DeviceNode> All => Ordered;

        internal DeviceNodes()
        {
            Root = new DeviceNode { InstanceId = RootId, Status = StatusNtEnumerator | StatusNtDriver | StatusStarted | StatusDriverLoaded };
            ById.Add(RootId, Root);
            Ordered.Add(Root);
        }

        internal static string EnumKeyPath(string InstanceId) => ControlSet + @"Enum\" + InstanceId;

        internal static string ClassKeyPath(string Driver) => ControlSet + @"Control\Class\" + Driver;

        internal bool TryFind(string InstanceId, out DeviceNode Node) => ById.TryGetValue(InstanceId, out Node);

        // CfgMgr32 requests wait for the display adapter, the one device that publishes after process start.
        internal static bool TryWaitForSources(BinaryEmulator Instance, out NTSTATUS Parked) =>
            Win32k.Win32kDxgk.TryGetIdentity(Instance, Win32k.Win32kDxgk.Display, out _, out Parked);

        internal static bool TryMapRegistryProperty(uint Code, out DevicePropertyKey Key, out int RegType)
        {
            foreach ((uint Candidate, DevicePropertyKey Mapped, int Type, _) in RegistryProperties)
            {
                if (Candidate == Code)
                {
                    Key = Mapped;
                    RegType = Type;
                    return true;
                }
            }

            Key = default;
            RegType = 0;
            return false;
        }

        internal bool TryAdd(WinSysHelper WinHelper, DeviceNode Node)
        {
            if (Node.Parent == null || !ById.ContainsKey(Node.Parent.InstanceId) || ById.ContainsKey(Node.InstanceId))
                return false;

            ById.Add(Node.InstanceId, Node);
            Ordered.Add(Node);
            Node.Parent.Children.Add(Node);
            WriteEnumKey(WinHelper, Node);
            return true;
        }

        internal static bool TryGetRegistryValue(DeviceNode Node, DevicePropertyKey Key, int RegType, out byte[] Data)
        {
            Data = null;
            if (!Node.Properties.TryGetValue(Key, out DeviceProperty Property))
                return false;

            Data = Property.Type == TypeGuid && RegType == WinSysHelper.RegSz
                ? Encoding.Unicode.GetBytes(new Guid(Property.Data).ToString("B") + "\0")
                : Property.Data;
            return true;
        }

        private static void WriteEnumKey(WinSysHelper WinHelper, DeviceNode Node)
        {
            string Path = EnumKeyPath(Node.InstanceId);
            if (!WinHelper.CreateRegistryKeyPath(Path, true, out _))
                return;

            foreach ((_, DevicePropertyKey Key, int RegType, string ValueName) in RegistryProperties)
            {
                if (ValueName != null && TryGetRegistryValue(Node, Key, RegType, out byte[] Data))
                    WinHelper.SetRegistryValue(Path, ValueName, RegType, Data);
            }
        }
    }
}
