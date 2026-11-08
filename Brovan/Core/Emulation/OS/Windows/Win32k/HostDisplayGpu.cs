using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    // Finds the host GPU that the guest's DXGI reports as adapter 0, and keeps the answer for the session.
    internal static unsafe class HostDisplayGpu
    {
        private const string DisableVariable = "BROVAN_NO_HOST_GPU_PROBE";
        private const string SessionFileName = "display-gpu.bin";

        private const uint ProbeApiVersion = VulkanStandIns.ApiVersion11;
        private const uint MinimumGuestApiVersion = VulkanStandIns.ApiVersion13;
        private const uint MaxPciId = 0xFFFF;
        private const int MaxExtensions = 1024;
        private const int MaxSysfsEntries = 4096;

        private const uint CmFilterPresent = 0x100;
        private const uint CmFilterClass = 0x200;
        private const int DevPropKeySize = 20;
        private const int MaxHostStringChars = 128;

        private const uint RecordMagic = 0x55504742;
        private const uint RecordFormatVersion = 2;
        private const int MaxDescriptionChars = 256;
        private const int MaxProviderChars = 128;
        private const int MaxDriverVersionChars = 64;
        private const int RecordVersion = 4;
        private const int RecordVendorId = 8;
        private const int RecordDeviceId = 12;
        private const int RecordUuid = 16;
        private const int RecordHasLocation = 32;
        private const int RecordBus = 36;
        private const int RecordSlot = 40;
        private const int RecordFunction = 42;
        private const int RecordDescriptionChars = 44;
        private const int RecordProviderChars = 46;
        private const int RecordDriverVersionChars = 48;
        private const int RecordDescription = 52;
        private const int RecordProvider = RecordDescription + MaxDescriptionChars * 2;
        private const int RecordDriverVersion = RecordProvider + MaxProviderChars * 2;
        private const int RecordSize = RecordDriverVersion + MaxDriverVersionChars * 2;

        private static readonly int AppSize = BrovVulkLayout.StructSize["VkApplicationInfo"];
        private static readonly int AppApiVersion = BrovVulkLayout.MemberOffset["VkApplicationInfo.apiVersion"];
        private static readonly int InstanceInfoSize = BrovVulkLayout.StructSize["VkInstanceCreateInfo"];
        private static readonly int InstanceInfoApp = BrovVulkLayout.MemberOffset["VkInstanceCreateInfo.pApplicationInfo"];
        private static readonly int Properties2Size = BrovVulkLayout.StructSize["VkPhysicalDeviceProperties2"];
        private static readonly int Properties2Properties = BrovVulkLayout.MemberOffset["VkPhysicalDeviceProperties2.properties"];
        private static readonly int PropertiesVendorId = BrovVulkLayout.MemberOffset["VkPhysicalDeviceProperties.vendorID"];
        private static readonly int PropertiesDeviceId = BrovVulkLayout.MemberOffset["VkPhysicalDeviceProperties.deviceID"];
        private static readonly int PropertiesDeviceName = BrovVulkLayout.MemberOffset["VkPhysicalDeviceProperties.deviceName"];
        private static readonly int DriverSize = BrovVulkLayout.StructSize["VkPhysicalDeviceDriverProperties"];
        private static readonly int DriverName = BrovVulkLayout.MemberOffset["VkPhysicalDeviceDriverProperties.driverName"];
        private static readonly int PciSize = BrovVulkLayout.StructSize["VkPhysicalDevicePCIBusInfoPropertiesEXT"];
        private static readonly int PciDomain = BrovVulkLayout.MemberOffset["VkPhysicalDevicePCIBusInfoPropertiesEXT.pciDomain"];
        private static readonly int PciBus = BrovVulkLayout.MemberOffset["VkPhysicalDevicePCIBusInfoPropertiesEXT.pciBus"];
        private static readonly int PciDevice = BrovVulkLayout.MemberOffset["VkPhysicalDevicePCIBusInfoPropertiesEXT.pciDevice"];
        private static readonly int PciFunction = BrovVulkLayout.MemberOffset["VkPhysicalDevicePCIBusInfoPropertiesEXT.pciFunction"];
        private static readonly int ExtensionSize = BrovVulkLayout.StructSize["VkExtensionProperties"];

        internal static bool Disabled => Environment.GetEnvironmentVariable(DisableVariable) == "1";

        // The adapter order the guest's DXGI uses.
        internal static int Select(ReadOnlySpan<int> DeviceTypes, ReadOnlySpan<uint> ApiVersions)
        {
            bool AnyNotCpu = false;
            foreach (int Type in DeviceTypes)
                AnyNotCpu |= Type != BrovVulkConstants.VK_PHYSICAL_DEVICE_TYPE_CPU;

            int Best = -1;
            int BestRank = int.MaxValue;
            for (int Index = 0; Index < DeviceTypes.Length; Index++)
            {
                if (ApiVersions[Index] < MinimumGuestApiVersion)
                    continue;
                if (AnyNotCpu && DeviceTypes[Index] == BrovVulkConstants.VK_PHYSICAL_DEVICE_TYPE_CPU)
                    continue;

                int Rank = DeviceTypes[Index] switch
                {
                    BrovVulkConstants.VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU => 0,
                    BrovVulkConstants.VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU => 1,
                    BrovVulkConstants.VK_PHYSICAL_DEVICE_TYPE_VIRTUAL_GPU => 2,
                    _ => 3,
                };

                if (Rank < BestRank)
                {
                    Best = Index;
                    BestRank = Rank;
                }
            }

            return Best;
        }

        internal static AdapterIdentity Probe(out string Reason)
        {
            IntPtr Loader = BrovVulkProc.HostLoader;
            if (Loader == IntPtr.Zero || !NativeLibrary.TryGetExport(Loader, "vkGetInstanceProcAddr", out IntPtr GetProc) || GetProc == IntPtr.Zero)
            {
                Reason = "no host Vulkan loader";
                return null;
            }

            delegate* unmanaged<IntPtr, byte*, IntPtr> Gipa = (delegate* unmanaged<IntPtr, byte*, IntPtr>)GetProc;
            delegate* unmanaged<byte*, void*, IntPtr*, int> Create = (delegate* unmanaged<byte*, void*, IntPtr*, int>)Proc(Gipa, IntPtr.Zero, "vkCreateInstance\0"u8);
            if (Create == null)
            {
                Reason = "the host loader has no vkCreateInstance";
                return null;
            }

            byte* App = stackalloc byte[AppSize];
            byte* Info = stackalloc byte[InstanceInfoSize];
            new Span<byte>(App, AppSize).Clear();
            new Span<byte>(Info, InstanceInfoSize).Clear();
            *(int*)App = BrovVulkConstants.VK_STRUCTURE_TYPE_APPLICATION_INFO;
            *(uint*)(App + AppApiVersion) = ProbeApiVersion;
            *(int*)Info = BrovVulkConstants.VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
            *(byte**)(Info + InstanceInfoApp) = App;

            HashSet<string> Before = LoadedLibraries(null);
            IntPtr Instance = IntPtr.Zero;
            delegate* unmanaged<IntPtr, void*, void> Destroy = null;
            try
            {
                int Created = Create(Info, null, &Instance);
                if (Created != 0 || Instance == IntPtr.Zero)
                {
                    Reason = $"vkCreateInstance returned {Created}";
                    return null;
                }

                Destroy = (delegate* unmanaged<IntPtr, void*, void>)Proc(Gipa, Instance, "vkDestroyInstance\0"u8);
                return ProbeInstance(Gipa, Instance, out Reason);
            }
            finally
            {
                KeepLoadedSince(Before);
                if (Destroy != null)
                    Destroy(Instance, null);
            }
        }

        // An ELF host runs the TSD destructors of an exiting thread by address. A host driver can unload a library
        // that left one for the probe thread, so every library that the probe caused to load stays loaded.
        private static void KeepLoadedSince(HashSet<string> Before)
        {
            if (Before == null)
                return;

            HashSet<string> Added = LoadedLibraries(Before);
            if (Added == null)
                return;

            foreach (string Library in Added)
            {
                if (!NativeLibrary.TryLoad(Library, out _))
                    Utils.LogError($"[HostDisplayGpu] Cannot keep {Library} loaded");
            }
        }

        private sealed class LibraryScan
        {
            internal readonly HashSet<string> Paths = new HashSet<string>(StringComparer.Ordinal);
            internal HashSet<string> Known;
            internal Exception Failure;
        }

        private static HashSet<string> LoadedLibraries(HashSet<string> Known)
        {
            if (GeneralHelper.IsWindows || !NativeLibrary.TryGetExport(NativeLibrary.GetMainProgramHandle(), "dl_iterate_phdr", out IntPtr Iterate))
                return null;

            LibraryScan Scan = new LibraryScan { Known = Known };
            GCHandle Handle = GCHandle.Alloc(Scan);
            try
            {
                ((delegate* unmanaged<delegate* unmanaged<IntPtr, nuint, IntPtr, int>, IntPtr, int>)Iterate)(&AddLibrary, GCHandle.ToIntPtr(Handle));
            }
            finally
            {
                Handle.Free();
            }

            if (Scan.Failure != null)
            {
                Utils.LogError($"[HostDisplayGpu] Cannot list the host libraries: {Scan.Failure.Message}");
                return null;
            }

            return Scan.Paths;
        }

        [UnmanagedCallersOnly]
        private static int AddLibrary(IntPtr Info, nuint Size, IntPtr Data)
        {
            LibraryScan Scan = (LibraryScan)GCHandle.FromIntPtr(Data).Target;
            try
            {
                byte* Name = *(byte**)(Info + IntPtr.Size);
                if (Name != null && *Name == (byte)'/')
                {
                    string Library = Marshal.PtrToStringUTF8((IntPtr)Name);
                    if (Scan.Known == null || !Scan.Known.Contains(Library))
                        Scan.Paths.Add(Library);
                }
                return 0;
            }
            catch (Exception Error)
            {
                Scan.Failure = Error;
                return 1;
            }
        }

        private static IntPtr Proc(delegate* unmanaged<IntPtr, byte*, IntPtr> Gipa, IntPtr Instance, ReadOnlySpan<byte> Name)
        {
            fixed (byte* Pointer = Name)
                return Gipa(Instance, Pointer);
        }

        private static AdapterIdentity ProbeInstance(delegate* unmanaged<IntPtr, byte*, IntPtr> Gipa, IntPtr Instance, out string Reason)
        {
            delegate* unmanaged<IntPtr, uint*, IntPtr*, int> Enumerate = (delegate* unmanaged<IntPtr, uint*, IntPtr*, int>)Proc(Gipa, Instance, "vkEnumeratePhysicalDevices\0"u8);
            delegate* unmanaged<IntPtr, byte*, void> Properties2 = (delegate* unmanaged<IntPtr, byte*, void>)Proc(Gipa, Instance, "vkGetPhysicalDeviceProperties2\0"u8);
            delegate* unmanaged<IntPtr, byte*, uint*, byte*, int> Extensions = (delegate* unmanaged<IntPtr, byte*, uint*, byte*, int>)Proc(Gipa, Instance, "vkEnumerateDeviceExtensionProperties\0"u8);
            if (Enumerate == null || Properties2 == null || Extensions == null)
            {
                Reason = "the host instance lacks a Vulkan 1.1 query";
                return null;
            }

            uint Count = VulkanStandIns.MaxPhysicalDevices;
            IntPtr* Devices = stackalloc IntPtr[VulkanStandIns.MaxPhysicalDevices];
            int Result = Enumerate(Instance, &Count, Devices);
            if (Result < 0 || Count == 0)
            {
                Reason = "the host has no Vulkan device";
                return null;
            }
            Count = Math.Min(Count, VulkanStandIns.MaxPhysicalDevices);

            Span<int> Types = stackalloc int[(int)Count];
            Span<uint> ApiVersions = stackalloc uint[(int)Count];
            byte* Properties = stackalloc byte[Properties2Size];
            for (int Index = 0; Index < Count; Index++)
            {
                new Span<byte>(Properties, Properties2Size).Clear();
                *(int*)Properties = BrovVulkConstants.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2;
                Properties2(Devices[Index], Properties);
                Types[Index] = *(int*)(Properties + Properties2Properties + VulkanStandIns.PropertiesDeviceType);
                ApiVersions[Index] = *(uint*)(Properties + Properties2Properties + BrovVulkGenExt.PropertiesApiVersion);
            }

            int Chosen = Select(Types, ApiVersions);
            if (Chosen < 0)
            {
                Reason = "no host Vulkan device supports Vulkan 1.3";
                return null;
            }

            IntPtr Device = Devices[Chosen];
            bool HasPciExtension = HasExtension(Extensions, Device, "VK_EXT_pci_bus_info"u8);

            byte* Id = stackalloc byte[VulkanStandIns.IdPropertiesSize];
            byte* Driver = stackalloc byte[DriverSize];
            byte* Pci = stackalloc byte[PciSize];
            new Span<byte>(Properties, Properties2Size).Clear();
            new Span<byte>(Id, VulkanStandIns.IdPropertiesSize).Clear();
            new Span<byte>(Driver, DriverSize).Clear();
            new Span<byte>(Pci, PciSize).Clear();
            *(int*)Properties = BrovVulkConstants.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2;
            *(byte**)(Properties + VkOffsets.NodePNext) = Id;
            *(int*)Id = BrovVulkConstants.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ID_PROPERTIES;
            *(byte**)(Id + VkOffsets.NodePNext) = Driver;
            *(int*)Driver = BrovVulkConstants.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DRIVER_PROPERTIES;
            if (HasPciExtension)
            {
                *(byte**)(Driver + VkOffsets.NodePNext) = Pci;
                *(int*)Pci = BrovVulkConstants.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PCI_BUS_INFO_PROPERTIES_EXT;
            }
            Properties2(Device, Properties);

            byte* Core = Properties + Properties2Properties;
            uint VendorId = *(uint*)(Core + PropertiesVendorId);
            uint DeviceId = *(uint*)(Core + PropertiesDeviceId);
            if (VendorId > MaxPciId || DeviceId > MaxPciId)
            {
                Reason = $"vendor 0x{VendorId:X} device 0x{DeviceId:X} is not a PCI id";
                return null;
            }

            Reason = null;
            string Name = ReadFixedString(Core + PropertiesDeviceName, BrovVulkConstants.VK_MAX_PHYSICAL_DEVICE_NAME_SIZE);
            string Provider = ReadFixedString(Driver + DriverName, BrovVulkConstants.VK_MAX_DRIVER_NAME_SIZE);
            byte[] Uuid = new ReadOnlySpan<byte>(Id + VulkanStandIns.IdDeviceUuid, VulkanStandIns.UuidSize).ToArray();

            bool HasLocation = false;
            uint Bus = 0;
            ushort Slot = 0;
            ushort Function = 0;
            if (HasPciExtension && *(uint*)(Pci + PciDomain) == 0)
            {
                HasLocation = true;
                Bus = *(uint*)(Pci + PciBus);
                Slot = (ushort)*(uint*)(Pci + PciDevice);
                Function = (ushort)*(uint*)(Pci + PciFunction);
            }

            string DriverVersion = null;
            if (GeneralHelper.IsWindows && *(uint*)(Id + VulkanStandIns.IdDeviceLuidValid) != 0)
            {
                ulong Luid = *(ulong*)(Id + VulkanStandIns.IdDeviceLuid);
                if (TryReadWindowsHostAdapter(Luid, out bool HostHasLocation, out uint HostBus, out uint HostAddress, out string HostProvider,
                    out DriverVersion))
                {
                    if (!string.IsNullOrEmpty(HostProvider))
                        Provider = HostProvider;
                    if (!HasLocation && HostHasLocation)
                    {
                        HasLocation = true;
                        Bus = HostBus;
                        Slot = (ushort)(HostAddress >> 16);
                        Function = (ushort)HostAddress;
                    }
                }
            }
            else if (!GeneralHelper.IsWindows && !HasLocation && TryReadSysfsLocation(VendorId, DeviceId, out uint SysBus, out ushort SysSlot, out ushort SysFunction))
            {
                HasLocation = true;
                Bus = SysBus;
                Slot = SysSlot;
                Function = SysFunction;
            }

            return AdapterIdentity.ForPci(VendorId, DeviceId, Name, Provider, DriverVersion, Uuid, HasLocation, Bus, Slot, Function);
        }

        private static bool HasExtension(delegate* unmanaged<IntPtr, byte*, uint*, byte*, int> Extensions, IntPtr Device, ReadOnlySpan<byte> Wanted)
        {
            uint Count = 0;
            if (Extensions(Device, null, &Count, null) < 0 || Count == 0 || Count > MaxExtensions)
                return false;

            byte[] List = new byte[Count * ExtensionSize];
            fixed (byte* Buffer = List)
            {
                if (Extensions(Device, null, &Count, Buffer) < 0)
                    return false;

                for (int Index = 0; Index < Count; Index++)
                {
                    if (FixedName(Buffer + Index * ExtensionSize, BrovVulkConstants.VK_MAX_EXTENSION_NAME_SIZE).SequenceEqual(Wanted))
                        return true;
                }
            }

            return false;
        }

        private static ReadOnlySpan<byte> FixedName(byte* Field, int Size)
        {
            ReadOnlySpan<byte> Bytes = new ReadOnlySpan<byte>(Field, Size);
            int End = Bytes.IndexOf((byte)0);
            return End < 0 ? Bytes : Bytes.Slice(0, End);
        }

        private static string ReadFixedString(byte* Field, int Size) => Encoding.UTF8.GetString(FixedName(Field, Size));

        private static bool TryReadWindowsHostAdapter(ulong Luid, out bool HasLocation, out uint Bus, out uint Address, out string Provider,
            out string DriverVersion)
        {
            HasLocation = false;
            Bus = 0;
            Address = 0;
            Provider = null;
            DriverVersion = null;

            if (NativeWinImports.CM_Get_Device_ID_List_SizeW(out uint Length, Win32kDxgk.DisplayClass, CmFilterClass | CmFilterPresent) != 0 || Length == 0)
                return false;

            char[] List = new char[Length];
            fixed (char* Ids = List)
            {
                if (NativeWinImports.CM_Get_Device_ID_ListW(Win32kDxgk.DisplayClass, Ids, Length, CmFilterClass | CmFilterPresent) != 0)
                    return false;
            }

            byte* Key = stackalloc byte[DevPropKeySize];
            ReadOnlySpan<char> Rest = List;
            while (!Rest.IsEmpty && Rest[0] != '\0')
            {
                int End = Rest.IndexOf('\0');
                if (End < 0)
                    break;

                uint Node;
                uint Located;
                fixed (char* Id = Rest)
                    Located = NativeWinImports.CM_Locate_DevNodeW(out Node, Id, 0);

                Rest = Rest.Slice(End + 1);
                if (Located != 0 || !TryReadHostProperty(Node, Key, DeviceNodes.AdapterLuid, DeviceNodes.TypeUInt64, out ulong Value) || Value != Luid)
                    continue;

                if (TryReadHostProperty(Node, Key, DeviceNodes.BusNumber, DeviceNodes.TypeUInt32, out ulong BusValue)
                    && TryReadHostProperty(Node, Key, DeviceNodes.Address, DeviceNodes.TypeUInt32, out ulong AddressValue))
                {
                    HasLocation = true;
                    Bus = (uint)BusValue;
                    Address = (uint)AddressValue;
                }

                Provider = ReadHostString(Node, Key, DeviceNodes.DriverProvider);
                DriverVersion = ReadHostString(Node, Key, DeviceNodes.DriverVersion);
                return true;
            }

            return false;
        }

        private static void WriteKey(byte* Key, DevicePropertyKey Property)
        {
            Property.Category.TryWriteBytes(new Span<byte>(Key, 16));
            *(uint*)(Key + 16) = Property.Id;
        }

        private static bool TryReadHostProperty(uint Node, byte* Key, DevicePropertyKey Property, uint ExpectedType, out ulong Value)
        {
            Value = 0;
            WriteKey(Key, Property);
            ulong Buffer = 0;
            uint Size = ExpectedType == DeviceNodes.TypeUInt64 ? 8u : 4u;
            if (NativeWinImports.CM_Get_DevNode_PropertyW(Node, Key, out uint Type, &Buffer, ref Size, 0) != 0 || Type != ExpectedType)
                return false;

            Value = Buffer;
            return true;
        }

        private static string ReadHostString(uint Node, byte* Key, DevicePropertyKey Property)
        {
            WriteKey(Key, Property);
            char* Buffer = stackalloc char[MaxHostStringChars];
            uint Size = MaxHostStringChars * sizeof(char);
            if (NativeWinImports.CM_Get_DevNode_PropertyW(Node, Key, out uint Type, Buffer, ref Size, 0) != 0 || Type != DeviceNodes.TypeString)
                return null;

            ReadOnlySpan<char> Text = new ReadOnlySpan<char>(Buffer, (int)Math.Min(Size / sizeof(char), (uint)MaxHostStringChars));
            int End = Text.IndexOf('\0');
            return new string(End < 0 ? Text : Text.Slice(0, End));
        }

        // Domains other than 0 have no NT bus number.
        private static bool TryReadSysfsLocation(uint VendorId, uint DeviceId, out uint Bus, out ushort Slot, out ushort Function)
        {
            Bus = 0;
            Slot = 0;
            Function = 0;
            int Matches = 0;

            try
            {
                int Seen = 0;
                foreach (string Entry in Directory.EnumerateDirectories("/sys/bus/pci/devices"))
                {
                    if (++Seen > MaxSysfsEntries)
                        break;

                    if (!TryReadHex(Path.Combine(Entry, "class"), out uint Class) || (Class >> 16) != 0x03
                        || !TryReadHex(Path.Combine(Entry, "vendor"), out uint Vendor) || Vendor != VendorId
                        || !TryReadHex(Path.Combine(Entry, "device"), out uint Device) || Device != DeviceId)
                        continue;

                    string Name = Path.GetFileName(Entry);
                    string[] Parts = Name.Split(':', '.');
                    if (Parts.Length != 4
                        || !uint.TryParse(Parts[0], System.Globalization.NumberStyles.HexNumber, null, out uint Domain) || Domain != 0
                        || !uint.TryParse(Parts[1], System.Globalization.NumberStyles.HexNumber, null, out uint EntryBus)
                        || !ushort.TryParse(Parts[2], System.Globalization.NumberStyles.HexNumber, null, out ushort EntrySlot)
                        || !ushort.TryParse(Parts[3], System.Globalization.NumberStyles.HexNumber, null, out ushort EntryFunction))
                        continue;

                    Matches++;
                    Bus = EntryBus;
                    Slot = EntrySlot;
                    Function = EntryFunction;
                }
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException)
            {
                return false;
            }

            return Matches == 1;
        }

        private static bool TryReadHex(string FilePath, out uint Value)
        {
            Value = 0;
            string Text;
            try
            {
                Text = File.ReadAllText(FilePath).Trim();
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException)
            {
                return false;
            }

            if (Text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                Text = Text.Substring(2);
            return uint.TryParse(Text, System.Globalization.NumberStyles.HexNumber, null, out Value);
        }

        internal static bool TryReadSessionRecord(out AdapterIdentity Identity)
        {
            Identity = null;
            string Directory = GuestSession.OpenDirectory;
            if (Directory == null)
                return false;

            string FilePath = Path.Combine(Directory, SessionFileName);
            if (!File.Exists(FilePath))
                return false;

            byte[] Record = new byte[RecordSize];
            try
            {
                using FileStream Stream = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
                if (Stream.Length != RecordSize)
                    return false;
                Stream.ReadExactly(Record);
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException)
            {
                return false;
            }

            ReadOnlySpan<byte> Data = Record;
            uint VendorId = BinaryPrimitives.ReadUInt32LittleEndian(Data.Slice(RecordVendorId));
            uint DeviceId = BinaryPrimitives.ReadUInt32LittleEndian(Data.Slice(RecordDeviceId));
            int DescriptionChars = BinaryPrimitives.ReadUInt16LittleEndian(Data.Slice(RecordDescriptionChars));
            int ProviderChars = BinaryPrimitives.ReadUInt16LittleEndian(Data.Slice(RecordProviderChars));
            int DriverVersionChars = BinaryPrimitives.ReadUInt16LittleEndian(Data.Slice(RecordDriverVersionChars));
            if (BinaryPrimitives.ReadUInt32LittleEndian(Data) != RecordMagic || BinaryPrimitives.ReadUInt32LittleEndian(Data.Slice(RecordVersion)) != RecordFormatVersion
                || VendorId > MaxPciId || DeviceId > MaxPciId || DescriptionChars > MaxDescriptionChars || ProviderChars > MaxProviderChars
                || DriverVersionChars > MaxDriverVersionChars)
                return false;

            Identity = AdapterIdentity.ForPci(
                VendorId,
                DeviceId,
                Encoding.Unicode.GetString(Data.Slice(RecordDescription, DescriptionChars * 2)),
                Encoding.Unicode.GetString(Data.Slice(RecordProvider, ProviderChars * 2)),
                DriverVersionChars == 0 ? null : Encoding.Unicode.GetString(Data.Slice(RecordDriverVersion, DriverVersionChars * 2)),
                Data.Slice(RecordUuid, VulkanStandIns.UuidSize).ToArray(),
                (BinaryPrimitives.ReadUInt32LittleEndian(Data.Slice(RecordHasLocation)) & 1) != 0,
                BinaryPrimitives.ReadUInt32LittleEndian(Data.Slice(RecordBus)),
                BinaryPrimitives.ReadUInt16LittleEndian(Data.Slice(RecordSlot)),
                BinaryPrimitives.ReadUInt16LittleEndian(Data.Slice(RecordFunction)));
            return true;
        }

        // The first writer of a session wins, and GuestSession deletes the record with the session.
        internal static void WriteSessionRecord(AdapterIdentity Identity)
        {
            string Directory = GuestSession.OpenDirectory;
            if (Directory == null)
                return;

            byte[] Record = new byte[RecordSize];
            Span<byte> Data = Record;
            string Description = Fit(Identity.Description, MaxDescriptionChars);
            string Provider = Fit(Identity.ProviderName, MaxProviderChars);
            string DriverVersion = Fit(Identity.DriverVersion ?? string.Empty, MaxDriverVersionChars);
            BinaryPrimitives.WriteUInt32LittleEndian(Data, RecordMagic);
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(RecordVersion), RecordFormatVersion);
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(RecordVendorId), Identity.VendorId);
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(RecordDeviceId), Identity.DeviceId);
            Identity.DeviceUuid.AsSpan(0, VulkanStandIns.UuidSize).CopyTo(Data.Slice(RecordUuid));
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(RecordHasLocation), Identity.HasLocation ? 1u : 0u);
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(RecordBus), Identity.Bus);
            BinaryPrimitives.WriteUInt16LittleEndian(Data.Slice(RecordSlot), Identity.Device);
            BinaryPrimitives.WriteUInt16LittleEndian(Data.Slice(RecordFunction), Identity.Function);
            BinaryPrimitives.WriteUInt16LittleEndian(Data.Slice(RecordDescriptionChars), (ushort)Description.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(Data.Slice(RecordProviderChars), (ushort)Provider.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(Data.Slice(RecordDriverVersionChars), (ushort)DriverVersion.Length);
            Encoding.Unicode.GetBytes(Description, Data.Slice(RecordDescription));
            Encoding.Unicode.GetBytes(Provider, Data.Slice(RecordProvider));
            Encoding.Unicode.GetBytes(DriverVersion, Data.Slice(RecordDriverVersion));

            string Final = Path.Combine(Directory, SessionFileName);
            string Temporary = Final + "." + Environment.ProcessId.ToString("X") + ".tmp";
            try
            {
                File.WriteAllBytes(Temporary, Record);
                File.Move(Temporary, Final, false);
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException)
            {
                if (!File.Exists(Final))
                    Utils.LogError($"[HostDisplayGpu] Cannot keep the display GPU for the session: {Error.Message}");
                try
                {
                    File.Delete(Temporary);
                }
                catch (Exception DeleteError) when (DeleteError is IOException || DeleteError is UnauthorizedAccessException)
                {
                    Utils.LogError($"[HostDisplayGpu] Cannot delete {Temporary}: {DeleteError.Message}");
                }
            }
        }

        private static string Fit(string Text, int MaxChars) => Text.Length > MaxChars ? Text.Substring(0, MaxChars) : Text;
    }
}
