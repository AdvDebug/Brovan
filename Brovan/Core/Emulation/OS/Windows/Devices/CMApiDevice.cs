using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;

namespace Brovan.Core.Emulation.OS.Windows
{
    // A request that cannot be captured fails the IOCTL, and every later failure goes into the reply header.
    internal sealed class CMApiDevice : IWinDevice
    {
        private const uint CmApiDeviceType = 0x47;
        private const uint MethodNeither = 3;
        private const uint IoctlGetDeviceIdList = (CmApiDeviceType << 16) | (0x200 << 2) | MethodNeither;
        private const uint IoctlGetDeviceInterfaceList = (CmApiDeviceType << 16) | (0x201 << 2) | MethodNeither;
        private const uint IoctlGetObjectProperty = (CmApiDeviceType << 16) | (0x204 << 2) | MethodNeither;
        private const uint IoctlGetRegistryProperty = (CmApiDeviceType << 16) | (0x206 << 2) | MethodNeither;
        private const uint IoctlGetRelatedDevice = (CmApiDeviceType << 16) | (0x208 << 2) | MethodNeither;
        private const uint IoctlGetDeviceStatus = (CmApiDeviceType << 16) | (0x209 << 2) | MethodNeither;
        private const uint IoctlLocateDevNode = (CmApiDeviceType << 16) | (0x210 << 2) | MethodNeither;
        private const uint IoctlOpenDeviceKey = (CmApiDeviceType << 16) | (0x216 << 2) | MethodNeither;

        private const int BasicReplySize = 8;
        private const int StatusReplySize = 20;
        private const int HandleReplySize = 16;
        private const int BufferReplySize = 20;
        private const int BufferReplyData = 16;
        private const int ReplyStatusOffset = 4;
        private const int ReplyLengthOffset = 8;
        private const int ReplyTypeOffset = 12;

        private const int HeaderFlags = 4;
        private const int HeaderObjectType = 8;
        private const int PropertyKeySize = 20;

        // Two WCHARs. CM_Get_Device_Interface_ListW refuses anything shorter and asks again.
        private const int EmptyInterfaceListBytes = 4;

        private const int MaxStringBytes = 0xFFFF;
        private const int MaxDeviceIdLength = 200;

        private const uint ObjectDevice = 1;
        private const uint LocateNormal = 1;
        private const uint LocatePhantom = 2;
        private const uint RelationParent = 1;
        private const uint RelationChild = 2;
        private const uint RelationSibling = 3;

        private const uint ListFilterMask = 0xFFFF;
        private const uint ListPresentOnly = 0x10000;
        private const uint ListSkipMandatory = 0x20000;
        private const uint ListFilterNone = 0;
        private const uint ListFilterEnumerator = 0x1;
        private const uint ListFilterService = 0x2;
        private const uint ListFilterEjection = 0x4;
        private const uint ListFilterRemoval = 0x8;
        private const uint ListFilterPower = 0x10;
        private const uint ListFilterBus = 0x20;
        private const uint ListFilterTransport = 0x40;
        private const uint ListFilterClass = 0x80;

        private const uint MaxRegistryProperty = 0x25;
        private const uint RegistryUnused0 = 0x04;
        private const uint RegistryUnused1 = 0x06;
        private const uint RegistryUnused2 = 0x07;
        private const uint RegistrySecuritySds = 0x19;

        private const uint KeyHardware = 0x11;
        private const uint KeyControl = 0x13;
        private const uint KeyLogConf = 0x14;
        private const uint KeyTypeMask = 0xFF;
        private const uint KeyUser = 0x100;
        private const uint KeyConfig = 0x200;
        private const uint DispositionOpenAlways = 1;

        public string DeviceName => "\\Device\\DeviceApi\\CMApi";

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            InternalPath = DeviceName;
            Handler = Handle;
            return NTSTATUS.STATUS_SUCCESS;
        }

        // The request layouts follow the PiCMCapture*InputData routines, x64 then x86.
        private readonly record struct Layout(int Size, int Pointer, int Length, int Result, int CallerBuffer = 0)
        {
            internal int Fields => Length + sizeof(uint);
        }

        private static readonly Layout ObjectX64 = new(40, 0x10, 0x18, 0x20);
        private static readonly Layout ObjectX86 = new(28, 0x0C, 0x10, 0x18);
        private static readonly Layout ListX64 = new(24, 0x08, 0x10, 0x14);
        private static readonly Layout ListX86 = new(20, 0x08, 0x0C, 0x10);
        private static readonly Layout RegistryX64 = new(56, 0x10, 0x18, 0x34, CallerBuffer: 0x28);
        private static readonly Layout RegistryX86 = new(40, 0x0C, 0x10, 0x24, CallerBuffer: 0x1C);
        private static readonly Layout PropertyX64 = new(72, 0x10, 0x18, 0x44, CallerBuffer: 0x38);
        private static readonly Layout PropertyX86 = new(56, 0x0C, 0x10, 0x34, CallerBuffer: 0x2C);
        private static readonly Layout KeyX64 = new(48, 0x10, 0x18, 0x28);
        private static readonly Layout KeyX86 = new(36, 0x0C, 0x10, 0x20);

        private static bool TryDescribe(uint IOCTL, bool Wide, out Layout Request, out int ReplySize)
        {
            (Layout X64, Layout X86, ReplySize) = IOCTL switch
            {
                IoctlLocateDevNode => (ObjectX64, ObjectX86, BasicReplySize),
                IoctlGetDeviceStatus or IoctlGetRelatedDevice => (ObjectX64, ObjectX86, StatusReplySize),
                IoctlGetDeviceIdList => (ListX64, ListX86, StatusReplySize),
                IoctlGetRegistryProperty => (RegistryX64, RegistryX86, StatusReplySize),
                IoctlGetObjectProperty => (PropertyX64, PropertyX86, StatusReplySize),
                IoctlOpenDeviceKey => (KeyX64, KeyX86, HandleReplySize),
                _ => (default(Layout), default(Layout), 0),
            };

            Request = Wide ? X64 : X86;
            return ReplySize != 0;
        }

        private static NTSTATUS Handle(uint IOCTL, ref DeviceData Data, BinaryEmulator Instance)
        {
            uint PointerSize = (uint)Instance.WinHelper.PointerSize;
            if (!TryDescribe(IOCTL, PointerSize == 8, out Layout Request, out int ReplySize))
                return Unmodelled(IOCTL, ref Data);

            if (!DeviceNodes.TryWaitForSources(Instance, out NTSTATUS Parked))
                return Refuse(ref Data, Parked);

            ReadOnlySpan<byte> Input = Data.InputBuffer == null ? ReadOnlySpan<byte>.Empty : Data.InputBuffer.AsSpan(0, (int)Math.Min(Data.InputLength, (uint)Data.InputBuffer.Length));
            if (Input.Length != Request.Size || Field(Input, 0) != Request.Size)
                return Refuse(ref Data, NTSTATUS.STATUS_INVALID_PARAMETER);

            NTSTATUS Captured = CaptureString(Instance, Input, Request, PointerSize, out string Name);
            if (Captured != NTSTATUS.STATUS_SUCCESS)
                return Refuse(ref Data, Captured);

            if (Field(Input, Request.Result) != ReplySize || Data.OutputLength < ReplySize)
                return Refuse(ref Data, NTSTATUS.STATUS_INVALID_PARAMETER);

            DeviceNodes Nodes = Instance.WinHelper.DeviceNodes;
            return IOCTL switch
            {
                IoctlLocateDevNode => Locate(ref Data, Instance, Nodes, Input, Request, Name),
                IoctlGetDeviceStatus => Status(ref Data, Nodes, Input, Request, Name),
                IoctlGetRelatedDevice => Related(ref Data, Nodes, Input, Request, Name),
                IoctlGetDeviceIdList => IdList(ref Data, Nodes, Input, Name),
                IoctlGetRegistryProperty => RegistryProperty(ref Data, Nodes, Input, Request, PointerSize, Name),
                IoctlGetObjectProperty => ObjectProperty(ref Data, Nodes, Input, Request, PointerSize, Name),
                _ => OpenKey(ref Data, Instance, Nodes, Input, Request, Name),
            };
        }

        private static uint Field(ReadOnlySpan<byte> Input, int Offset) => BinaryPrimitives.ReadUInt32LittleEndian(Input.Slice(Offset));

        private static bool HasCallerBuffer(ReadOnlySpan<byte> Input, Layout Request, uint PointerSize) =>
            WinSysHelper.ReadPointerField(Input.Slice(Request.CallerBuffer), 0, PointerSize) != 0
            || Field(Input, Request.CallerBuffer + (int)PointerSize) != 0;

        // The byte length counts the NUL, and NT forces the last WCHAR to 0.
        private static NTSTATUS CaptureString(BinaryEmulator Instance, ReadOnlySpan<byte> Input, Layout Request, uint PointerSize, out string Text)
        {
            Text = null;
            ulong Pointer = WinSysHelper.ReadPointerField(Input.Slice(Request.Pointer), 0, PointerSize);
            uint Length = Field(Input, Request.Length);
            if (Pointer == 0)
                return Length == 0 ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;
            if (Length < sizeof(char) || Length > MaxStringBytes)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Bytes = Instance.WinHelper.ReadMemorySpan(Pointer, Length);
            if (Bytes.IsEmpty)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ReadOnlySpan<char> Chars = MemoryMarshal.Cast<byte, char>(Bytes.Slice(0, (int)(Length & ~1u) - sizeof(char)));
            int End = Chars.IndexOf('\0');
            Text = new string(End < 0 ? Chars : Chars.Slice(0, End));
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS Refuse(ref DeviceData Data, NTSTATUS Status)
        {
            Data.OutputBuffer = Array.Empty<byte>();
            Data.Information = 0;
            return Status;
        }

        private static Span<byte> Claim(ref DeviceData Data, int Size)
        {
            if (Data.OutputBuffer == null || Data.OutputBuffer.Length < Size)
                Data.OutputBuffer = new byte[Size];

            Span<byte> Reply = Data.OutputBuffer.AsSpan(0, Size);
            Reply.Clear();
            Data.Information = (ulong)Size;
            return Reply;
        }

        private static Span<byte> BeginReply(ref DeviceData Data, int HeaderSize, NTSTATUS Status, int Size = 0)
        {
            Span<byte> Reply = Claim(ref Data, Math.Max(HeaderSize, Size));
            BinaryPrimitives.WriteUInt32LittleEndian(Reply, (uint)HeaderSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Reply.Slice(ReplyStatusOffset), (uint)Status);
            return Reply;
        }

        private static NTSTATUS Basic(ref DeviceData Data, NTSTATUS Status)
        {
            BeginReply(ref Data, BasicReplySize, Status);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS StatusFailure(ref DeviceData Data, NTSTATUS Status) => DeviceStatus(ref Data, Status, 0, 0);

        private static NTSTATUS DeviceStatus(ref DeviceData Data, NTSTATUS Status, uint Flags, uint Problem)
        {
            Span<byte> Reply = BeginReply(ref Data, StatusReplySize, Status);
            BinaryPrimitives.WriteUInt32LittleEndian(Reply.Slice(8), Flags);
            BinaryPrimitives.WriteUInt32LittleEndian(Reply.Slice(12), Problem);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS BufferFailure(ref DeviceData Data, NTSTATUS Status, uint Required = 0)
        {
            Span<byte> Reply = BeginReply(ref Data, BufferReplySize, Status);
            BinaryPrimitives.WriteUInt32LittleEndian(Reply.Slice(ReplyLengthOffset), Required);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool TryBeginPayload(ref DeviceData Data, uint Type, int Length, NTSTATUS SmallStatus, out Span<byte> Payload)
        {
            Payload = Span<byte>.Empty;
            if ((long)Data.OutputLength - BufferReplySize < Length)
            {
                BufferFailure(ref Data, SmallStatus, (uint)Length);
                return false;
            }

            Span<byte> Reply = BeginReply(ref Data, BufferReplySize, NTSTATUS.STATUS_SUCCESS, BufferReplySize + Length);
            BinaryPrimitives.WriteUInt32LittleEndian(Reply.Slice(ReplyLengthOffset), (uint)Length);
            BinaryPrimitives.WriteUInt32LittleEndian(Reply.Slice(ReplyTypeOffset), Type);
            Payload = Reply.Slice(BufferReplyData, Length);
            return true;
        }

        private static NTSTATUS Buffer(ref DeviceData Data, uint Type, ReadOnlySpan<byte> Bytes)
        {
            if (TryBeginPayload(ref Data, Type, Bytes.Length, NTSTATUS.STATUS_BUFFER_TOO_SMALL, out Span<byte> Payload))
                Bytes.CopyTo(Payload);

            return NTSTATUS.STATUS_SUCCESS;
        }

        // Adds one NUL, so a list passes the terminators of its entries in the text.
        private static NTSTATUS BufferText(ref DeviceData Data, uint Type, ReadOnlySpan<char> Text,
            NTSTATUS SmallStatus = NTSTATUS.STATUS_BUFFER_TOO_SMALL)
        {
            if (TryBeginPayload(ref Data, Type, (Text.Length + 1) * sizeof(char), SmallStatus, out Span<byte> Payload))
                MemoryMarshal.AsBytes(Text).CopyTo(Payload);

            return NTSTATUS.STATUS_SUCCESS;
        }

        // A phantom locate also finds a device that has only its Enum key (PiCMValidateDeviceInstance).
        private static NTSTATUS Locate(ref DeviceData Data, BinaryEmulator Instance, DeviceNodes Nodes, ReadOnlySpan<byte> Input, Layout Request, string Id)
        {
            uint Mode = Field(Input, HeaderFlags);
            if (Id == null || (Mode != LocateNormal && Mode != LocatePhantom) || Field(Input, HeaderObjectType) != ObjectDevice
                || Field(Input, Request.Fields) != 0)
                return Basic(ref Data, NTSTATUS.STATUS_INVALID_PARAMETER);

            if (Nodes.TryFind(Id, out _))
                return Basic(ref Data, NTSTATUS.STATUS_SUCCESS);

            WinRegKey Key = Instance.WinHelper.ResolveRegistryKey(DeviceNodes.EnumKeyPath(Id));
            if (Key == null)
                return Basic(ref Data, NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND);

            if (Mode == LocateNormal || Instance.WinHelper.ReadRegistryDword(Key, "Phantom") != 0)
                return Basic(ref Data, NTSTATUS.STATUS_NO_SUCH_DEVICE);

            return Basic(ref Data, NTSTATUS.STATUS_SUCCESS);
        }

        // The checks and their order follow PiCMGetDeviceStatus.
        private static NTSTATUS Status(ref DeviceData Data, DeviceNodes Nodes, ReadOnlySpan<byte> Input, Layout Request, string Id)
        {
            if (Id == null || Field(Input, HeaderFlags) != 0 || Field(Input, HeaderObjectType) != ObjectDevice || Field(Input, Request.Fields) != 0)
                return StatusFailure(ref Data, NTSTATUS.STATUS_INVALID_PARAMETER);

            return Nodes.TryFind(Id, out DeviceNode Node)
                ? DeviceStatus(ref Data, NTSTATUS.STATUS_SUCCESS, Node.Status, Node.Problem)
                : StatusFailure(ref Data, NTSTATUS.STATUS_NO_SUCH_DEVICE);
        }

        // The checks and their order follow PiCMGetRelatedDeviceInstance.
        private static NTSTATUS Related(ref DeviceData Data, DeviceNodes Nodes, ReadOnlySpan<byte> Input, Layout Request, string Id)
        {
            uint Relation = Field(Input, Request.Fields);
            if (Id == null || Field(Input, HeaderFlags) != 0 || Field(Input, HeaderObjectType) != ObjectDevice)
                return BufferFailure(ref Data, NTSTATUS.STATUS_INVALID_PARAMETER);
            if (!IsValidInstanceId(Id))
                return BufferFailure(ref Data, NTSTATUS.STATUS_OBJECT_NAME_INVALID);
            if (Relation < RelationParent || Relation > RelationSibling)
                return BufferFailure(ref Data, NTSTATUS.STATUS_INVALID_PARAMETER);
            if (!Nodes.TryFind(Id, out DeviceNode Node))
                return BufferFailure(ref Data, NTSTATUS.STATUS_NO_SUCH_DEVICE);

            DeviceNode Target = Relation switch
            {
                RelationParent => Node.Parent,
                RelationChild => Node.Children.Count != 0 ? Node.Children[0] : null,
                _ => NextSibling(Node),
            };
            if (Target == null)
                return BufferFailure(ref Data, NTSTATUS.STATUS_NO_SUCH_DEVICE);

            NTSTATUS Small = Relation != RelationParent && Data.OutputLength == BufferReplySize ? NTSTATUS.STATUS_INVALID_PARAMETER : NTSTATUS.STATUS_BUFFER_TOO_SMALL;
            return BufferText(ref Data, 0, Target.InstanceId, Small);
        }

        private static DeviceNode NextSibling(DeviceNode Node)
        {
            if (Node.Parent == null)
                return null;

            List<DeviceNode> Siblings = Node.Parent.Children;
            int Index = Siblings.IndexOf(Node);
            return Index >= 0 && Index + 1 < Siblings.Count ? Siblings[Index + 1] : null;
        }

        private static bool IsValidInstanceId(string Id)
        {
            if (Id.Length >= MaxDeviceIdLength)
                return false;

            int Parts = 1;
            char Previous = '\\';
            foreach (char Character in Id)
            {
                if (Character < 0x21 || Character > 0x7F || Character == ',')
                    return false;
                if (Character == '\\')
                {
                    if (Previous == '\\')
                        return false;
                    Parts++;
                }
                Previous = Character;
            }

            return Parts == 3 && Previous != '\\';
        }

        // The filter rules follow PiCMGetDeviceIdList and PiCMConvertDeviceListFilters.
        private static NTSTATUS IdList(ref DeviceData Data, DeviceNodes Nodes, ReadOnlySpan<byte> Input, string Filter)
        {
            uint Flags = Field(Input, HeaderFlags);
            uint Kind = Flags & ListFilterMask;
            if ((Flags & ~(ListFilterMask | ListPresentOnly | ListSkipMandatory)) != 0 || (Kind != ListFilterNone && Filter == null))
                return BufferFailure(ref Data, NTSTATUS.STATUS_INVALID_PARAMETER);

            StringBuilder List = new StringBuilder();
            switch (Kind)
            {
                case ListFilterNone:
                    foreach (DeviceNode Node in Nodes.All)
                        List.Append(Node.InstanceId).Append('\0');
                    break;

                case ListFilterEnumerator:
                    {
                        if (Filter.Length == 0 || Filter.AsSpan().Count('\\') > 1)
                            return BufferFailure(ref Data, NTSTATUS.STATUS_INVALID_PARAMETER);

                        foreach (DeviceNode Node in Nodes.All)
                        {
                            string Id = Node.InstanceId;
                            if (Id.Length > Filter.Length && Id[Filter.Length] == '\\' && Id.StartsWith(Filter, StringComparison.OrdinalIgnoreCase))
                                List.Append(Id).Append('\0');
                        }
                        break;
                    }

                case ListFilterClass:
                    {
                        if (!Guid.TryParse(Filter, out Guid Class))
                            return BufferFailure(ref Data, NTSTATUS.STATUS_INVALID_PARAMETER);

                        foreach (DeviceNode Node in Nodes.All)
                        {
                            if (Node.Properties.TryGetValue(DeviceNodes.ClassGuid, out DeviceProperty Value) && new Guid(Value.Data) == Class)
                                List.Append(Node.InstanceId).Append('\0');
                        }
                        break;
                    }

                case ListFilterBus:
                    {
                        if (!Nodes.TryFind(Filter, out DeviceNode Parent))
                            return BufferFailure(ref Data, NTSTATUS.STATUS_NO_SUCH_DEVICE);
                        foreach (DeviceNode Child in Parent.Children)
                            List.Append(Child.InstanceId).Append('\0');
                        break;
                    }

                case ListFilterService:
                case ListFilterEjection:
                case ListFilterRemoval:
                case ListFilterPower:
                case ListFilterTransport:
                    break;

                default:
                    return BufferFailure(ref Data, NTSTATUS.STATUS_INVALID_PARAMETER);
            }

            return BufferText(ref Data, 0, List.ToString());
        }

        // Code is the caller's CM_DRP value (CmGetDeviceRegPropWorker).
        private static NTSTATUS RegistryProperty(ref DeviceData Data, DeviceNodes Nodes, ReadOnlySpan<byte> Input, Layout Request, uint PointerSize,
            string Id)
        {
            uint Code = Field(Input, Request.Fields);
            uint Type = Field(Input, HeaderObjectType);
            if (Id == null || Field(Input, HeaderFlags) != 0 || Field(Input, Request.Fields + sizeof(uint)) != 0
                || HasCallerBuffer(Input, Request, PointerSize)
                || Code == 0 || Code > MaxRegistryProperty || (Type != ObjectDevice && Type != 2))
                return BufferFailure(ref Data, NTSTATUS.STATUS_INVALID_PARAMETER);

            if (Type != ObjectDevice)
                return BufferFailure(ref Data, NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND);
            if (!Nodes.TryFind(Id, out DeviceNode Node))
                return BufferFailure(ref Data, NTSTATUS.STATUS_NO_SUCH_DEVICE);
            if (Code is RegistryUnused0 or RegistryUnused1 or RegistryUnused2 or RegistrySecuritySds)
                return BufferFailure(ref Data, NTSTATUS.STATUS_PROPSET_NOT_FOUND);

            if (Code == DeviceNodes.EnumeratorNameCode)
            {
                int Separator = Node.InstanceId.IndexOf('\\');
                return BufferText(ref Data, WinSysHelper.RegSz, Node.InstanceId.AsSpan(0, Separator < 0 ? Node.InstanceId.Length : Separator));
            }

            if (!DeviceNodes.TryMapRegistryProperty(Code, out DevicePropertyKey Key, out int RegType)
                || !DeviceNodes.TryGetRegistryValue(Node, Key, RegType, out byte[] Value))
                return BufferFailure(ref Data, NTSTATUS.STATUS_NOT_FOUND);

            return Buffer(ref Data, (uint)RegType, Value);
        }

        // Only device objects are modelled (PnpGetObjectPropertyWorker).
        private static NTSTATUS ObjectProperty(ref DeviceData Data, DeviceNodes Nodes, ReadOnlySpan<byte> Input, Layout Request, uint PointerSize,
            string Id)
        {
            uint Type = Field(Input, HeaderObjectType);
            bool KnownType = (Type >= 1 && Type <= 4) || (Type >= 0x10001 && Type <= 0x10005);
            if (Id == null || Field(Input, HeaderFlags) != 0 || Field(Input, Request.Fields + PropertyKeySize) != 0
                || HasCallerBuffer(Input, Request, PointerSize) || !KnownType)
                return BufferFailure(ref Data, NTSTATUS.STATUS_INVALID_PARAMETER);

            if (Type != ObjectDevice)
                return BufferFailure(ref Data, NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND);
            if (!Nodes.TryFind(Id, out DeviceNode Node))
                return BufferFailure(ref Data, NTSTATUS.STATUS_NO_SUCH_DEVICE);

            DevicePropertyKey Key = new DevicePropertyKey(new Guid(Input.Slice(Request.Fields, 16)), Field(Input, Request.Fields + 16));
            if (!Node.Properties.TryGetValue(Key, out DeviceProperty Property))
                return BufferFailure(ref Data, NTSTATUS.STATUS_NOT_FOUND);

            return Buffer(ref Data, Property.Type, Property.Data);
        }

        private static NTSTATUS OpenKey(ref DeviceData Data, BinaryEmulator Instance, DeviceNodes Nodes, ReadOnlySpan<byte> Input, Layout Request, string Id)
        {
            uint KeyType = Field(Input, HeaderFlags);
            uint Access = Field(Input, Request.Fields);
            uint Disposition = Field(Input, Request.Fields + sizeof(uint));
            uint Kind = KeyType & KeyTypeMask;
            if (Id == null || Field(Input, HeaderObjectType) != ObjectDevice
                || Kind < KeyHardware || Kind > KeyLogConf || (KeyType & ~(KeyTypeMask | KeyUser | KeyConfig)) != 0)
                return HandleReply(ref Data, NTSTATUS.STATUS_INVALID_PARAMETER, 0);
            if (!IsValidInstanceId(Id))
                return HandleReply(ref Data, NTSTATUS.STATUS_OBJECT_NAME_INVALID, 0);

            string Path = null;
            if (Nodes.TryFind(Id, out DeviceNode Node) && (KeyType & (KeyUser | KeyConfig)) == 0)
            {
                string EnumKey = DeviceNodes.EnumKeyPath(Node.InstanceId);
                Path = Kind switch
                {
                    KeyHardware => EnumKey + @"\Device Parameters",
                    KeyControl => EnumKey + @"\Control",
                    KeyLogConf => EnumKey + @"\LogConf",
                    _ => Node.Properties.TryGetValue(DeviceNodes.Driver, out DeviceProperty Driver)
                        ? DeviceNodes.ClassKeyPath(Encoding.Unicode.GetString(Driver.Data).TrimEnd('\0'))
                        : null,
                };
            }

            WinHandle Opened = Path != null ? Instance.WinHelper.OpenRegistryKey(Path, (AccessMask)Access) : null;
            if (Opened == null && Path != null && Disposition == DispositionOpenAlways && Instance.WinHelper.CreateRegistryKeyPath(Path, true, out _))
                Opened = Instance.WinHelper.OpenRegistryKey(Path, (AccessMask)Access);
            if (Opened != null)
                return HandleReply(ref Data, NTSTATUS.STATUS_SUCCESS, Opened.Handle);

            if (Disposition == DispositionOpenAlways && Node == null)
                return HandleReply(ref Data, NTSTATUS.STATUS_NO_SUCH_DEVICE, 0);
            return HandleReply(ref Data, NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND, 0);
        }

        private static NTSTATUS HandleReply(ref DeviceData Data, NTSTATUS Status, ulong Handle)
        {
            Span<byte> Reply = BeginReply(ref Data, HandleReplySize, Status);
            BinaryPrimitives.WriteUInt64LittleEndian(Reply.Slice(8), Handle);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS Unmodelled(uint IOCTL, ref DeviceData Data)
        {
            if (Data.OutputLength < BufferReplySize)
                return Refuse(ref Data, NTSTATUS.STATUS_BUFFER_TOO_SMALL);

            Span<byte> Reply = Claim(ref Data, BufferReplySize);

            // cfgmgr32 reads a missing class as an empty interface list only after the sizing call asks for room for
            // its terminator. Otherwise the caller loops forever.
            if (IOCTL == IoctlGetDeviceInterfaceList && Data.OutputLength < BufferReplySize + EmptyInterfaceListBytes)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Reply.Slice(ReplyStatusOffset, 4), (uint)NTSTATUS.STATUS_BUFFER_TOO_SMALL);
                BinaryPrimitives.WriteUInt32LittleEndian(Reply.Slice(ReplyLengthOffset, 4), EmptyInterfaceListBytes);
            }
            else
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Reply.Slice(ReplyStatusOffset, 4), (uint)NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
