using static Brovan.Core.Helpers.BinaryHelpers;
using Brovan.Core.Emulation.OS.Windows.RPC.Ports;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtConnectPort : IWinSyscall
    {
        internal struct PORT_VIEW
        {
            public uint Length;
            public ulong SectionHandle;
            public uint SectionOffset;
            public ulong ViewSize;
            public ulong ViewBase;
            public ulong ViewRemoteBase;

            public static uint SizeOf(bool Is64) => Is64 ? 0x30u : 0x18u;

            public static PORT_VIEW ReadFrom(BinaryEmulator Instance, ulong Address, bool Is64)
            {
                PORT_VIEW View = default;
                View.Length = Instance.ReadMemoryUInt(Address + 0x00);

                if (Is64)
                {
                    View.SectionHandle = Instance.ReadMemoryULong(Address + 0x08);
                    View.SectionOffset = Instance.ReadMemoryUInt(Address + 0x10);
                    View.ViewSize = Instance.ReadMemoryULong(Address + 0x18);
                    View.ViewBase = Instance.ReadMemoryULong(Address + 0x20);
                    View.ViewRemoteBase = Instance.ReadMemoryULong(Address + 0x28);
                    return View;
                }

                View.SectionHandle = Instance.ReadMemoryUInt(Address + 0x04);
                View.SectionOffset = Instance.ReadMemoryUInt(Address + 0x08);
                View.ViewSize = Instance.ReadMemoryUInt(Address + 0x0C);
                View.ViewBase = Instance.ReadMemoryUInt(Address + 0x10);
                View.ViewRemoteBase = Instance.ReadMemoryUInt(Address + 0x14);
                return View;
            }

            // The connect answers with the view fields. Length, SectionHandle and SectionOffset stay as the caller set them.
            public readonly bool WriteResult(BinaryEmulator Instance, ulong Address, bool Is64)
            {
                WinSysHelper Helper = Instance.WinHelper;

                if (Is64)
                {
                    return Helper.WriteUInt64(Address + 0x18, ViewSize)
                        && Helper.WriteUInt64(Address + 0x20, ViewBase)
                        && Helper.WriteUInt64(Address + 0x28, ViewRemoteBase);
                }

                return Helper.WriteUInt32(Address + 0x0C, (uint)ViewSize)
                    && Helper.WriteUInt32(Address + 0x10, (uint)ViewBase)
                    && Helper.WriteUInt32(Address + 0x14, (uint)ViewRemoteBase);
            }
        }

        internal struct REMOTE_PORT_VIEW
        {
            public uint Length;
            public ulong ViewSize;
            public ulong ViewBase;

            public static uint SizeOf(bool Is64) => Is64 ? 0x18u : 0x0Cu;

            public static REMOTE_PORT_VIEW ReadFrom(BinaryEmulator Instance, ulong Address, bool Is64)
            {
                REMOTE_PORT_VIEW View = default;
                View.Length = Instance.ReadMemoryUInt(Address + 0x00);

                if (Is64)
                {
                    View.ViewSize = Instance.ReadMemoryULong(Address + 0x08);
                    View.ViewBase = Instance.ReadMemoryULong(Address + 0x10);
                    return View;
                }

                View.ViewSize = Instance.ReadMemoryUInt(Address + 0x04);
                View.ViewBase = Instance.ReadMemoryUInt(Address + 0x08);
                return View;
            }

            public readonly bool WriteResult(BinaryEmulator Instance, ulong Address, bool Is64)
            {
                WinSysHelper Helper = Instance.WinHelper;

                if (Is64)
                    return Helper.WriteUInt64(Address + 0x08, ViewSize) && Helper.WriteUInt64(Address + 0x10, ViewBase);

                return Helper.WriteUInt32(Address + 0x04, (uint)ViewSize) && Helper.WriteUInt32(Address + 0x08, (uint)ViewBase);
            }
        }

        private const uint SecurityQosSize = 0x0C;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            WinSysHelper Helper = Instance.WinHelper;
            ulong PortHandlePtr = Helper.GetArg(0);
            ulong PortNamePtr = Helper.GetArg(1);
            ulong SecurityQosPtr = Helper.GetArg(2);
            ulong ClientViewPtr = Helper.GetArg(3);
            ulong ServerViewPtr = Helper.GetArg(4);
            ulong MaxMessageLengthPtr = Helper.GetArg(5);
            ulong ConnectionInfoPtr = Helper.GetArg(6);
            ulong ConnectionInfoLengthPtr = Helper.GetArg(7);
            bool Is64 = Helper.PointerSize == 8;

            // NT probes every argument before it looks up the port.
            if (!Instance.IsRegionCommitted(PortHandlePtr, (uint)Helper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint ConnectionInfoLength = 0;
            if (ConnectionInfoLengthPtr != 0)
            {
                if (!Instance.IsRegionCommitted(ConnectionInfoLengthPtr, sizeof(uint)))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                ConnectionInfoLength = Instance.ReadMemoryUInt(ConnectionInfoLengthPtr);
                if (!Instance.IsRegionCommitted(ConnectionInfoPtr, ConnectionInfoLength))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            PORT_VIEW ClientView = default;
            if (ClientViewPtr != 0)
            {
                if (!Instance.IsRegionCommitted(ClientViewPtr, PORT_VIEW.SizeOf(Is64)))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                ClientView = PORT_VIEW.ReadFrom(Instance, ClientViewPtr, Is64);
                NTSTATUS ClientStatus = CheckViewLength(ClientViewPtr, ClientView.Length, PORT_VIEW.SizeOf(false), PORT_VIEW.SizeOf(true), Is64);
                if (ClientStatus != NTSTATUS.STATUS_SUCCESS)
                    return ClientStatus;
            }

            REMOTE_PORT_VIEW ServerView = default;
            if (ServerViewPtr != 0)
            {
                if (!Instance.IsRegionCommitted(ServerViewPtr, REMOTE_PORT_VIEW.SizeOf(Is64)))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                ServerView = REMOTE_PORT_VIEW.ReadFrom(Instance, ServerViewPtr, Is64);
                NTSTATUS ServerStatus = CheckViewLength(ServerViewPtr, ServerView.Length, REMOTE_PORT_VIEW.SizeOf(false), REMOTE_PORT_VIEW.SizeOf(true), Is64);
                if (ServerStatus != NTSTATUS.STATUS_SUCCESS)
                    return ServerStatus;
            }

            if (MaxMessageLengthPtr != 0 && !Instance.IsRegionCommitted(MaxMessageLengthPtr, sizeof(uint)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (SecurityQosPtr != 0 && !Instance.IsRegionCommitted(SecurityQosPtr, SecurityQosSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (PortNamePtr == 0)
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            if (!Helper.TryReadUnicodeString(PortNamePtr, out string PortName, out NTSTATUS PortNameStatus))
                return PortNameStatus;

            if (string.IsNullOrEmpty(PortName))
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            WinSection PortSection = null;
            if (ClientViewPtr != 0)
            {
                PortSection = Helper.GetSectionByHandle(ClientView.SectionHandle, AccessMask.GiveTemp);
                if (PortSection == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;
            }

            ulong ViewBase = 0;
            ulong ViewSize = 0;
            if (PortSection != null)
            {
                ViewSize = ClientView.ViewSize;
                if (ViewSize == 0 || ViewSize > PortSection.Size)
                    ViewSize = PortSection.Size;

                ViewSize = BinaryEmulator.AlignUp(ViewSize, 0x1000);

                // Brovan is the server, so both ends share the client's view.
                uint ViewProtect = (uint)Helper.ConvertInternalToWinProtect(MemoryProtection.ReadWrite);
                NTSTATUS ViewStatus = NtMapViewOfSection.MapDataView(Instance, PortSection, 0, ViewSize, 0, ViewProtect, out ViewBase);
                if (ViewStatus != NTSTATUS.STATUS_SUCCESS)
                    return ViewStatus;
            }

            WinPort Port = FindPortByName(Instance, PortName);
            if (Port == null)
            {
                Port = new WinPort
                {
                    Name = PortName,
                    Handler = CsrssPortHandler.Handle
                };

                Helper.WinPorts.Add(Port);
            }
            else if (Port.Handler == null)
            {
                Port.Handler = CsrssPortHandler.Handle;
            }

            WinHandle Handle = Helper.HandleManager.AddHandle(Port, AccessMask.StandardRightsAll);
            Helper.AddWinHandle(Handle);

            bool Written = Helper.WritePointer(PortHandlePtr, Handle.Handle);

            if (Written && PortSection != null)
            {
                ClientView.ViewSize = ViewSize;
                ClientView.ViewBase = ViewBase;
                ClientView.ViewRemoteBase = ViewBase;
                Written = ClientView.WriteResult(Instance, ClientViewPtr, Is64);

                if (Written && ServerViewPtr != 0)
                {
                    ServerView.ViewSize = ViewSize;
                    ServerView.ViewBase = ViewBase;
                    Written = ServerView.WriteResult(Instance, ServerViewPtr, Is64);
                }
            }

            if (Written && MaxMessageLengthPtr != 0)
                Written = Helper.WriteUInt32(MaxMessageLengthPtr, 0x148u);

            if (Written && ConnectionInfoLengthPtr != 0)
            {
                if (ConnectionInfoPtr != 0 && ConnectionInfoLength >= 0x20)
                {
                    WinSection SharedSection = FindSectionByName(Instance, "\\Windows\\SharedSection");
                    if (SharedSection != null)
                    {
                        ulong SharedBase = SharedSection.BackingAddress;

                        Written = Instance._emulator.WriteMemory(ConnectionInfoPtr + 0x00, SharedBase, 8) && Instance._emulator.WriteMemory(ConnectionInfoPtr + 0x08, SharedBase + 0x10, 8) && Instance._emulator.WriteMemory(ConnectionInfoPtr + 0x10, 4UL, 8);
                    }
                }

                Written = Written && Helper.WriteUInt32(ConnectionInfoLengthPtr, ConnectionInfoLength);
            }

            if (!Written)
            {
                Helper.CloseHandle(Handle.Handle);
                if (ViewBase != 0)
                    Helper.UnmapViewOfSection(ViewBase);

                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtConnectPort: Port=\"{PortName}\", Handle=0x{Handle.Handle:X}", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: WOW64 also accepts the x64 length and skips the alignment check.
        private static NTSTATUS CheckViewLength(ulong Address, uint Length, uint Size32, uint Size64, bool Is64)
        {
            if (Length != Size64 && (Is64 || Length != Size32))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Is64 && (Address & 3) != 0)
                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static WinPort FindPortByName(BinaryEmulator Instance, string Name)
        {
            foreach (WinPort Port in Instance.WinHelper.WinPorts)
            {
                if (string.Equals(Port.Name, Name, StringComparison.OrdinalIgnoreCase))
                    return Port;
            }

            return null;
        }

        private static WinSection FindSectionByName(BinaryEmulator Instance, string Name)
        {
            foreach (WinSection s in Instance.WinHelper.WinSections)
            {
                if (string.Equals(s.Name, Name, StringComparison.OrdinalIgnoreCase))
                    return s;

                if (string.Equals(Name, "\\Windows\\SharedSection", StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrEmpty(s.Name) &&
                    s.Name.EndsWith("\\Windows\\SharedSection", StringComparison.OrdinalIgnoreCase))
                    return s;
            }

            return null;
        }
    }
}