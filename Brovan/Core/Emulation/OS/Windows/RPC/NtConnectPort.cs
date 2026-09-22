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

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong PortHandlePtr = Instance.WinHelper.GetArg(0);
            ulong PortNamePtr = Instance.WinHelper.GetArg(1);
            ulong SecurityQosPtr = Instance.WinHelper.GetArg(2);
            ulong ClientViewPtr = Instance.WinHelper.GetArg(3);
            ulong ServerViewPtr = Instance.WinHelper.GetArg(4);
            ulong MaxMessageLengthPtr = Instance.WinHelper.GetArg(5);
            ulong ConnectionInfoPtr = Instance.WinHelper.GetArg(6);
            ulong ConnectionInfoLengthPtr = Instance.WinHelper.GetArg(7);

            if (PortHandlePtr == 0 || PortNamePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(PortHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadUnicodeString(PortNamePtr, out string PortName, out NTSTATUS PortNameStatus))
                return PortNameStatus;

            if (string.IsNullOrEmpty(PortName))
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            WinPort ExistingPort = FindPortByName(Instance, PortName);
            WinHandle Handle;

            if (ExistingPort != null)
            {
                Handle = Instance.WinHelper.HandleManager.AddHandle(
                    ExistingPort,
                    AccessMask.StandardRightsAll
                );
            }
            else
            {
                WinPort Port = new WinPort
                {
                    Name = PortName,
                    Handler = CsrssPortHandler.Handle
                };

                Instance.WinHelper.WinPorts.Add(Port);

                Handle = Instance.WinHelper.HandleManager.AddHandle(Port, AccessMask.StandardRightsAll);
            }

            if (ExistingPort != null && ExistingPort.Handler == null)
                ExistingPort.Handler = CsrssPortHandler.Handle;

            Instance.WinHelper.AddWinHandle(Handle);

            if (!Instance.WinHelper.WritePointer(PortHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (ClientViewPtr != 0)
            {
                bool Is64 = Instance.WinHelper.PointerSize == 8;
                uint ClientViewSize = PORT_VIEW.SizeOf(Is64);

                if (!Instance.IsRegionMapped(ClientViewPtr, ClientViewSize))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                PORT_VIEW ClientView = PORT_VIEW.ReadFrom(Instance, ClientViewPtr, Is64);

                if (ClientView.Length < ClientViewSize)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                WinSection PortSection = Instance.WinHelper.GetSectionByHandle(ClientView.SectionHandle, AccessMask.GiveTemp);
                if (PortSection == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                ulong ViewSize = ClientView.ViewSize;
                if (ViewSize == 0 || ViewSize > PortSection.Size)
                    ViewSize = PortSection.Size;

                ClientView.ViewSize = ViewSize;
                ClientView.ViewBase = PortSection.BackingAddress;
                ClientView.ViewRemoteBase = PortSection.BackingAddress;

                if (!ClientView.WriteResult(Instance, ClientViewPtr, Is64))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                // CsrClientConnectToServer closes the section handle as soon as the connect returns and
                // keeps using this view, so the port view has to hold the section alive on its own.
                PortSection.MappedViewCount++;

                if (ServerViewPtr != 0)
                {
                    uint ServerViewSize = REMOTE_PORT_VIEW.SizeOf(Is64);

                    if (!Instance.IsRegionMapped(ServerViewPtr, ServerViewSize))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    REMOTE_PORT_VIEW ServerView = REMOTE_PORT_VIEW.ReadFrom(Instance, ServerViewPtr, Is64);

                    if (ServerView.Length < ServerViewSize)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    ServerView.ViewSize = ViewSize;
                    ServerView.ViewBase = ClientView.ViewRemoteBase;

                    if (!ServerView.WriteResult(Instance, ServerViewPtr, Is64))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }
            }

            if (MaxMessageLengthPtr != 0 && Instance.IsRegionMapped(MaxMessageLengthPtr, 4))
                Instance._emulator.WriteMemory(MaxMessageLengthPtr, 0x148u);

            if (ConnectionInfoLengthPtr != 0 && Instance.IsRegionMapped(ConnectionInfoLengthPtr, 4))
            {
                uint Requested = Instance._emulator.ReadMemoryUInt(ConnectionInfoLengthPtr);

                if (ConnectionInfoPtr != 0 && Requested >= 0x20 && Instance.IsRegionMapped(ConnectionInfoPtr, Requested))
                {
                    WinSection SharedSection = FindSectionByName(Instance, "\\Windows\\SharedSection");
                    if (SharedSection != null)
                    {
                        ulong SharedBase = SharedSection.BackingAddress;
                        ulong StaticPtr = SharedBase + 0x10;

                        bool ok = Instance._emulator.WriteMemory(ConnectionInfoPtr + 0x00, SharedBase, 8) && Instance._emulator.WriteMemory(ConnectionInfoPtr + 0x08, SharedBase + 0x10, 8) && Instance._emulator.WriteMemory(ConnectionInfoPtr + 0x10, 4UL, 8);

                        if (!ok)
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }
                }

                Instance._emulator.WriteMemory(ConnectionInfoLengthPtr, Requested, 4);
            }

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtConnectPort: Port=\"{PortName}\", Handle=0x{Handle.Handle:X}", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static WinPort FindPortByName(BinaryEmulator Instance, string Name)
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