using static Brovan.Core.Helpers.BinaryHelpers;
using System.Runtime.InteropServices;
using System.Text;
using Brovan.Core.Emulation.OS.Windows.RPC.Ports;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtConnectPort : IWinSyscall
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct PORT_VIEW64
        {
            public uint Length;
            public uint Padding0;
            public ulong SectionHandle;
            public uint SectionOffset;
            public uint Padding1;
            public ulong ViewSize;
            public ulong ViewBase;
            public ulong ViewRemoteBase;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct REMOTE_PORT_VIEW64
        {
            public uint Length;
            public uint Padding0;
            public ulong ViewSize;
            public ulong ViewBase;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong PortHandlePtr = Instance.WinHelper.GetArg64(0);
            ulong PortNamePtr = Instance.WinHelper.GetArg64(1);
            ulong SecurityQosPtr = Instance.WinHelper.GetArg64(2);
            ulong ClientViewPtr = Instance.WinHelper.GetArg64(3);
            ulong ServerViewPtr = Instance.WinHelper.GetArg64(4);
            ulong MaxMessageLengthPtr = Instance.WinHelper.GetArg64(5);
            ulong ConnectionInfoPtr = Instance.WinHelper.GetArg64(6);
            ulong ConnectionInfoLengthPtr = Instance.WinHelper.GetArg64(7);

            if (PortHandlePtr == 0 || PortNamePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(PortHandlePtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!StructSerializer.ParseStruct(Instance, PortNamePtr, out UNICODE_STRING64 PortNameStruct))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            string PortName = ReadUnicodeString(Instance, PortNameStruct);
            if (string.IsNullOrEmpty(PortName))
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            PortName = PortName.TrimEnd('\0');

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

            Instance.WinHelper.WinHandles.Add(Handle);

            if (!Instance._emulator.WriteMemory(PortHandlePtr, (ulong)Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (ClientViewPtr != 0)
            {
                if (!Instance.IsRegionMapped(ClientViewPtr, 0x30))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (!StructSerializer.ParseStruct(Instance, ClientViewPtr, out PORT_VIEW64 ClientView))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (ClientView.Length < 0x30)
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

                if (StructSerializer.WriteStruct(Instance, ClientViewPtr, ClientView) != WriteStructResult.Ok)
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (ServerViewPtr != 0)
                {
                    if (!Instance.IsRegionMapped(ServerViewPtr, 0x18))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!StructSerializer.ParseStruct(Instance, ServerViewPtr, out REMOTE_PORT_VIEW64 ServerView))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    if (ServerView.Length < 0x18)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    ServerView.ViewSize = ViewSize;
                    ServerView.ViewBase = ClientView.ViewRemoteBase;

                    if (StructSerializer.WriteStruct(Instance, ServerViewPtr, ServerView) != WriteStructResult.Ok)
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

        private static string ReadUnicodeString(BinaryEmulator Instance, UNICODE_STRING64 UnicodeString)
        {
            if (UnicodeString.Length == 0 || UnicodeString.Buffer == 0)
                return null;

            if ((UnicodeString.Length & 1) != 0)
                return null;

            if (!Instance.IsRegionMapped(UnicodeString.Buffer, UnicodeString.Length))
                return null;

            return Instance._emulator.ReadMemoryString(UnicodeString.Buffer, UnicodeString.Length, Encoding.Unicode);
        }
    }
}