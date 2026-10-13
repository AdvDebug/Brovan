using static Brovan.Core.Helpers.BinaryHelpers;
using Brovan.Core.Emulation.OS.Windows.RPC.Ports;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAlpcConnectPort : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong PortHandlePtr = Instance.WinHelper.GetArg(0);
            ulong PortNamePtr = Instance.WinHelper.GetArg(1);

            if (PortHandlePtr == 0 || PortNamePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(PortHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadUnicodeString(PortNamePtr, out string PortName, out NTSTATUS PortNameStatus))
                return PortNameStatus;

            if (string.IsNullOrEmpty(PortName))
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            WinPort Port = NtConnectPort.FindPortForOpen(Instance, PortName);
            if (Port == null)
            {
                Port = new WinPort
                {
                    Name = PortName,
                    Handler = CsrssPortHandler.Handle
                };
                Instance.WinHelper.WinPorts.Add(Port);
            }

            return Connect(Instance, PortHandlePtr, Port);
        }

        // NtAlpcConnectPort and NtAlpcConnectPortEx both pass ConnectionMessage, BufferLength and Timeout in slots 6, 7 and 10.
        internal static NTSTATUS Connect(BinaryEmulator Instance, ulong PortHandlePtr, WinPort Port)
        {
            if (Port.Queue != null)
                return AlpcMessaging.ConnectGuest(Instance, Port, PortHandlePtr, Instance.WinHelper.GetArg(6), Instance.WinHelper.GetArg(7), Instance.WinHelper.GetArg(10));

            WinHandle Handle = Instance.WinHelper.OpenObjectHandle(Port, AccessMask.StandardRightsAll);

            if (!Instance.WinHelper.WritePointer(PortHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            // Ensure the SharedSection is initialised so callers that read
            // PEB->ReadOnlySharedMemoryBase immediately after connecting succeed.
            WinSection SharedSection = NtMapViewOfSection.FindSharedSection(Instance);
            if (SharedSection != null)
                NtMapViewOfSection.EnsureSharedSectionInitialized(Instance, SharedSection);

            if ((Instance.Settings.Flags & LogFlags.General) != 0)
                Instance.TriggerEventMessage(
                $"[+] ALPC connect \"{Port.Name}\" Handle=0x{Handle.Handle:X}",
                LogFlags.General);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}