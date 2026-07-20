using System.Linq;
using System.Text;
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

            if (!StructSerializer.ParseStruct(Instance, PortNamePtr, out UNICODE_STRING64 PortNameStruct))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (PortNameStruct.Length == 0 || PortNameStruct.Buffer == 0)
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            if (!Instance.IsRegionMapped(PortNameStruct.Buffer, PortNameStruct.Length))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            string PortName = Instance._emulator.ReadMemoryString(PortNameStruct.Buffer, PortNameStruct.Length, Encoding.Unicode)?.TrimEnd('\0');

            if (string.IsNullOrEmpty(PortName))
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            // Find existing port or create a new one with the CSRSS handler.
            WinPort Port = Instance.WinHelper.WinPorts
                .FirstOrDefault(p => string.Equals(p.Name, PortName,
                    StringComparison.OrdinalIgnoreCase));

            if (Port == null)
            {
                Port = new WinPort
                {
                    Name = PortName,
                    Handler = CsrssPortHandler.Handle
                };
                Instance.WinHelper.WinPorts.Add(Port);
            }

            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(
                Port, AccessMask.StandardRightsAll);
            Instance.WinHelper.AddWinHandle(Handle);

            if (!Instance._emulator.WriteMemory(PortHandlePtr, (ulong)Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            // Ensure the SharedSection is initialised so callers that read
            // PEB->ReadOnlySharedMemoryBase immediately after connecting succeed.
            foreach (WinSection Sec in Instance.WinHelper.WinSections)
            {
                if (Sec == null || Sec.Initialized) continue;
                if (string.Equals(Sec.Name, "\\Windows\\SharedSection",
                        StringComparison.OrdinalIgnoreCase) ||
                    (!string.IsNullOrEmpty(Sec.Name) &&
                      Sec.Name.EndsWith("\\Windows\\SharedSection",
                          StringComparison.OrdinalIgnoreCase)))
                {
                    CsrssPortHandler.EnsureSharedSectionInitialized(Instance, Sec.BackingAddress);
                }
            }

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage(
                $"[+] NtAlpcConnectPort: Port=\"{PortName}\", Handle=0x{Handle.Handle:X}",
                LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}