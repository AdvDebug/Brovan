using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAlpcSetInformation : IWinSyscall
    {
        private const int AssociateCompletionPortSize = 16;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong PortHandle = Instance.WinHelper.GetArg(0);
            uint InformationClass = (uint)Instance.WinHelper.GetArg(1);
            ulong InformationPtr = Instance.WinHelper.GetArg(2);
            uint Length = (uint)Instance.WinHelper.GetArg(3);

            WinPort Port = Instance.WinHelper.HandleManager.GetObjectByHandle<WinPort>(PortHandle);
            if (Port == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (!Port.IsServer)
                return NTSTATUS.STATUS_NOT_SUPPORTED;

            if (InformationPtr != 0 && Length != 0 && !Instance.IsRegionMapped(InformationPtr, Length))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!AlpcMessaging.Supported(Instance))
                return NTSTATUS.STATUS_SUCCESS;

            if (InformationClass == NtAlpcQueryInformation.AlpcRegisterCompletionListInformation)
            {
                Brovan.Core.Helpers.Utils.LogError($"[-] ALPC: \"{Port.Name}\" asks for a completion list, which ports of this process do not fill.");
                return NTSTATUS.STATUS_NOT_SUPPORTED;
            }

            // The other classes tune queues that Brovan does not have.
            if (InformationClass != NtAlpcQueryInformation.AlpcAssociateCompletionPortInformation)
                return NTSTATUS.STATUS_SUCCESS;

            if (Length < AssociateCompletionPortSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            Span<byte> Association = stackalloc byte[AssociateCompletionPortSize];
            if (!Instance.ReadMemory(InformationPtr, Association))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return AlpcMessaging.AssociateCompletionPort(Instance, Port, BinaryPrimitives.ReadUInt64LittleEndian(Association), BinaryPrimitives.ReadUInt64LittleEndian(Association.Slice(8)));
        }
    }
}
