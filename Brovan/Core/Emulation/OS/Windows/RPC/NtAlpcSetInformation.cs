using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;
using Brovan.Core.Emulation.OS.Windows.RPC.Ports;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAlpcSetInformation : IWinSyscall
    {
        private const int AssociateCompletionPortSize = 16;
        private const int AssociateCompletionPortSize32 = 8;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong PortHandle = Instance.WinHelper.GetArg(0);
            uint InformationClass = (uint)Instance.WinHelper.GetArg(1);
            ulong InformationPtr = Instance.WinHelper.GetArg(2);
            uint Length = (uint)Instance.WinHelper.GetArg(3);
            bool Wide = Instance.WinHelper.PointerSize == 8;

            // WOW64 checks the x86 association length before the kernel sees the call.
            if (!Wide && InformationClass == NtAlpcQueryInformation.AlpcAssociateCompletionPortInformation && Length < AssociateCompletionPortSize32)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.WinHelper.HandleManager.TryGetHandle(PortHandle, out ulong PortKey, out HandleEntry PortEntry) || PortEntry.Object is not WinPort Port)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            bool ClientAssociation = InformationClass == NtAlpcQueryInformation.AlpcAssociateCompletionPortInformation
                && (AlpcMessaging.QueuesAnswers(Port) || CsrssPortHandler.QueuesAnswers(Port));
            if (!Port.IsServer && !ClientAssociation)
                return NTSTATUS.STATUS_NOT_SUPPORTED;

            if (InformationPtr != 0 && Length != 0 && !Instance.IsRegionMapped(InformationPtr, Length))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Wide && Port.Handler != null)
            {
                Brovan.Core.Helpers.Utils.LogError($"[-] ALPC: \"{Port.Name}\" answers after the syscall to x64 guests only, so an STA call to it fails.");
                return NTSTATUS.STATUS_NOT_SUPPORTED;
            }

            if (InformationClass == NtAlpcQueryInformation.AlpcRegisterCompletionListInformation)
            {
                Brovan.Core.Helpers.Utils.LogError($"[-] ALPC: \"{Port.Name}\" asks for a completion list, which ports of this process do not fill.");
                return NTSTATUS.STATUS_NOT_SUPPORTED;
            }

            // The other classes tune queues that Brovan does not have.
            if (InformationClass != NtAlpcQueryInformation.AlpcAssociateCompletionPortInformation)
                return NTSTATUS.STATUS_SUCCESS;

            if (Wide && Length < AssociateCompletionPortSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            Span<byte> Association = stackalloc byte[AssociateCompletionPortSize];
            Association = Association.Slice(0, Wide ? AssociateCompletionPortSize : AssociateCompletionPortSize32);
            if (!Instance.ReadMemory(InformationPtr, Association))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            // WOW64 zero-extends the x86 key and sign-extends the handle.
            ulong CompletionKey = Wide ? BinaryPrimitives.ReadUInt64LittleEndian(Association) : BinaryPrimitives.ReadUInt32LittleEndian(Association);
            ulong CompletionHandle = Wide
                ? BinaryPrimitives.ReadUInt64LittleEndian(Association.Slice(8))
                : (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(Association.Slice(4));
            return Port.Handler != null
                ? AlpcMessaging.AssociateCompletionPort(Instance, AlpcMessaging.EnsureServedQueue(Port, PortKey), CompletionKey, CompletionHandle)
                : AlpcMessaging.AssociateCompletionPort(Instance, Port, CompletionKey, CompletionHandle);
        }
    }
}
