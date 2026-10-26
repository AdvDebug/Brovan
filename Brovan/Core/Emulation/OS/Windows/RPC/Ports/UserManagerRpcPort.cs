using System;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Ports
{
    internal static class UserManagerRpcPortHandler
    {
        private static readonly Guid UserMarshalData = new Guid("0d3c7f20-1c8d-4654-a1b3-51563b298bda");

        internal static readonly EndpointMapper.RpcInterface Interface = new EndpointMapper.RpcInterface(UserMarshalData, 1, 0);
        private static readonly Guid[] InterfaceIds = { UserMarshalData };

        private const uint ProcGetUserMarshalData = 0;

        public static NTSTATUS Handle(WinPort Port, byte[] SendData, PortReply Reply, BinaryEmulator Instance)
        {
            if (!LrpcPacket.TryParse(SendData, out LrpcMessage Message))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            switch (Message.Type)
            {
                case LrpcMessageType.Bind:
                    if (!LrpcBindings.TryAccept(Reply.Client.Bindings, Message, InterfaceIds, out _, out Reply.Data))
                        Reply.Data = LrpcPacket.BuildFault(Message, LrpcPacket.RpcSUnknownIf);
                    break;

                case LrpcMessageType.Request:
                    Reply.Data = HandleRequest(Port, Message, Reply.Client.Bindings, Instance);
                    break;
            }

            Reply.Data ??= LrpcPacket.EchoHeader(SendData);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static byte[] HandleRequest(WinPort Port, in LrpcMessage Message, LrpcBindingTable Bindings, BinaryEmulator Instance)
        {
            if (!LrpcBindings.TryResolve(Bindings, Message, out Guid Interface, out _))
                return LrpcPacket.BuildFault(Message, LrpcPacket.RpcSUnknownIf);

            if (Interface == UserMarshalData && Message.ProcNumber == ProcGetUserMarshalData)
                return GetUserMarshalData(Message, Instance);

            if ((Instance.Settings.Flags & LogFlags.General) != 0)
                Instance.TriggerEventMessage($"[!] No server for proc {Message.ProcNumber} of {Interface} on \"{Port?.Name}\"; faulting.", LogFlags.General);
            return LrpcPacket.BuildFault(Message, LrpcPacket.RpcSProcnumOutOfRange);
        }

        // USER_DATA is a unique pointer, allocated whole, to two unique strings: NonRoamableId and AccountName.
        private static byte[] GetUserMarshalData(in LrpcMessage Message, BinaryEmulator Instance)
        {
            Ndr20Reader Reader = new Ndr20Reader(Message.StubData);
            if (!Reader.TryReadUInt32(out uint MarshalId))
                return LrpcPacket.BuildFault(Message, LrpcPacket.RpcXBadStubData);

            uint Result = Instance.WinHelper.UserManager.GetUserData(Instance, MarshalId, out string NonRoamableId, out string AccountName);
            Ndr20Writer Writer = new Ndr20Writer(0x80);
            if (Result != Orpc.SOk)
            {
                Writer.WriteUInt32(0);
            }
            else
            {
                Writer.WriteUniqueReferent();
                Writer.WriteUniqueReferent();
                Writer.WriteUniqueReferent();
                Writer.WriteConformantWideString(NonRoamableId);
                Writer.WriteConformantWideString(AccountName);
            }

            Writer.WriteUInt32(Result);
            return LrpcPacket.BuildResponse(Message, Writer.Written);
        }
    }
}
