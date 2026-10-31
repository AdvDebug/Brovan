using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class Wow64BasepCreateActCtx : IWinSyscall
    {
        // x86 BASE_SXS_CREATE_ACTIVATION_CONTEXT_MSG.
        private const int OffArchitecture = 0x04;
        private const int OffManifestHandleType = 0x12;
        private const int OffManifestFileHandle = 0x1C;
        private const int OffManifestHandle = 0x20;
        private const int OffManifestOffset = 0x28;
        private const int OffManifestSize = 0x30;
        private const int OffOutputPointer = 0x7C;
        private const int MessageSize = 0x80;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Message = Instance.WinHelper.GetArg(0);

            Span<byte> Fields = stackalloc byte[MessageSize];
            if (Message == 0 || !Instance.ReadMemory(Message, Fields))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            WinSxS.ActivationContextRequest Request = new WinSxS.ActivationContextRequest(
                Fields[OffManifestHandleType],
                BinaryPrimitives.ReadUInt32LittleEndian(Fields.Slice(OffManifestFileHandle)),
                BinaryPrimitives.ReadUInt32LittleEndian(Fields.Slice(OffManifestHandle)),
                BinaryPrimitives.ReadUInt64LittleEndian(Fields.Slice(OffManifestOffset)),
                BinaryPrimitives.ReadUInt32LittleEndian(Fields.Slice(OffManifestSize)),
                BinaryPrimitives.ReadUInt16LittleEndian(Fields.Slice(OffArchitecture)),
                BinaryPrimitives.ReadUInt32LittleEndian(Fields.Slice(OffOutputPointer)));

            return WinSxS.CreateActivationContext(Instance, Request, out _);
        }
    }
}
