using System;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Shell
{
    internal sealed class ApplicationActivationBroker : HostObject
    {
        internal static readonly Guid Interface = new Guid("d98fd14a-522a-4d59-b875-811e83919a9e");

        private const uint ProcGetViewActivationResult = 5;
        private const uint ElementNotFound = 0x80070490;
        private const uint HostIdNotFound = 0xD0000225;
        private const int ViewActivationResultSize = 28;

        internal override bool Supports(Guid Iid) => Iid == Orpc.IUnknownId || Iid == Interface;

        internal override bool TryCall(HostCall Call, Guid Iid, uint ProcNumber, ReadOnlySpan<byte> Parameters, out byte[] Stub)
        {
            Stub = null;
            if (Iid != Interface || ProcNumber != ProcGetViewActivationResult)
                return false;

            Stub = GetViewActivationResult(Call, Parameters);
            return true;
        }

        // The activation result stays zero, as Brovan's shell places the view at once.
        private byte[] GetViewActivationResult(HostCall Call, ReadOnlySpan<byte> Parameters)
        {
            Ndr20Reader Reader = new Ndr20Reader(Parameters);
            if (!Reader.TryReadUInt64(out ulong ActivationId))
                return null;

            ulong HostId = Call.Instance.WindowsGuest?.PackageIdentity?.HostId ?? 0;
            PendingViewActivation View = Call.Instance.WinHelper.ShellRegistrar.FindPendingView(ActivationId, HostId);

            Ndr20Writer Writer = new Ndr20Writer(0x200);
            Orpc.WriteResponseHeader(ref Writer);
            Writer.AlignTo(8);
            Writer.WriteZeros(ViewActivationResultSize);
            uint Written = WriteOutInterface(ref Writer, Call, View?.WindowFactory, Orpc.IInspectableId);
            uint Result = HostId == 0 ? HostIdNotFound : View == null ? ElementNotFound : Written;

            Writer.AlignTo(4);
            Writer.WriteUInt32(Result);
            return Writer.ToArray();
        }
    }
}
