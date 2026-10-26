using System;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Shell
{
    // Brovan's shell shows every view with the default presenter.
    internal sealed class PresenterBroker : HostObject
    {
        internal static readonly Guid Interface = new Guid("4d79a826-bc52-4374-9fa2-5c9a5a684432");

        private const uint ProcGetAppliedPresenter = 8;
        private const uint DefaultPresenter = 0;

        internal override bool Supports(Guid Iid) => Iid == Orpc.IUnknownId || Iid == Orpc.IInspectableId || Iid == Interface;

        internal override bool TryCall(HostCall Call, Guid Iid, uint ProcNumber, ReadOnlySpan<byte> Parameters, out byte[] Stub)
        {
            Stub = null;
            if (Iid != Interface || ProcNumber != ProcGetAppliedPresenter)
                return false;

            Stub = GetAppliedPresenter(Call, Parameters);
            return true;
        }

        // NT: the kind is written also when the window is not found.
        private static byte[] GetAppliedPresenter(HostCall Call, ReadOnlySpan<byte> Parameters)
        {
            Ndr20Reader Reader = new Ndr20Reader(Parameters);
            if (!Reader.TryReadUInt32(out uint WindowId))
                return null;

            bool Found = Call.Instance.WinHelper.ShellNavigation?.HasWindow(WindowId) == true;

            Ndr20Writer Writer = new Ndr20Writer(0x40);
            Orpc.WriteResponseHeader(ref Writer);
            Writer.WriteUInt32(DefaultPresenter);
            Writer.WriteUInt32(Found ? Orpc.SOk : Orpc.EElementNotFound);
            return Writer.ToArray();
        }
    }
}
