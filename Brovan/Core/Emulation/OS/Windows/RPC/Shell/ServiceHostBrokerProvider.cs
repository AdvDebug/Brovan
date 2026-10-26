using System;
using System.Collections.Generic;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Shell
{
    internal sealed class ServiceHostBrokerProvider : HostObject
    {
        internal static readonly Guid Class = new Guid("3480a401-bde9-4407-bc02-798a866ac051");
        private static readonly Guid ProviderInterface = new Guid("0f4accb1-d8f9-4011-ba37-2557925a78cf");

        private const uint ProcGetBroker = 3;
        private static readonly Dictionary<Guid, Func<HostObject>> Services = new Dictionary<Guid, Func<HostObject>>
        {
            [ApplicationActivationBroker.Interface] = () => new ApplicationActivationBroker(),
            [PresenterBroker.Interface] = () => new PresenterBroker(),
        };

        internal override bool Permanent => true;

        internal override bool Supports(Guid Interface) => Interface == Orpc.IUnknownId || Interface == ProviderInterface;

        internal override bool TryCall(HostCall Call, Guid Interface, uint ProcNumber, ReadOnlySpan<byte> Parameters, out byte[] Stub)
        {
            Stub = null;
            if (Interface != ProviderInterface || ProcNumber != ProcGetBroker)
                return false;

            Stub = GetBroker(Call, Parameters);
            return true;
        }

        // NT answers E_NOTIMPL, not E_NOINTERFACE, when no provider has the service (CServiceHost::GetBroker).
        private byte[] GetBroker(HostCall Call, ReadOnlySpan<byte> Parameters)
        {
            Ndr20Reader Reader = new Ndr20Reader(Parameters);
            if (!Reader.TryReadGuid(out Guid Service) || !Reader.TryReadGuid(out Guid Interface))
                return null;

            HostObject Broker = null;
            if (Services.TryGetValue(Service, out Func<HostObject> Create))
            {
                Broker = Create();
                if (!Broker.Supports(Interface))
                    Broker = null;
            }

            Ndr20Writer Writer = new Ndr20Writer(0x100);
            Orpc.WriteResponseHeader(ref Writer);
            uint Written = WriteOutInterface(ref Writer, Call, Broker, Interface);
            uint Result = Broker == null ? Orpc.ENotImpl : Written;

            Writer.AlignTo(4);
            Writer.WriteUInt32(Result);
            return Writer.ToArray();
        }
    }
}
