using System;

namespace Brovan.Core.Emulation.OS.Windows.RPC.UserManager
{
    internal sealed class UserManagerStatics : HostObject
    {
        private static readonly Guid SignInStateManager = new Guid("100eb64b-b24c-4c38-8964-720d926d05a4");

        // The interfaces of the native factory's GetIids.
        private static readonly Guid[] Interfaces =
        {
            Orpc.IUnknownId,
            Orpc.IInspectableId,
            new Guid("00000035-0000-0000-c000-000000000046"),
            new Guid("252e7f79-acfa-4ea2-9a7e-fa27a8a4d3d9"),
            new Guid("039a83e3-d5bd-491a-9e47-3feba3427a92"),
            new Guid("1292a652-a1b2-483b-ae29-3d90012c77c1"),
            new Guid("2e85bca9-772c-4a63-9ff6-65ab7cd7612a"),
            new Guid("52c2dfbf-05ed-466b-8e94-b72d27548635"),
            new Guid("e3ef19ae-1599-4fc8-beb1-6616f62ad07a"),
            new Guid("ffc01044-c5b8-4e69-a46f-830e337ce18a"),
            SignInStateManager,
            new Guid("661110c7-5083-4b93-8d41-1d37a51e4425"),
        };

        private const uint ProcUserFromContext = 20;
        private const uint ErrorUnknownUserContext = 0x80A2030B;

        private readonly SessionUserObject User;

        internal UserManagerStatics(SessionUserObject User) => this.User = User;

        internal override bool Permanent => true;

        internal override bool Supports(Guid Interface) => Array.IndexOf(Interfaces, Interface) >= 0;

        internal override bool TryCall(HostCall Call, Guid Interface, uint ProcNumber, ReadOnlySpan<byte> Parameters, out byte[] Stub)
        {
            Stub = null;
            if (Interface != SignInStateManager || ProcNumber != ProcUserFromContext)
                return false;

            Ndr20Reader Reader = new Ndr20Reader(Parameters);
            if (Reader.TryReadUInt64(out ulong Context))
                Stub = UserFromContext(Call, Context);
            return true;
        }

        private byte[] UserFromContext(HostCall Call, ulong Context)
        {
            HostObject Found = Context == WinToken.InteractiveUserContext ? User : null;
            Ndr20Writer Writer = new Ndr20Writer(0x100);
            Orpc.WriteResponseHeader(ref Writer);
            uint Result = WriteOutInterface(ref Writer, Call, Found, SessionUserObject.UserInterface);
            if (Found == null)
                Result = Context == 0 ? Orpc.EInvalidArg : ErrorUnknownUserContext;

            Writer.WriteUInt32(Result);
            return Writer.ToArray();
        }
    }
}
