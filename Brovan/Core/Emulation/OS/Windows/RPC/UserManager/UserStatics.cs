using System;

namespace Brovan.Core.Emulation.OS.Windows.RPC.UserManager
{
    internal sealed class UserStatics : HostObject
    {
        internal const string ClassId = "Windows.System.User";

        private static readonly Guid UserStaticsInterface = new Guid("155eb23b-242a-45e0-a2e9-3171fc6a7fdd");

        // The interfaces of the native factory's GetIids.
        private static readonly Guid[] Interfaces =
        {
            Orpc.IUnknownId,
            Orpc.IInspectableId,
            new Guid("00000035-0000-0000-c000-000000000046"),
            UserStaticsInterface,
            new Guid("74a37e11-2eb5-4487-b0d5-2c6790e013e9"),
        };

        private const uint ProcGetFromId = 10;

        private readonly UserManagerService Service;

        internal UserStatics(UserManagerService Service) => this.Service = Service;

        internal override bool Permanent => true;

        internal override bool Supports(Guid Interface) => Array.IndexOf(Interfaces, Interface) >= 0;

        internal override bool TryCall(HostCall Call, Guid Interface, uint ProcNumber, ReadOnlySpan<byte> Parameters, out byte[] Stub)
        {
            Stub = null;
            if (Interface != UserStaticsInterface || ProcNumber != ProcGetFromId)
                return false;

            Ndr20Reader Reader = new Ndr20Reader(Parameters);
            if (Reader.TryReadUInt32(out uint Marker) && Marker == Orpc.UserMarshalMarker && Orpc.TryReadHstringBody(ref Reader, out ReadOnlySpan<char> Id))
                Stub = GetFromId(Call, Service.FindUser(Call.Instance, Id));
            return true;
        }

        // NT: an id that names no user is S_OK with a null user.
        private static byte[] GetFromId(HostCall Call, SessionUserObject User)
        {
            Ndr20Writer Writer = new Ndr20Writer(0x100);
            Orpc.WriteResponseHeader(ref Writer);
            uint Result = WriteOutInterface(ref Writer, Call, User, SessionUserObject.UserInterface);
            Writer.WriteUInt32(Result);
            return Writer.ToArray();
        }
    }
}
