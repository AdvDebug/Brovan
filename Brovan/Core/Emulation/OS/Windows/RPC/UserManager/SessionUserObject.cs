using System;
using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.RPC.UserManager
{
    internal sealed class SessionUserObject : HostObject
    {
        internal const uint MarshalId = 1;

        internal static readonly Guid UserInterface = new Guid("df9a26c6-e746-4bcd-b5d4-120103c4209b");

        // NT: usermgrproxy's UserMarshalClient unmarshals it.
        private static readonly Guid UserMarshalClass = new Guid("99b29d3b-368a-4be6-b675-805a69114497");

        private static readonly Guid[] Interfaces =
        {
            Orpc.IUnknownId,
            Orpc.IInspectableId,
            UserInterface,
            new Guid("00000038-0000-0000-c000-000000000046"),
            new Guid("98ba5628-a6e3-518e-89d9-d3b2b1991a10"),
            new Guid("520e18e2-f00d-53d1-a9f6-88c697561dc0"),
            new Guid("6ea5bfa1-7433-5a5f-b15c-be429485c6b6"),
        };

        // _USER_MARSHAL_PACKET, as User::MarshalInterface writes it.
        private const int PacketSize = 60;
        private const int OffMarshalId = 8;
        private const int OffAuthenticationStatus = 12;
        private const int OffType = 13;
        private const int OffServerProcessId = 16;
        private const int OffUserContext = 20;
        private const byte LocallyAuthenticated = 1;
        private const byte LocalUser = 0;

        private readonly uint ServerProcessId;

        internal SessionUserObject(uint ServerProcessId) => this.ServerProcessId = ServerProcessId;

        // NT: the service holds its users for the whole session.
        internal override bool Permanent => true;

        internal override bool Supports(Guid Interface) => Array.IndexOf(Interfaces, Interface) >= 0;

        internal override bool TryCall(HostCall Call, Guid Interface, uint ProcNumber, ReadOnlySpan<byte> Parameters, out byte[] Stub)
        {
            Stub = null;
            return false;
        }

        internal override Guid UnmarshalClass => UserMarshalClass;

        // NT: the packet, then the free-threaded marshaler's standard OBJREF.
        internal override byte[] GetMarshalData(Guid Interface, in StdObjRef Std)
        {
            byte[] Data = new byte[PacketSize + StandardObjRefSize];
            Span<byte> Packet = Data.AsSpan(0, PacketSize);
            BinaryPrimitives.WriteUInt16LittleEndian(Packet, PacketSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Packet.Slice(4), PacketSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Packet.Slice(OffMarshalId), MarshalId);
            Packet[OffAuthenticationStatus] = LocallyAuthenticated;
            Packet[OffType] = LocalUser;
            BinaryPrimitives.WriteUInt32LittleEndian(Packet.Slice(OffServerProcessId), ServerProcessId);
            BinaryPrimitives.WriteUInt64LittleEndian(Packet.Slice(OffUserContext), WinToken.InteractiveUserContext);
            WriteStandardObjRef(Data.AsSpan(PacketSize), Interface, Std);
            return Data;
        }
    }
}
