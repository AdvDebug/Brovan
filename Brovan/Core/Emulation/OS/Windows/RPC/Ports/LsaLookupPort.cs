using System;
using System.Buffers.Binary;
using System.Text;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Ports
{
    // The lsass lookup interface. combase asks it for the account domain.
    internal static class LsaLookupPortHandler
    {
        public const string PortName = "\\RPC Control\\lsapolicylookup";

        // Opnums from this build's sechost.
        private const uint ProcOpenLocalPolicy = 0;
        private const uint ProcClose = 1;
        private const uint ProcGetDomainInfo = 5;

        private const ushort AccountDomainInformation = 5;

        private const uint StatusSuccess = 0;

        private const string ComputerNameKey = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName";
        private const string DefaultComputerName = "BROVAN";

        public static bool TryHandle(string Port, uint ProcNumber, ReadOnlySpan<byte> Stub, BinaryEmulator Instance, out byte[] Reply)
        {
            Reply = null;

            if (!string.Equals(Port, PortName, StringComparison.OrdinalIgnoreCase))
                return false;

            switch (ProcNumber)
            {
                case ProcOpenLocalPolicy:
                    Reply = Ndr20Writer.BuildContextHandleReply(Guid.NewGuid());
                    return true;

                case ProcClose:
                    Reply = Ndr20Writer.BuildContextHandleReply(Guid.Empty);
                    return true;

                case ProcGetDomainInfo:
                    return TryGetDomainInfo(Stub, Instance, out Reply);
            }

            return false;
        }

        private static bool TryGetDomainInfo(ReadOnlySpan<byte> Stub, BinaryEmulator Instance, out byte[] Reply)
        {
            Reply = null;

            if (Stub.Length < Ndr20Writer.ContextHandleSize + 2)
                return false;

            ushort InfoClass = BinaryPrimitives.ReadUInt16LittleEndian(Stub.Slice(Ndr20Writer.ContextHandleSize, 2));
            Ndr20Writer Writer = new Ndr20Writer(128);

            if (InfoClass != AccountDomainInformation || !TryBuildDomainSid(Instance.WinHelper.CurrentUserSid, out byte[] DomainSid))
            {
                Writer.WriteUInt32(0);
                Writer.WriteUInt32((uint)NTSTATUS.STATUS_INVALID_PARAMETER);
                Reply = Writer.ToArray();
                return true;
            }

            string DomainName = ReadComputerName(Instance);
            ushort NameBytes = (ushort)(DomainName.Length * sizeof(char));

            // The union: discriminant, then POLICY_ACCOUNT_DOMAIN_INFO with the name and SID deferred.
            Writer.WriteUniqueReferent();
            Writer.WriteUInt16(AccountDomainInformation);
            Writer.AlignTo(4);
            Writer.WriteUInt16(NameBytes);
            Writer.WriteUInt16(NameBytes);
            Writer.WriteUniqueReferent();
            Writer.WriteUniqueReferent();

            Writer.WriteUInt32((uint)DomainName.Length);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32((uint)DomainName.Length);
            Writer.WriteBytes(Encoding.Unicode.GetBytes(DomainName));
            Writer.AlignTo(4);

            Writer.WriteUInt32(DomainSid[1]);
            Writer.WriteBytes(DomainSid);
            Writer.AlignTo(4);

            Writer.WriteUInt32(StatusSuccess);
            Reply = Writer.ToArray();
            return true;
        }

        // The account domain is the user's SID without its relative id.
        private static bool TryBuildDomainSid(string UserSid, out byte[] Sid)
        {
            Sid = null;

            if (string.IsNullOrEmpty(UserSid))
                return false;

            string[] Parts = UserSid.Split('-');
            if (Parts.Length < 5 || Parts[0] != "S" || !byte.TryParse(Parts[1], out byte Revision) || !ulong.TryParse(Parts[2], out ulong Authority))
                return false;

            int SubAuthorityCount = Parts.Length - 4;
            if (SubAuthorityCount > 15)
                return false;

            uint[] SubAuthorities = new uint[SubAuthorityCount];
            for (int i = 0; i < SubAuthorityCount; i++)
            {
                if (!uint.TryParse(Parts[3 + i], out SubAuthorities[i]))
                    return false;
            }

            Sid = NtQueryInformationToken.BuildSid(Revision, Authority, SubAuthorities);
            return true;
        }

        private static string ReadComputerName(BinaryEmulator Instance)
        {
            WinRegKey Key = Instance.WinHelper.ResolveRegistryKey(ComputerNameKey);
            if (Key == null || !Instance.WinHelper.TryGetRegistryValue(Key, "ComputerName", out ValueNode Value) || Value?.Data == null)
                return DefaultComputerName;

            string Name = Encoding.Unicode.GetString(Value.Data).TrimEnd('\0');
            return Name.Length == 0 ? DefaultComputerName : Name;
        }

    }
}
