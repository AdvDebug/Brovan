using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Brovan.Core.Helpers;
using static Brovan.Core.Emulation.OS.Windows.NtQueryInformationToken;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Ports
{
    // The lsass lookup interface. combase asks it for the account domain.
    internal static class LsaLookupPortHandler
    {
        public const string PortName = "\\RPC Control\\lsapolicylookup";

        // Opnums from this build's sechost.
        private const uint ProcOpenLocalPolicy = 0;
        private const uint ProcClose = 1;
        private const uint ProcTranslateSids = 2;
        private const uint ProcTranslateNames = 3;
        private const uint ProcGetDomainInfo = 5;

        private const ushort AccountDomainInformation = 5;

        // The sechost stubs of this build declare these [range] bounds.
        private const uint MaxLookupSids = 0x5000;
        private const uint MaxLookupNames = 1000;
        private const uint ReferencedDomainsMax = 32;

        // Each SID in a request takes a referent, a conformance and a SID of at least 8 bytes.
        private const int MinSidEntrySize = 16;
        private const int UnicodeStringHeaderSize = 8;

        private const ushort SidTypeUser = 1;
        private const ushort SidTypeGroup = 2;
        private const ushort SidTypeDomain = 3;
        private const ushort SidTypeAlias = 4;
        private const ushort SidTypeWellKnownGroup = 5;
        private const ushort SidTypeUnknown = 8;
        private const ushort SidTypeLabel = 10;
        private const ushort SidTypeLogonSession = 11;

        private const byte NtAuthority = 5;
        private const uint LogonIdsRid = 5;
        private const string DomainUsersName = "None";
        private const string BuiltinDomainName = "BUILTIN";

        // Indices into FixedDomains. The account domain of the machine follows them.
        private const int NoDomain = -1;
        private const int NtAuthorityDomain = 0;
        private const int WorldDomain = 1;
        private const int NtlmDomain = 2;
        private const int LocalDomain = 3;
        private const int CreatorDomain = 4;
        private const int LabelDomain = 5;
        private const int PackageDomain = 6;
        private const int BuiltinDomain = 7;
        private const int AccountDomain = 8;
        private const int DomainCount = 9;

        private const int DomainListSize = 0x40 + DomainCount * 0x70;

        private static readonly (string Name, byte[] Sid)[] FixedDomains =
        {
            ("NT AUTHORITY", BuildSid(5)),
            (string.Empty, BuildSid(1)),
            ("NT AUTHORITY", BuildSid(5, 64)),
            (string.Empty, BuildSid(2)),
            (string.Empty, BuildSid(3)),
            ("Mandatory Label", BuildSid(16)),
            ("APPLICATION PACKAGE AUTHORITY", BuildSid(15, 2)),
            (BuiltinDomainName, BuildSid(5, 32)),
        };

        private readonly record struct Translation(ushort Use, byte[] Sid, string Name, int Domain)
        {
            public bool Mapped => Use != SidTypeUnknown;
        }

        // Names as an en-US lsass gives them. The list covers every group and label of a Brovan token.
        private static readonly Translation[] WellKnownAccounts =
        {
            new Translation(SidTypeWellKnownGroup, EveryoneSid, "Everyone", WorldDomain),
            new Translation(SidTypeWellKnownGroup, LocalSid, "LOCAL", LocalDomain),
            new Translation(SidTypeWellKnownGroup, ConsoleLogonSid, "CONSOLE LOGON", LocalDomain),
            new Translation(SidTypeWellKnownGroup, BuildSid(3, 0), "CREATOR OWNER", CreatorDomain),
            new Translation(SidTypeWellKnownGroup, OwnerRightsSid, "OWNER RIGHTS", CreatorDomain),
            new Translation(SidTypeWellKnownGroup, NetworkSid, "NETWORK", NtAuthorityDomain),
            new Translation(SidTypeWellKnownGroup, InteractiveSid, "INTERACTIVE", NtAuthorityDomain),
            new Translation(SidTypeWellKnownGroup, AnonymousLogonSid, "ANONYMOUS LOGON", NtAuthorityDomain),
            new Translation(SidTypeWellKnownGroup, PrincipalSelfSid, "SELF", NtAuthorityDomain),
            new Translation(SidTypeWellKnownGroup, AuthenticatedUsersSid, "Authenticated Users", NtAuthorityDomain),
            new Translation(SidTypeWellKnownGroup, ThisOrganizationSid, "This Organization", NtAuthorityDomain),
            new Translation(SidTypeWellKnownGroup, LocalSystemSid, "SYSTEM", NtAuthorityDomain),
            new Translation(SidTypeWellKnownGroup, BuildSid(5, 19), "LOCAL SERVICE", NtAuthorityDomain),
            new Translation(SidTypeWellKnownGroup, BuildSid(5, 20), "NETWORK SERVICE", NtAuthorityDomain),
            new Translation(SidTypeWellKnownGroup, LocalAccountSid, "Local account", NtAuthorityDomain),
            new Translation(SidTypeWellKnownGroup, LocalAccountAndAdministratorSid, "Local account and member of Administrators group", NtAuthorityDomain),
            new Translation(SidTypeWellKnownGroup, NtlmAuthenticationSid, "NTLM Authentication", NtlmDomain),
            new Translation(SidTypeAlias, AdministratorsSid, "Administrators", BuiltinDomain),
            new Translation(SidTypeAlias, UsersSid, "Users", BuiltinDomain),
            new Translation(SidTypeLabel, LabelSidOf(UntrustedIntegrityRid), "Untrusted Mandatory Level", LabelDomain),
            new Translation(SidTypeLabel, LabelSidOf(LowIntegrityRid), "Low Mandatory Level", LabelDomain),
            new Translation(SidTypeLabel, LabelSidOf(MediumIntegrityRid), "Medium Mandatory Level", LabelDomain),
            new Translation(SidTypeLabel, LabelSidOf(HighIntegrityRid), "High Mandatory Level", LabelDomain),
            new Translation(SidTypeLabel, LabelSidOf(SystemIntegrityRid), "System Mandatory Level", LabelDomain),
            new Translation(SidTypeWellKnownGroup, AllApplicationPackagesSid, "ALL APPLICATION PACKAGES", PackageDomain),
            new Translation(SidTypeWellKnownGroup, AllRestrictedApplicationPackagesSid, "ALL RESTRICTED APPLICATION PACKAGES", PackageDomain),
        };

        private static readonly Dictionary<string, int>.AlternateLookup<ReadOnlySpan<char>> WellKnownNames = IndexWellKnownNames();

        private static Dictionary<string, int>.AlternateLookup<ReadOnlySpan<char>> IndexWellKnownNames()
        {
            Dictionary<string, int> Names = new Dictionary<string, int>(WellKnownAccounts.Length, StringComparer.OrdinalIgnoreCase);
            for (int Index = 0; Index < WellKnownAccounts.Length; Index++)
                Names.Add(WellKnownAccounts[Index].Name, Index);

            return Names.GetAlternateLookup<ReadOnlySpan<char>>();
        }

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

                case ProcTranslateSids:
                    return TryTranslateSids(Stub, Instance, out Reply);

                case ProcTranslateNames:
                    return TryTranslateNames(Stub, Instance, out Reply);
            }

            return false;
        }

        private static bool TryTranslateSids(ReadOnlySpan<byte> Stub, BinaryEmulator Instance, out byte[] Reply)
        {
            Reply = null;
            Ndr20Reader Reader = new Ndr20Reader(Stub);
            if (!Reader.TryReadContextHandle(out _) || !Reader.TryReadUInt32(out uint Count) || !Reader.TryReadUInt32(out uint SidsReferent)
                || Count > MaxLookupSids || Count > (uint)Stub.Length / MinSidEntrySize)
                return false;

            if (Count != 0 && (SidsReferent == 0 || !Reader.TryReadUInt32(out uint Conformance) || Conformance != Count))
                return false;

            for (int i = 0; i < Count; i++)
            {
                if (!Reader.TryReadUInt32(out uint SidReferent) || SidReferent == 0)
                    return false;
            }

            Translation[] Rented = ArrayPool<Translation>.Shared.Rent((int)Count);
            try
            {
                Span<Translation> Translations = Rented.AsSpan(0, (int)Count);
                for (int i = 0; i < Count; i++)
                {
                    if (!Reader.TryReadSid(out ReadOnlySpan<byte> Sid))
                        return false;
                    Translations[i] = TranslateSid(Sid);
                }

                Span<int> Slots = stackalloc int[DomainCount];
                Ndr20Writer Writer = new Ndr20Writer(DomainListSize + (int)Count * 0x80);
                WriteDomainsAndEntryArray(ref Writer, Translations, Slots, Instance, null);
                foreach (Translation Item in Translations)
                {
                    Writer.WriteUInt16(Item.Use);
                    Writer.AlignTo(4);
                    WriteUnicodeStringHeader(ref Writer, Item.Name);
                    Writer.WriteInt32(SlotOf(Item, Slots));
                    Writer.WriteUInt32(0);
                }

                foreach (Translation Item in Translations)
                    WriteUnicodeStringBuffer(ref Writer, Item.Name);

                WriteMappedCountAndStatus(ref Writer, Translations);
                Reply = Writer.ToArray();
                return true;
            }
            finally
            {
                ArrayPool<Translation>.Shared.Return(Rented, clearArray: true);
            }
        }

        private static bool TryTranslateNames(ReadOnlySpan<byte> Stub, BinaryEmulator Instance, out byte[] Reply)
        {
            Reply = null;
            Ndr20Reader Reader = new Ndr20Reader(Stub);
            if (!Reader.TryReadContextHandle(out _) || !Reader.TryReadUInt32(out uint Count) || Count > MaxLookupNames
                || !Reader.TryReadUInt32(out uint Conformance) || Conformance != Count)
                return false;

            // The RPC_UNICODE_STRING headers come first and their buffers after them, in the same order.
            Ndr20Reader Headers = Reader;
            if (!Reader.TrySkip((int)Count * UnicodeStringHeaderSize))
                return false;

            string DomainName = Count != 0 ? ReadComputerName(Instance) : string.Empty;
            Translation[] Rented = ArrayPool<Translation>.Shared.Rent((int)Count);
            try
            {
                Span<Translation> Translations = Rented.AsSpan(0, (int)Count);
                for (int i = 0; i < Count; i++)
                {
                    if (!Headers.TryReadUInt16(out ushort Length) || !Headers.TryReadUInt16(out _) || !Headers.TryReadUInt32(out uint Referent))
                        return false;

                    ReadOnlySpan<byte> Chars = default;
                    if (Referent != 0 && (!Reader.TryReadConformantWideChars(out Chars, out uint Offset) || Offset != 0 || Chars.Length != Length))
                        return false;

                    Translations[i] = TranslateName(MemoryMarshal.Cast<byte, char>(Chars), DomainName);
                }

                Span<int> Slots = stackalloc int[DomainCount];
                Ndr20Writer Writer = new Ndr20Writer(DomainListSize + (int)Count * 0x50);
                WriteDomainsAndEntryArray(ref Writer, Translations, Slots, Instance, DomainName);
                foreach (Translation Item in Translations)
                {
                    Writer.WriteUInt16(Item.Use);
                    Writer.AlignTo(4);
                    if (Item.Sid != null)
                        Writer.WriteUniqueReferent();
                    else
                        Writer.WriteUInt32(0);
                    Writer.WriteInt32(SlotOf(Item, Slots));
                    Writer.WriteUInt32(0);
                }

                foreach (Translation Item in Translations)
                {
                    if (Item.Sid != null)
                        WriteSid(ref Writer, Item.Sid);
                }

                WriteMappedCountAndStatus(ref Writer, Translations);
                Reply = Writer.ToArray();
                return true;
            }
            finally
            {
                ArrayPool<Translation>.Shared.Return(Rented, clearArray: true);
            }
        }

        private static Translation TranslateSid(ReadOnlySpan<byte> Sid)
        {
            foreach (Translation Known in WellKnownAccounts)
            {
                if (Sid.SequenceEqual(Known.Sid))
                    return Known;
            }

            if (TryGetLogonSession(Sid, out string Session))
                return new Translation(SidTypeLogonSession, null, Session, NtAuthorityDomain);

            if (Sid.SequenceEqual(FixedDomains[BuiltinDomain].Sid))
                return new Translation(SidTypeDomain, null, BuiltinDomainName, BuiltinDomain);

            if (Sid.SequenceEqual(AccountDomainSid))
                return new Translation(SidTypeDomain, AccountDomainSid, string.Empty, AccountDomain);

            if (!TryGetAccountRid(Sid, out uint Rid))
                return new Translation(SidTypeUnknown, null, FormatSid(Sid), NoDomain);

            return Rid switch
            {
                InteractiveUserRid => new Translation(SidTypeUser, InteractiveUserSid, WinSysHelper.CurrentUserName, AccountDomain),
                DomainUsersRid => new Translation(SidTypeGroup, DomainUsersSid, DomainUsersName, AccountDomain),
                _ => new Translation(SidTypeUnknown, null, string.Empty, AccountDomain),
            };
        }

        private static Translation TranslateName(ReadOnlySpan<char> Name, string DomainName)
        {
            int Separator = Name.IndexOf('\\');
            bool Qualified = Separator >= 0;
            ReadOnlySpan<char> Domain = Qualified ? Name.Slice(0, Separator) : default;
            ReadOnlySpan<char> Account = Qualified ? Name.Slice(Separator + 1) : Name;

            if (!Qualified && NamesMatch(Account, DomainName))
                return new Translation(SidTypeDomain, AccountDomainSid, null, AccountDomain);

            if (!Qualified && NamesMatch(Account, BuiltinDomainName))
                return new Translation(SidTypeDomain, FixedDomains[BuiltinDomain].Sid, null, BuiltinDomain);

            if (WellKnownNames.TryGetValue(Account, out int Index))
            {
                Translation Known = WellKnownAccounts[Index];
                if (!Qualified || NamesMatch(Domain, FixedDomains[Known.Domain].Name))
                    return Known;
            }

            bool InDomain = !Qualified || NamesMatch(Domain, DomainName);
            if (InDomain && NamesMatch(Account, WinSysHelper.CurrentUserName))
                return new Translation(SidTypeUser, InteractiveUserSid, null, AccountDomain);

            if (InDomain && NamesMatch(Account, DomainUsersName))
                return new Translation(SidTypeGroup, DomainUsersSid, null, AccountDomain);

            // An unknown account of a domain that lsass knows still names that domain.
            int Listed = !Qualified ? NoDomain : InDomain ? AccountDomain : NamesMatch(Domain, BuiltinDomainName) ? BuiltinDomain : NoDomain;
            return new Translation(SidTypeUnknown, null, null, Listed);
        }

        private static bool NamesMatch(ReadOnlySpan<char> Left, string Right) => Left.Equals(Right, StringComparison.OrdinalIgnoreCase);

        private static bool TryGetLogonSession(ReadOnlySpan<byte> Sid, out string Name)
        {
            Name = null;
            if (Sid.Length != SidLength(3) || FirstSubAuthority(Sid, NtAuthority) != LogonIdsRid)
                return false;

            Name = $"LogonSessionId_{SubAuthority(Sid, 1)}_{SubAuthority(Sid, 2)}";
            return true;
        }

        // lsass lists well-known authorities, then BUILTIN, then the account domain, each group in order of first use.
        private static int ListDomains(ReadOnlySpan<Translation> Translations, Span<int> Slots, Span<int> Order)
        {
            Slots.Fill(NoDomain);
            Span<int> Named = stackalloc int[DomainCount];
            int NamedCount = 0;
            foreach (Translation Item in Translations)
            {
                if (Item.Domain != NoDomain && Slots[Item.Domain] == NoDomain)
                {
                    Slots[Item.Domain] = 0;
                    Named[NamedCount++] = Item.Domain;
                }
            }

            int Listed = 0;
            for (int Group = 0; Group <= ListGroupOf(AccountDomain); Group++)
            {
                foreach (int Domain in Named.Slice(0, NamedCount))
                {
                    if (ListGroupOf(Domain) != Group)
                        continue;

                    Slots[Domain] = Listed;
                    Order[Listed++] = Domain;
                }
            }

            return Listed;
        }

        private static int ListGroupOf(int Domain) => Domain < BuiltinDomain ? 0 : Domain == BuiltinDomain ? 1 : 2;

        private static void WriteDomainsAndEntryArray(ref Ndr20Writer Writer, ReadOnlySpan<Translation> Translations, Span<int> Slots, BinaryEmulator Instance, string AccountDomainName)
        {
            Span<int> Order = stackalloc int[DomainCount];
            int Listed = ListDomains(Translations, Slots, Order);
            if (Slots[AccountDomain] != NoDomain)
                AccountDomainName ??= ReadComputerName(Instance);

            WriteReferencedDomains(ref Writer, Order.Slice(0, Listed), AccountDomainName);
            uint Count = (uint)Translations.Length;
            Writer.WriteUInt32(Count);
            Writer.WriteUniqueUInt32(Count != 0, Count);
        }

        private static int SlotOf(in Translation Item, ReadOnlySpan<int> Slots) => Item.Domain == NoDomain ? NoDomain : Slots[Item.Domain];

        private static void WriteReferencedDomains(ref Ndr20Writer Writer, ReadOnlySpan<int> Domains, string AccountDomainName)
        {
            Writer.WriteUniqueReferent();
            if (Domains.IsEmpty)
            {
                Writer.WriteZeros(3 * sizeof(uint));
                return;
            }

            Writer.WriteUInt32((uint)Domains.Length);
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32(ReferencedDomainsMax);
            Writer.WriteUInt32((uint)Domains.Length);
            foreach (int Domain in Domains)
            {
                WriteUnicodeStringHeader(ref Writer, NameOfDomain(Domain, AccountDomainName), EmptyHasBuffer: true);
                Writer.WriteUniqueReferent();
            }

            foreach (int Domain in Domains)
            {
                WriteUnicodeStringBuffer(ref Writer, NameOfDomain(Domain, AccountDomainName), EmptyHasBuffer: true);
                WriteSid(ref Writer, Domain == AccountDomain ? AccountDomainSid : FixedDomains[Domain].Sid);
            }
        }

        private static string NameOfDomain(int Domain, string AccountDomainName) => Domain == AccountDomain ? AccountDomainName : FixedDomains[Domain].Name;

        // lsass gives an empty domain name a buffer with room for the NUL, and an empty account name no buffer.
        private static void WriteUnicodeStringHeader(ref Ndr20Writer Writer, string Value, bool EmptyHasBuffer = false)
        {
            if (string.IsNullOrEmpty(Value) && !EmptyHasBuffer)
            {
                Writer.WriteZeros(UnicodeStringHeaderSize);
                return;
            }

            ushort Bytes = (ushort)(Value.Length * sizeof(char));
            Writer.WriteUInt16(Bytes);
            Writer.WriteUInt16((ushort)(Bytes + sizeof(char)));
            Writer.WriteUniqueReferent();
        }

        private static void WriteUnicodeStringBuffer(ref Ndr20Writer Writer, string Value, bool EmptyHasBuffer = false)
        {
            if (string.IsNullOrEmpty(Value) && !EmptyHasBuffer)
                return;

            Writer.WriteUInt32((uint)Value.Length + 1);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32((uint)Value.Length);
            Writer.WriteUtf16(Value);
            Writer.AlignTo(4);
        }

        private static void WriteSid(ref Ndr20Writer Writer, byte[] Sid)
        {
            Writer.WriteUInt32(Sid[1]);
            Writer.WriteBytes(Sid);
            Writer.AlignTo(4);
        }

        private static void WriteMappedCountAndStatus(ref Ndr20Writer Writer, ReadOnlySpan<Translation> Translations)
        {
            uint Mapped = 0;
            foreach (Translation Item in Translations)
            {
                if (Item.Mapped)
                    Mapped++;
            }

            NTSTATUS Status = Mapped == Translations.Length ? NTSTATUS.STATUS_SUCCESS : Mapped == 0 ? NTSTATUS.STATUS_NONE_MAPPED : NTSTATUS.STATUS_SOME_NOT_MAPPED;
            Writer.WriteUInt32(Mapped);
            Writer.WriteUInt32((uint)Status);
        }

        private static bool TryGetDomainInfo(ReadOnlySpan<byte> Stub, BinaryEmulator Instance, out byte[] Reply)
        {
            Reply = null;

            if (Stub.Length < Ndr20Writer.ContextHandleSize + 2)
                return false;

            ushort InfoClass = BinaryPrimitives.ReadUInt16LittleEndian(Stub.Slice(Ndr20Writer.ContextHandleSize, 2));
            Ndr20Writer Writer = new Ndr20Writer(128);

            if (InfoClass != AccountDomainInformation)
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
            Writer.WriteUtf16(DomainName);
            Writer.AlignTo(4);

            WriteSid(ref Writer, AccountDomainSid);
            Writer.WriteUInt32((uint)NTSTATUS.STATUS_SUCCESS);
            Reply = Writer.ToArray();
            return true;
        }

        internal static string ReadComputerName(BinaryEmulator Instance)
        {
            if (!Instance.WinHelper.TryReadRegistryValue(ComputerNameKey, "ComputerName", out ValueNode Value) || Value?.Data == null)
                return DefaultComputerName;

            ReadOnlySpan<char> Name = MemoryMarshal.Cast<byte, char>(Value.Data.AsSpan(0, Value.Data.Length & ~1)).TrimEnd('\0');
            return Name.IsEmpty ? DefaultComputerName : new string(Name);
        }

    }
}
