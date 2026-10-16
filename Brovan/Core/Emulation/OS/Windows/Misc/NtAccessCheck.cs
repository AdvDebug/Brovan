using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Brovan.Core.Helpers;
using static Brovan.Core.Emulation.OS.Windows.NtQueryInformationToken;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAccessCheck : IWinSyscall
    {
        private const uint GenericRead = 0x80000000;
        private const uint GenericWrite = 0x40000000;
        private const uint GenericExecute = 0x20000000;
        private const uint GenericAll = 0x10000000;
        private const uint GenericBits = GenericRead | GenericWrite | GenericExecute | GenericAll;
        private const uint MaximumAllowed = 0x02000000;
        private const uint AccessSystemSecurity = 0x01000000;
        private const uint Synchronize = 0x00100000;
        private const uint WriteDac = 0x00040000;
        private const uint ReadControl = 0x00020000;
        private const uint StandardRightsAll = 0x001F0000;
        private const uint SpecificRightsAll = 0x0000FFFF;
        private const uint OwnerImpliedRights = ReadControl | WriteDac;

        private const byte SecurityDescriptorRevision = 1;
        private const int OffControl = 2;
        internal const ushort SeDaclPresent = 0x0004;
        private const ushort SeSaclPresent = 0x0010;
        private const ushort SeSelfRelative = 0x8000;
        internal const int SelfRelativeHeaderSize = 20;

        private const int OwnerField = 0;
        private const int GroupField = 1;
        private const int SaclField = 2;
        private const int DaclField = 3;
        private const int FieldCount = 4;

        internal const byte AclRevision = 2;
        private const byte AclRevisionDs = 4;
        internal const int AclHeaderSize = 8;
        private const int AceHeaderSize = 4;
        internal const int AceSidOffset = 8;
        private const int ObjectAceFlagsSize = 4;
        private const int ObjectTypeSize = 16;

        private const byte AccessAllowedAce = 0;
        private const byte AccessDeniedAce = 1;
        private const byte AccessAllowedObjectAce = 5;
        private const byte AccessDeniedObjectAce = 6;
        private const byte AccessAllowedCallbackAce = 9;
        private const byte AccessDeniedCallbackAce = 0x0A;
        private const byte AccessAllowedCallbackObjectAce = 0x0B;
        private const byte AccessDeniedCallbackObjectAce = 0x0C;
        private const byte SystemMandatoryLabelAce = 0x11;
        private const byte InheritOnlyAce = 0x08;
        private const uint AceObjectTypePresent = 1;
        private const uint AceInheritedObjectTypePresent = 2;

        private const uint MandatoryNoWriteUp = 1;
        private const uint MandatoryNoReadUp = 2;
        private const uint MandatoryNoExecuteUp = 4;

        private const uint AllowGroups = SeGroupEnabled;
        private const uint DenyGroups = SeGroupEnabled | SeGroupUseForDenyOnly;

        private const int PrivilegeSetEmptySize = 20;

        internal static uint ApplyGenericMapping(uint DesiredAccess, uint MapRead, uint MapWrite, uint MapExecute, uint MapAll)
        {
            uint Mapped = DesiredAccess;

            if ((Mapped & GenericRead) != 0)
            {
                Mapped &= ~GenericRead;
                Mapped |= MapRead;
            }

            if ((Mapped & GenericWrite) != 0)
            {
                Mapped &= ~GenericWrite;
                Mapped |= MapWrite;
            }

            if ((Mapped & GenericExecute) != 0)
            {
                Mapped &= ~GenericExecute;
                Mapped |= MapExecute;
            }

            if ((Mapped & GenericAll) != 0)
            {
                Mapped &= ~GenericAll;
                Mapped |= MapAll;
            }

            return Mapped;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            WinSysHelper Helper = Instance.WinHelper;
            return Check(Instance, DescriptorPtr: Helper.GetArg(0), SelfSidPtr: 0, TokenHandle: Helper.GetArg(1), Desired: (uint)Helper.GetArg(2), ObjectTypeListLength: 0,
                MappingPtr: Helper.GetArg(3), PrivilegeSetPtr: Helper.GetArg(4), PrivilegeSetLengthPtr: Helper.GetArg(5), GrantedAccessPtr: Helper.GetArg(6),
                AccessStatusPtr: Helper.GetArg(7));
        }

        private readonly ref struct Descriptor
        {
            internal readonly ReadOnlySpan<byte> Owner;
            internal readonly ReadOnlySpan<byte> Group;
            internal readonly ReadOnlySpan<byte> Dacl;
            internal readonly ReadOnlySpan<byte> Sacl;

            internal Descriptor(ReadOnlySpan<byte> Owner, ReadOnlySpan<byte> Group, ReadOnlySpan<byte> Dacl, ReadOnlySpan<byte> Sacl)
            {
                this.Owner = Owner;
                this.Group = Group;
                this.Dacl = Dacl;
                this.Sacl = Sacl;
            }
        }

        private ref struct Identity
        {
            internal readonly byte[] User;
            internal readonly TokenGroup[] Groups;
            internal readonly WinToken Token;
            private readonly ReadOnlySpan<byte> OwnerSid;
            private bool? Owner;

            internal Identity(byte[] User, TokenGroup[] Groups, WinToken Token, ReadOnlySpan<byte> OwnerSid)
            {
                this.User = User;
                this.Groups = Groups;
                this.Token = Token;
                this.OwnerSid = OwnerSid;
            }

            internal bool IsOwner() => Owner ??= Contains(OwnerSid, AllowGroups);

            internal readonly bool Contains(scoped ReadOnlySpan<byte> Sid, uint GroupAttributes)
            {
                if (Sid.SequenceEqual(User))
                    return true;

                foreach (TokenGroup Group in Groups)
                {
                    if ((Group.Attributes & GroupAttributes) != 0 && Sid.SequenceEqual(Group.Sid))
                        return true;
                }

                return false;
            }
        }

        internal static NTSTATUS Check(BinaryEmulator Instance, ulong DescriptorPtr, ulong SelfSidPtr, ulong TokenHandle, uint Desired, uint ObjectTypeListLength,
            ulong MappingPtr, ulong PrivilegeSetPtr, ulong PrivilegeSetLengthPtr, ulong GrantedAccessPtr, ulong AccessStatusPtr)
        {
            WinSysHelper Helper = Instance.WinHelper;
            if (!Touch(Helper, PrivilegeSetLengthPtr, out uint PrivilegeSetLength) || !Touch(Helper, AccessStatusPtr, out _) || !Touch(Helper, GrantedAccessPtr, out _))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (PrivilegeSetLength != 0)
            {
                if ((PrivilegeSetPtr & 3) != 0)
                    return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;
                if (!Instance.IsMemoryRangeMapped(PrivilegeSetPtr, PrivilegeSetLength))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if (PrivilegeSetPtr != 0 && PrivilegeSetLength >= PrivilegeSetEmptySize && !Helper.WriteUInt32(PrivilegeSetPtr, 0))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if ((MappingPtr & 3) != 0)
                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

            GENERIC_MAPPING Mapping = default;
            if (!Instance.ReadMemory(MappingPtr, MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref Mapping, 1))))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if ((Desired & GenericBits) != 0)
                return NTSTATUS.STATUS_GENERIC_NOT_MAPPED;

            NTSTATUS Status = ResolveClientToken(Instance, TokenHandle, out WinToken Token);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (ObjectTypeListLength != 0)
            {
                Utils.LogError("[-] NtAccessCheckByType: object type lists are not modelled.");
                return NTSTATUS.STATUS_NOT_IMPLEMENTED;
            }

            Status = CaptureDescriptor(Instance, DescriptorPtr, out Descriptor Captured);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Captured.Owner.IsEmpty || Captured.Group.IsEmpty)
                return NTSTATUS.STATUS_INVALID_SECURITY_DESCR;

            WinProcess OwnerProcess = OwnerOf(Instance, Token);
            uint IntegrityRid = IntegrityRidOf(Token, OwnerProcess);

            uint Requested = Desired & ~MaximumAllowed;
            bool Maximum = (Desired & MaximumAllowed) != 0;
            uint IntegrityMask = IntegrityAllowedMask(Captured.Sacl, IntegrityRid, Mapping, out uint ObjectRid);
            bool IntegrityRestricts = IntegrityRid < ObjectRid;
            bool IntegrityDenies = (IntegrityMask & Requested) != Requested;

            // NT lets a package or capability ACE override the label of an object at medium or below.
            bool PackageMayOverrideLabel = Token.IsAppContainer && ObjectRid <= MediumIntegrityRid && (IntegrityDenies || Maximum);
            if (IntegrityDenies && !PackageMayOverrideLabel)
                return Finish(Helper, GrantedAccessPtr, AccessStatusPtr, 0, NTSTATUS.STATUS_ACCESS_DENIED);

            // SeSecurityPrivilege is never enabled in a token Brovan hands out.
            if ((Desired & AccessSystemSecurity) != 0)
                return Finish(Helper, GrantedAccessPtr, AccessStatusPtr, 0, NTSTATUS.STATUS_PRIVILEGE_NOT_HELD);

            if (PrivilegeSetLength < PrivilegeSetEmptySize)
                return Helper.WriteUInt32(PrivilegeSetLengthPtr, PrivilegeSetEmptySize) ? NTSTATUS.STATUS_BUFFER_TOO_SMALL : NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Helper.WriteUInt64(PrivilegeSetPtr, 0))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            scoped ReadOnlySpan<byte> Self = default;
            if (SelfSidPtr != 0)
            {
                Status = ReadSid(Instance, SelfSidPtr, stackalloc byte[SidLength(MaxSubAuthorities)], out Self);
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;
            }

            Identity Client = new Identity(UserSidOf(Token, OwnerProcess), GroupsOf(Token, OwnerProcess), Token, Captured.Owner);
            uint Granted = 0;
            if ((Desired & (MaximumAllowed | OwnerImpliedRights)) != 0 && Client.IsOwner() && !OwnerRightsAcePresent(Captured.Dacl))
            {
                Granted = Maximum ? OwnerImpliedRights : Desired & OwnerImpliedRights;
                Desired &= ~OwnerImpliedRights;
                if (Desired == 0 && !Token.IsAppContainer)
                    return Finish(Helper, GrantedAccessPtr, AccessStatusPtr, Granted, NTSTATUS.STATUS_SUCCESS);
            }

            NTSTATUS AccessStatus = EvaluateDacl(Captured, ref Client, Self, Desired, Mapping.GenericAll, ref Granted, out bool PackageMatched);
            if (AccessStatus == NTSTATUS.STATUS_NOT_IMPLEMENTED)
                return AccessStatus;

            if (AccessStatus == NTSTATUS.STATUS_SUCCESS)
            {
                bool LabelOverridden = PackageMayOverrideLabel && PackageMatched;
                if (!Maximum && IntegrityDenies && !LabelOverridden)
                    AccessStatus = NTSTATUS.STATUS_ACCESS_DENIED;
                else if (Maximum && IntegrityRestricts && !LabelOverridden)
                {
                    Granted &= IntegrityMask;
                    if (Granted == 0)
                        AccessStatus = NTSTATUS.STATUS_ACCESS_DENIED;
                }
            }

            return Finish(Helper, GrantedAccessPtr, AccessStatusPtr, AccessStatus == NTSTATUS.STATUS_SUCCESS ? Granted : 0, AccessStatus);
        }

        private static NTSTATUS Finish(WinSysHelper Helper, ulong GrantedAccessPtr, ulong AccessStatusPtr, uint Granted, NTSTATUS AccessStatus)
        {
            if (!Helper.WriteUInt32(AccessStatusPtr, (uint)AccessStatus) || !Helper.WriteUInt32(GrantedAccessPtr, Granted))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool Touch(WinSysHelper Helper, ulong Address, out uint Value)
        {
            return Helper.TryReadUInt32(Address, out Value) && Helper.WriteUInt32(Address, Value);
        }

        // NT skips the type and level checks for the effective-token pseudo handles (SepReferenceTokenByHandle).
        private static NTSTATUS ResolveClientToken(BinaryEmulator Instance, ulong TokenHandle, out WinToken Token)
        {
            if (HandleManager.IsTokenPseudoHandle(TokenHandle))
                return ResolvePseudoToken(Instance, TokenHandle, out Token);

            NTSTATUS Status = Instance.WinHelper.ReferenceObjectByHandle(TokenHandle, AccessMask.TokenQuery, out Token);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Token.Type != TokenType.Impersonation)
                return NTSTATUS.STATUS_NO_IMPERSONATION_TOKEN;

            return Token.ImpersonationLevel < SecurityImpersonationLevel.SecurityIdentification ? NTSTATUS.STATUS_BAD_IMPERSONATION_LEVEL : NTSTATUS.STATUS_SUCCESS;
        }

        // The spans point into the shared scratch buffer and stay valid until its next use.
        private static NTSTATUS CaptureDescriptor(BinaryEmulator Instance, ulong DescriptorPtr, out Descriptor Captured)
        {
            Captured = default;
            WinSysHelper Helper = Instance.WinHelper;

            // NT captures a NULL descriptor as nothing, and the caller then refuses it for its missing owner.
            if (DescriptorPtr == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if ((DescriptorPtr & 3) != 0)
                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

            // NT reads the whole header before it checks alignment and revision (SeCaptureSecurityDescriptor).
            Span<byte> Raw = stackalloc byte[sizeof(ulong) + FieldCount * sizeof(ulong)];
            if (!Instance.ReadMemory(DescriptorPtr, Raw.Slice(0, SelfRelativeHeaderSize)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            // Self-relative fields are 4-byte offsets. Absolute fields are pointers and pointer aligned.
            ushort Control = BinaryPrimitives.ReadUInt16LittleEndian(Raw.Slice(OffControl));
            bool SelfRelative = (Control & SeSelfRelative) != 0;
            if (!SelfRelative && (DescriptorPtr & (ulong)(Helper.PointerSize - 1)) != 0)
                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

            if (Raw[0] != SecurityDescriptorRevision)
                return NTSTATUS.STATUS_UNKNOWN_REVISION;

            int FieldSize = SelfRelative ? sizeof(uint) : Helper.PointerSize;
            int End = FieldSize * (FieldCount + 1);
            if (End > SelfRelativeHeaderSize && !Instance.ReadMemory(DescriptorPtr + SelfRelativeHeaderSize, Raw.Slice(SelfRelativeHeaderSize, End - SelfRelativeHeaderSize)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Span<byte> Fields = Raw.Slice(FieldSize, FieldSize * FieldCount);

            Span<ulong> Locations = stackalloc ulong[FieldCount];
            for (int Index = 0; Index < FieldCount; Index++)
            {
                ulong Value = WinSysHelper.ReadPointerField(Fields, Index, (uint)FieldSize);
                Locations[Index] = Value == 0 ? 0 : SelfRelative ? DescriptorPtr + Value : Value;
            }

            if ((Control & SeSaclPresent) == 0)
                Locations[SaclField] = 0;
            if ((Control & SeDaclPresent) == 0)
                Locations[DaclField] = 0;

            Span<int> Sizes = stackalloc int[FieldCount];
            int TotalSize = 0;
            for (int Index = 0; Index < FieldCount; Index++)
            {
                if (Locations[Index] == 0)
                    continue;

                NTSTATUS Status = Index <= GroupField ? SidSize(Instance, Locations[Index], out Sizes[Index]) : AclSize(Instance, Locations[Index], out Sizes[Index]);
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;
                TotalSize += Sizes[Index];
            }

            Span<byte> Storage = Helper.Shared.GetSpan((ulong)TotalSize);
            Span<int> Offsets = stackalloc int[FieldCount];
            int Offset = 0;
            for (int Index = 0; Index < FieldCount; Index++)
            {
                if (Sizes[Index] != 0 && !Instance.ReadMemory(Locations[Index], Storage.Slice(Offset, Sizes[Index])))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                Offsets[Index] = Offset;
                Offset += Sizes[Index];
            }

            ReadOnlySpan<byte> Sacl = Storage.Slice(Offsets[SaclField], Sizes[SaclField]);
            ReadOnlySpan<byte> Dacl = Storage.Slice(Offsets[DaclField], Sizes[DaclField]);
            if (!AclIsValid(Sacl) || !AclIsValid(Dacl))
                return NTSTATUS.STATUS_INVALID_ACL;

            Captured = new Descriptor(Owner: Storage.Slice(Offsets[OwnerField], Sizes[OwnerField]), Group: Storage.Slice(Offsets[GroupField], Sizes[GroupField]),
                Dacl: Dacl, Sacl: Sacl);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static void WriteSelfRelativeHeader(Span<byte> Descriptor, ushort Control, int OwnerOffset, int GroupOffset, int DaclOffset)
        {
            Span<byte> Header = Descriptor.Slice(0, SelfRelativeHeaderSize);
            Header.Clear();
            Header[0] = SecurityDescriptorRevision;
            BinaryPrimitives.WriteUInt16LittleEndian(Header.Slice(OffControl), (ushort)(Control | SeSelfRelative));
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(FieldOffset(OwnerField)), (uint)OwnerOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(FieldOffset(GroupField)), (uint)GroupOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(FieldOffset(DaclField)), (uint)DaclOffset);
        }

        private static int FieldOffset(int Field) => sizeof(uint) * (1 + Field);

        private static NTSTATUS SidSize(BinaryEmulator Instance, ulong SidPtr, out int Size)
        {
            Size = 0;
            Span<byte> Head = stackalloc byte[2];
            if (!Instance.ReadMemory(SidPtr, Head))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            if (Head[0] != SidRevision || Head[1] > MaxSubAuthorities)
                return NTSTATUS.STATUS_INVALID_SID;
            Size = SidLength(Head[1]);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS ReadSid(BinaryEmulator Instance, ulong SidPtr, Span<byte> Buffer, out ReadOnlySpan<byte> Sid)
        {
            Sid = default;
            NTSTATUS Status = SidSize(Instance, SidPtr, out int Size);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Sid = Buffer.Slice(0, Size);
            return Instance.ReadMemory(SidPtr, Buffer.Slice(0, Size)) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        private static NTSTATUS AclSize(BinaryEmulator Instance, ulong AclPtr, out int Size)
        {
            Size = 0;
            Span<byte> Head = stackalloc byte[AclHeaderSize];
            if (!Instance.ReadMemory(AclPtr, Head))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            Size = BinaryPrimitives.ReadUInt16LittleEndian(Head.Slice(2));
            return Size < AclHeaderSize ? NTSTATUS.STATUS_INVALID_ACL : NTSTATUS.STATUS_SUCCESS;
        }

        private static bool AclIsValid(ReadOnlySpan<byte> Acl)
        {
            if (Acl.IsEmpty)
                return true;
            if (Acl[0] < AclRevision || Acl[0] > AclRevisionDs)
                return false;

            int AceCount = BinaryPrimitives.ReadUInt16LittleEndian(Acl.Slice(4));
            int Offset = AclHeaderSize;
            for (int Index = 0; Index < AceCount; Index++)
            {
                if (Offset + AceHeaderSize > Acl.Length)
                    return false;
                int AceSize = BinaryPrimitives.ReadUInt16LittleEndian(Acl.Slice(Offset + 2));
                if (AceSize < AceHeaderSize || (AceSize & 3) != 0 || Offset + AceSize > Acl.Length)
                    return false;
                Offset += AceSize;
            }

            return true;
        }

        // A lower token never gets a write right, whatever the label policy says (SepMandatoryIntegrityCheck).
        private static uint IntegrityAllowedMask(ReadOnlySpan<byte> Sacl, uint TokenRid, in GENERIC_MAPPING Mapping, out uint ObjectRid)
        {
            ObjectRid = MediumIntegrityRid;
            uint Policy = MandatoryNoWriteUp;
            foreach (Ace Entry in new AceWalker(Sacl))
            {
                if (Entry.Type != SystemMandatoryLabelAce)
                    continue;
                if ((Entry.Flags & InheritOnlyAce) != 0)
                    break;

                ReadOnlySpan<byte> Label = Entry.Sid;
                ObjectRid = Label[1] != 0 ? SubAuthority(Label, Label[1] - 1) : 0;
                Policy = Entry.Mask;
                break;
            }

            uint ReadOnly = Mapping.GenericRead | ReadControl;
            uint ExecuteOnly = (Mapping.GenericExecute & ~Mapping.GenericRead) | Synchronize;
            if (TokenRid >= ObjectRid)
                return ReadOnly | ExecuteOnly | Mapping.GenericAll | AccessSystemSecurity | StandardRightsAll | SpecificRightsAll;

            uint Allowed = 0;
            if ((Policy & MandatoryNoReadUp) == 0)
                Allowed |= ReadOnly;
            if ((Policy & MandatoryNoExecuteUp) == 0)
                Allowed |= ExecuteOnly;
            return Allowed;
        }

        private static bool OwnerRightsAcePresent(ReadOnlySpan<byte> Dacl)
        {
            foreach (Ace Entry in new AceWalker(Dacl))
            {
                if ((Entry.Flags & InheritOnlyAce) == 0 && Entry.Sid.SequenceEqual(OwnerRightsSid))
                    return true;
            }

            return false;
        }

        // NT needs the package and capability ACEs to cover an AppContainer's access as well (SepAccessCheck).
        private static NTSTATUS EvaluateDacl(in Descriptor Captured, ref Identity Client, scoped ReadOnlySpan<byte> Self, uint Desired, uint MapAll, ref uint Granted, out bool PackageMatched)
        {
            bool Maximum = (Desired & MaximumAllowed) != 0;
            bool AppContainer = Client.Token.IsAppContainer;
            PackageMatched = false;

            if (Captured.Dacl.IsEmpty)
            {
                if (AppContainer)
                    return NTSTATUS.STATUS_ACCESS_DENIED;

                Granted = Maximum ? MapAll | ((Granted | Desired) & ~MaximumAllowed) : Granted | Desired;
                return Granted == 0 ? NTSTATUS.STATUS_ACCESS_DENIED : NTSTATUS.STATUS_SUCCESS;
            }

            uint Requested = Desired & ~MaximumAllowed;
            uint PackageWanted = AppContainer ? (Maximum ? uint.MaxValue : Requested | Granted) : 0;
            uint Allowed = 0;
            uint Denied = 0;
            uint Remaining = Requested;
            uint PackageGranted = 0;
            foreach (Ace Entry in new AceWalker(Captured.Dacl))
            {
                if (!Maximum && Remaining == 0 && (PackageWanted & ~PackageGranted) == 0)
                    break;
                if ((Entry.Flags & InheritOnlyAce) != 0 || !Entry.AppliesToObject)
                    continue;

                // Conditions are not evaluated, so one that applies fails the check (SepNormalAccessCheck).
                if (Entry.Type == AccessAllowedCallbackAce)
                {
                    if (!Entry.HasCondition)
                        continue;

                    bool Applies = PackageWanted != 0 && IsPackageOrCapabilitySid(Entry.Sid)
                        ? PackageMatches(Entry.Sid, Client.Token)
                        : Matches(Entry.Sid, ref Client, Self, AllowGroups);
                    if (Applies)
                    {
                        Utils.LogError("[-] NtAccessCheck: a callback ACE with a condition applies to the client; conditions are not evaluated.");
                        return NTSTATUS.STATUS_NOT_IMPLEMENTED;
                    }

                    continue;
                }

                if (Entry.Allows)
                {
                    if (PackageWanted != 0 && IsPackageOrCapabilitySid(Entry.Sid))
                    {
                        if (PackageMatches(Entry.Sid, Client.Token))
                        {
                            PackageGranted |= Entry.Mask & PackageWanted;
                            PackageMatched = true;
                        }

                        continue;
                    }

                    if (Matches(Entry.Sid, ref Client, Self, AllowGroups))
                    {
                        Allowed |= Entry.Mask & ~Denied;
                        Remaining &= ~Entry.Mask;
                    }
                }
                else if (Entry.Denies && Matches(Entry.Sid, ref Client, Self, DenyGroups))
                {
                    if (!Maximum && (Entry.Mask & Remaining) != 0)
                        return NTSTATUS.STATUS_ACCESS_DENIED;
                    Denied |= Entry.Mask & ~Allowed;
                }
            }

            if (Maximum)
            {
                if (AppContainer)
                {
                    Allowed &= PackageGranted;
                    Granted &= PackageGranted;
                }

                if ((Requested & ~Allowed) != 0)
                    return NTSTATUS.STATUS_ACCESS_DENIED;

                Granted |= Allowed;
                return Granted == 0 ? NTSTATUS.STATUS_ACCESS_DENIED : NTSTATUS.STATUS_SUCCESS;
            }

            if (Remaining != 0 || (PackageWanted & ~PackageGranted) != 0)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            Granted |= Requested;
            return Granted == 0 ? NTSTATUS.STATUS_ACCESS_DENIED : NTSTATUS.STATUS_SUCCESS;
        }

        private static bool IsPackageOrCapabilitySid(ReadOnlySpan<byte> Sid)
        {
            return FirstSubAuthority(Sid, AppPackageAuthority) is AppPackageBaseRid or AppCapabilityBaseRid;
        }

        // NT matches both package groups for an AppContainer that is not less privileged (SepMatchPackage).
        private static bool PackageMatches(ReadOnlySpan<byte> AceSid, WinToken Token)
        {
            if (AceSid.SequenceEqual(AllApplicationPackagesSid) || AceSid.SequenceEqual(AllRestrictedApplicationPackagesSid)
                || AceSid.SequenceEqual(Token.AppContainerSid))
                return true;

            foreach (byte[] Capability in Token.CapabilitySids)
            {
                if (AceSid.SequenceEqual(Capability))
                    return true;
            }

            return false;
        }

        private static bool Matches(scoped ReadOnlySpan<byte> AceSid, ref Identity Client, scoped ReadOnlySpan<byte> Self, uint GroupAttributes)
        {
            if (!Self.IsEmpty && AceSid.SequenceEqual(PrincipalSelfSid))
                AceSid = Self;

            if (AceSid.SequenceEqual(OwnerRightsSid))
                return Client.IsOwner();

            return Client.Contains(AceSid, GroupAttributes);
        }

        private readonly ref struct Ace
        {
            internal readonly byte Type;
            internal readonly byte Flags;
            internal readonly uint Mask;
            internal readonly ReadOnlySpan<byte> Sid;
            internal readonly bool AppliesToObject;
            internal readonly bool HasCondition;

            internal Ace(byte Type, byte Flags, uint Mask, ReadOnlySpan<byte> Sid, bool AppliesToObject, bool HasCondition)
            {
                this.Type = Type;
                this.Flags = Flags;
                this.Mask = Mask;
                this.Sid = Sid;
                this.AppliesToObject = AppliesToObject;
                this.HasCondition = HasCondition;
            }

            internal bool Allows => Type is AccessAllowedAce or AccessAllowedObjectAce;
            internal bool Denies => Type is AccessDeniedAce or AccessDeniedObjectAce;
        }

        // The ACL must have passed AclIsValid. With no type list, NT skips object ACEs that name an object type.
        private ref struct AceWalker
        {
            private readonly ReadOnlySpan<byte> Acl;
            private int Offset;
            private int Left;
            private Ace CurrentAce;

            internal AceWalker(ReadOnlySpan<byte> Acl)
            {
                this.Acl = Acl;
                Offset = AclHeaderSize;
                Left = Acl.IsEmpty ? 0 : BinaryPrimitives.ReadUInt16LittleEndian(Acl.Slice(4));
            }

            public AceWalker GetEnumerator() => this;

            public Ace Current => CurrentAce;

            public bool MoveNext()
            {
                while (Left > 0)
                {
                    Left--;
                    ReadOnlySpan<byte> Entry = Acl.Slice(Offset, BinaryPrimitives.ReadUInt16LittleEndian(Acl.Slice(Offset + 2)));
                    Offset += Entry.Length;
                    if (Entry.Length < AceSidOffset)
                        continue;

                    byte Type = Entry[0];
                    int SidOffset = AceSidOffset;
                    bool Applies = true;
                    if (Type is AccessAllowedObjectAce or AccessDeniedObjectAce or AccessAllowedCallbackObjectAce or AccessDeniedCallbackObjectAce)
                    {
                        if (Entry.Length < AceSidOffset + ObjectAceFlagsSize)
                            continue;
                        uint ObjectFlags = BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(AceSidOffset));
                        SidOffset = AceSidOffset + ObjectAceFlagsSize + ((ObjectFlags & AceObjectTypePresent) != 0 ? ObjectTypeSize : 0)
                            + ((ObjectFlags & AceInheritedObjectTypePresent) != 0 ? ObjectTypeSize : 0);
                        Applies = (ObjectFlags & AceObjectTypePresent) == 0;
                    }
                    else if (Type is not (AccessAllowedAce or AccessDeniedAce or SystemMandatoryLabelAce or AccessAllowedCallbackAce or AccessDeniedCallbackAce))
                        continue;

                    if (SidOffset + SidLength(0) > Entry.Length)
                        continue;
                    int Length = SidLength(Entry[SidOffset + 1]);
                    if (SidOffset + Length > Entry.Length)
                        continue;

                    CurrentAce = new Ace(Type, Entry[1], BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(AceHeaderSize)), Entry.Slice(SidOffset, Length), Applies,
                        HasCondition: Entry.Length > SidOffset + Length);
                    return true;
                }

                return false;
            }
        }
    }
}
