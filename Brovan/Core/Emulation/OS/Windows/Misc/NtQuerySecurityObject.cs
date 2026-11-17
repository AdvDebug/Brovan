using static Brovan.Core.Emulation.OS.Windows.NtQueryInformationToken;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtQuerySecurityObject : IWinSyscall
    {
        private const uint OwnerSecurityInformation = 0x00000001;
        private const uint GroupSecurityInformation = 0x00000002;
        private const uint DaclSecurityInformation = 0x00000004;
        private const uint LabelSecurityInformation = 0x00000010;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Handle = Instance.WinHelper.GetArg(0);
            uint SecurityInformation = (uint)Instance.WinHelper.GetArg(1);
            ulong SecurityDescriptorPtr = Instance.WinHelper.GetArg(2);
            uint Length = (uint)Instance.WinHelper.GetArg(3);
            ulong LengthNeededPtr = Instance.WinHelper.GetArg(4);

            return QuerySecurityObject(Instance, Handle, SecurityInformation, SecurityDescriptorPtr, Length, LengthNeededPtr);
        }

        private static NTSTATUS QuerySecurityObject(BinaryEmulator Instance, ulong Handle, uint SecurityInformation, ulong SecurityDescriptorPtr, uint Length, ulong LengthNeededPtr)
        {
            bool Found = Instance.WinHelper.HandleManager.TryGetHandle(Handle, out HandleEntry Entry);
            if (!Found && !IsSpecialHandle(Handle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (SecurityInformation == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            // Brovan keeps no descriptor per object, so it reports what a new object would get, with a NULL DACL.
            bool HasDescriptor = Entry.Object == null || HasSecurityDescriptor(Instance, Entry.Object);
            byte[]? Owner = null;
            byte[]? Group = null;
            if (HasDescriptor && (SecurityInformation & (OwnerSecurityInformation | GroupSecurityInformation)) != 0)
            {
                WinToken Token = Instance.WinHelper.OwnProcess.GetPrimaryToken();
                if ((SecurityInformation & OwnerSecurityInformation) != 0)
                    Owner = UserSidOf(Token);
                if ((SecurityInformation & GroupSecurityInformation) != 0)
                    Group = PrimaryGroupOf(Token);
            }

            byte[]? Sacl = HasDescriptor && (SecurityInformation & LabelSecurityInformation) != 0 ? LabelAclOf(Instance, Handle, Entry.Object) : null;

            // NT places the owner, the group, the DACL and then the SACL after the header (SeQuerySecurityDescriptorInfo).
            int OwnerOffset = NtAccessCheck.SelfRelativeHeaderSize;
            int GroupOffset = OwnerOffset + (Owner?.Length ?? 0);
            int SaclOffset = GroupOffset + (Group?.Length ?? 0);
            int Required = SaclOffset + (Sacl?.Length ?? 0);
            if (LengthNeededPtr != 0 && !Instance.WinHelper.WriteUInt32(LengthNeededPtr, (uint)Required))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Length < Required)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            if (SecurityDescriptorPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsMemoryRangeMapped(SecurityDescriptorPtr, (ulong)Required))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ushort Control = HasDescriptor && (SecurityInformation & DaclSecurityInformation) != 0 ? NtAccessCheck.SeDaclPresent : (ushort)0;
            if (Sacl != null)
                Control |= NtAccessCheck.SeSaclPresent | NtAccessCheck.SeSaclAutoInherited;

            Span<byte> SecurityDescriptor = stackalloc byte[Required];
            NtAccessCheck.WriteSelfRelativeHeader(SecurityDescriptor, Control, OwnerOffset: Owner == null ? 0 : OwnerOffset, GroupOffset: Group == null ? 0 : GroupOffset,
                DaclOffset: 0, SaclOffset: Sacl == null ? 0 : SaclOffset);
            Owner?.CopyTo(SecurityDescriptor.Slice(OwnerOffset));
            Group?.CopyTo(SecurityDescriptor.Slice(GroupOffset));
            Sacl?.CopyTo(SecurityDescriptor.Slice(SaclOffset));

            if (!Instance.WriteMemory(SecurityDescriptorPtr, SecurityDescriptor))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"NtQuerySecurityObject: Handle=0x{Handle:X}, SecurityInformation=0x{SecurityInformation:X}, Length=0x{Length:X}.", LogFlags.Syscall);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool IsSpecialHandle(ulong Handle)
        {
            return HandleManager.IsCurrentProcessPseudoHandle(Handle) ||
                   HandleManager.IsCurrentThreadPseudoHandle(Handle) ||
                   Handle == uint.MaxValue ||
                   Handle == HandleManager.KNOWN_DLLS_DIRECTORY ||
                   Handle == HandleManager.KNOWN_DLLS32_DIRECTORY ||
                   Handle == HandleManager.RPC_CONTROL_DIRECTORY;
        }

        // NT labels a token NO_WRITE_UP and a process or thread NO_WRITE_UP | NO_READ_UP, at the integrity level of
        // the token. Other objects that a medium process creates carry no label.
        private static byte[]? LabelAclOf(BinaryEmulator Instance, ulong Handle, IHandleObject? Object)
        {
            uint Policy = NtAccessCheck.MandatoryNoWriteUp | NtAccessCheck.MandatoryNoReadUp;
            WinToken? Token = null;
            if (Object is WinToken Labelled)
            {
                Token = Labelled;
                Policy = NtAccessCheck.MandatoryNoWriteUp;
            }
            else if (Object is WinProcess Process)
                Token = Process.GetPrimaryToken();
            else if (Object is WinRemoteThread { Process: { } Remote })
                Token = ProcessOf(Instance, Remote)?.GetPrimaryToken();
            else if (Object is EmulatedThread || HandleManager.IsCurrentProcessPseudoHandle(Handle) || HandleManager.IsCurrentThreadPseudoHandle(Handle))
                Token = Instance.WinHelper.OwnProcess.GetPrimaryToken();

            if (Token == null)
                return null;

            return NtAccessCheck.BuildAcl(NtAccessCheck.AceEntry.MandatoryLabel(LabelSidOf(IntegrityRidOf(Token)), Policy));
        }

        private static WinProcess? ProcessOf(BinaryEmulator Instance, RemoteGuestProcess Remote)
        {
            foreach (WinProcess Process in Instance.WinHelper.WinProcesses)
            {
                if (Process.Remote == Remote)
                    return Process;
            }

            return null;
        }

        // NT gives an object a descriptor only when its type requires one or the object has a name.
        private static bool HasSecurityDescriptor(BinaryEmulator Instance, IHandleObject Object)
        {
            return Object.ObjectType is HandleType.ProcessHandle or HandleType.ThreadHandle or HandleType.TokenHandle or HandleType.FileHandle
                       or HandleType.RegistryKeyHandle or HandleType.JobHandle or HandleType.DirectoryHandle
                   || Instance.WinHelper.IsNamedObject(Object);
        }
    }
}
