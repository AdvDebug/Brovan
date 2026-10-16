using static Brovan.Core.Emulation.OS.Windows.NtQueryInformationToken;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtQuerySecurityObject : IWinSyscall
    {
        private const uint OwnerSecurityInformation = 0x00000001;
        private const uint GroupSecurityInformation = 0x00000002;
        private const uint DaclSecurityInformation = 0x00000004;

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
                WinProcess TokenOwner = OwnerOf(Instance, Token);
                if ((SecurityInformation & OwnerSecurityInformation) != 0)
                    Owner = UserSidOf(Token, TokenOwner);
                if ((SecurityInformation & GroupSecurityInformation) != 0)
                    Group = PrimaryGroupOf(Token, TokenOwner);
            }

            // NT places the owner and then the group after the header (SeQuerySecurityDescriptorInfo).
            int OwnerOffset = NtAccessCheck.SelfRelativeHeaderSize;
            int GroupOffset = OwnerOffset + (Owner?.Length ?? 0);
            int Required = GroupOffset + (Group?.Length ?? 0);
            if (LengthNeededPtr != 0 && !Instance.WinHelper.WriteUInt32(LengthNeededPtr, (uint)Required))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Length < Required)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            if (SecurityDescriptorPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsMemoryRangeMapped(SecurityDescriptorPtr, (ulong)Required))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ushort Control = HasDescriptor && (SecurityInformation & DaclSecurityInformation) != 0 ? NtAccessCheck.SeDaclPresent : (ushort)0;
            Span<byte> SecurityDescriptor = stackalloc byte[NtAccessCheck.SelfRelativeHeaderSize + 2 * SidLength(MaxSubAuthorities)];
            SecurityDescriptor = SecurityDescriptor.Slice(0, Required);
            NtAccessCheck.WriteSelfRelativeHeader(SecurityDescriptor, Control, OwnerOffset: Owner == null ? 0 : OwnerOffset, GroupOffset: Group == null ? 0 : GroupOffset,
                DaclOffset: 0);
            Owner?.CopyTo(SecurityDescriptor.Slice(OwnerOffset));
            Group?.CopyTo(SecurityDescriptor.Slice(GroupOffset));

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

        // NT gives an object a descriptor only when its type requires one or the object has a name.
        private static bool HasSecurityDescriptor(BinaryEmulator Instance, IHandleObject Object)
        {
            return Object.ObjectType is HandleType.ProcessHandle or HandleType.ThreadHandle or HandleType.TokenHandle or HandleType.FileHandle
                       or HandleType.RegistryKeyHandle or HandleType.JobHandle or HandleType.DirectoryHandle
                   || Instance.WinHelper.IsNamedObject(Object);
        }
    }
}
