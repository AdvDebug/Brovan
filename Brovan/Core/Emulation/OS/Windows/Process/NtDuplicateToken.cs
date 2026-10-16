using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtDuplicateToken : IWinSyscall
    {
        private const uint TokenPrimary = 1;
        private const uint TokenImpersonation = 2;

        private const int SecurityQosField = 5;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ExistingTokenHandle = Instance.WinHelper.GetArg(0);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);
            bool EffectiveOnly = (byte)Instance.WinHelper.GetArg(3) != 0;
            uint RequestedTokenType = (uint)Instance.WinHelper.GetArg(4);
            ulong NewTokenHandlePtr = Instance.WinHelper.GetArg(5);

            if (RequestedTokenType != TokenPrimary && RequestedTokenType != TokenImpersonation)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint HandleSize = (uint)Instance.WinHelper.PointerSize;
            if (NewTokenHandlePtr == 0 || !Instance.IsRegionMapped(NewTokenHandlePtr, HandleSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = CaptureSecurityQos(Instance, ObjectAttributesPtr, out SecurityImpersonationLevel? RequestedLevel);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            // NT references the source with ObReferenceObjectByHandle, which knows no token pseudo handles.
            Status = Instance.WinHelper.ReferenceObjectByHandle(ExistingTokenHandle, AccessMask.TokenDuplicate, out WinToken SourceToken, out _, out AccessMask SourceAccess);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            // NT gives a copy without a QoS the level of its source, and a primary source counts as anonymous.
            TokenType NewType = RequestedTokenType == TokenPrimary ? TokenType.Primary : TokenType.Impersonation;
            bool SourceImpersonates = SourceToken.Type == TokenType.Impersonation;
            SecurityImpersonationLevel SourceLevel = SourceImpersonates ? SourceToken.ImpersonationLevel : SecurityImpersonationLevel.SecurityAnonymous;
            SecurityImpersonationLevel ImpersonationLevel = RequestedLevel ?? SourceLevel;
            bool LevelAllowed = NewType == TokenType.Impersonation ? ImpersonationLevel <= SourceLevel : SourceLevel >= SecurityImpersonationLevel.SecurityImpersonation;
            if (SourceImpersonates && !LevelAllowed)
                return NTSTATUS.STATUS_BAD_IMPERSONATION_LEVEL;

            // NT checks the object attributes when it creates the copy (ObCreateObjectEx).
            Status = Instance.WinHelper.ReadCreateObjectName(ObjectAttributesPtr, out _, out uint HandleAttributes);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            AccessMask NewAccess = MapDesiredTokenAccess((AccessMask)(uint)DesiredAccess, SourceAccess);
            WinToken NewToken = SourceToken.Duplicate(NewType, ImpersonationLevel, EffectiveOnly);

            WinHandle Handle = Instance.WinHelper.OpenObjectHandle(NewToken, NewAccess, WinSysHelper.HandleFlagsOf(HandleAttributes));
            if (!Instance.WinHelper.WritePointer(NewTokenHandlePtr, Handle.Handle))
            {
                Instance.WinHelper.CloseHandle(Handle.Handle);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtDuplicateToken: Token=0x{ExistingTokenHandle:X} -> 0x{Handle.Handle:X}, Type={NewToken.Type}, Access=0x{(uint)NewAccess:X}.", LogFlags.Syscall);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static AccessMask MapDesiredTokenAccess(AccessMask DesiredAccess, AccessMask SourceAccess)
        {
            if (DesiredAccess == AccessMask.None)
                return SourceAccess == AccessMask.None ? AccessMask.TokenAllAccess : SourceAccess;

            if ((DesiredAccess & AccessMask.MaximumAllowed) != 0 || (DesiredAccess & AccessMask.GenericAll) != 0)
                return AccessMask.TokenAllAccess;

            AccessMask Mapped = DesiredAccess;
            if ((Mapped & AccessMask.GenericRead) != 0)
                Mapped = (Mapped & ~AccessMask.GenericRead) | AccessMask.TokenQuery | AccessMask.ReadControl;
            if ((Mapped & AccessMask.GenericWrite) != 0)
                Mapped = (Mapped & ~AccessMask.GenericWrite) | AccessMask.TokenAdjustPrivileges | AccessMask.TokenAdjustGroups | AccessMask.TokenAdjustDefault | AccessMask.TokenAdjustSessionId | AccessMask.ReadControl;
            if ((Mapped & AccessMask.GenericExecute) != 0)
                Mapped = (Mapped & ~AccessMask.GenericExecute) | AccessMask.TokenImpersonate | AccessMask.ReadControl;

            return Mapped;
        }

        // NT checks the length before it copies the QoS (SeCaptureSecurityQos).
        private static NTSTATUS CaptureSecurityQos(BinaryEmulator Instance, ulong ObjectAttributesPtr, out SecurityImpersonationLevel? ImpersonationLevel)
        {
            ImpersonationLevel = null;
            if (ObjectAttributesPtr == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if ((ObjectAttributesPtr & 3) != 0)
                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

            uint PointerSize = (uint)Instance.WinHelper.PointerSize;
            Span<byte> Field = stackalloc byte[sizeof(ulong)];
            if (!Instance.ReadMemory(ObjectAttributesPtr + SecurityQosField * PointerSize, Field.Slice(0, (int)PointerSize)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong SecurityQosPtr = WinSysHelper.ReadPointerField(Field, 0, PointerSize);
            if (SecurityQosPtr == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if ((SecurityQosPtr & 3) != 0)
                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

            Span<byte> Qos = stackalloc byte[SecurityQos.Size];
            if (!Instance.ReadMemory(SecurityQosPtr, Qos.Slice(0, sizeof(uint))))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (BinaryPrimitives.ReadUInt32LittleEndian(Qos) != SecurityQos.Size)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.ReadMemory(SecurityQosPtr + sizeof(uint), Qos.Slice(sizeof(uint))))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = SecurityQos.Read(Qos, out SecurityQos Captured);
            if (Status == NTSTATUS.STATUS_SUCCESS)
                ImpersonationLevel = Captured.Level;
            return Status;
        }
    }
}
