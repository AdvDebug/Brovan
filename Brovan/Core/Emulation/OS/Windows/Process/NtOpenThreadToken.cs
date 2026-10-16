namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenThreadToken : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            WinSysHelper Helper = Instance.WinHelper;
            return Open(Instance, ThreadHandle: Helper.GetArg(0), DesiredAccess: (uint)Helper.GetArg(1), OpenAsSelf: (byte)Helper.GetArg(2) != 0, HandleAttributes: 0, TokenHandlePtr: Helper.GetArg(3));
        }

        internal static NTSTATUS Open(BinaryEmulator Instance, ulong ThreadHandle, uint DesiredAccess, bool OpenAsSelf, uint HandleAttributes, ulong TokenHandlePtr)
        {
            WinSysHelper Helper = Instance.WinHelper;
            if (TokenHandlePtr == 0 || !Instance.IsRegionMapped(TokenHandlePtr, (ulong)Helper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            EmulatedThread Thread = WindowsThreadContext64.ResolveThread(Instance, ThreadHandle);
            if (Thread == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (!WindowsThreadContext64.HasThreadAccess(Instance, ThreadHandle, AccessMask.ThreadQueryLimitedInformation))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            WinToken Token = WinEmulatedThread.TryGetState(Thread)?.ImpersonationToken;

            if (Token == null)
                return NTSTATUS.STATUS_NO_TOKEN;

            if (Token.ImpersonationLevel == SecurityImpersonationLevel.SecurityAnonymous)
                return NTSTATUS.STATUS_CANT_OPEN_ANONYMOUS;

            // Without OpenAsSelf, NT checks under the caller's impersonation token (SeAccessCheckWithHint).
            WinToken CallerToken = OpenAsSelf ? null : NtQueryInformationToken.CallerImpersonationToken(Instance);
            if (CallerToken != null && CallerToken.ImpersonationLevel < SecurityImpersonationLevel.SecurityImpersonation)
                return NTSTATUS.STATUS_BAD_IMPERSONATION_LEVEL;

            ObjectHandleFlags Flags = (HandleAttributes & WinSysHelper.OBJ_INHERIT) != 0 ? ObjectHandleFlags.Inherit : ObjectHandleFlags.None;
            WinHandle Handle = Helper.HandleManager.AddHandle(Token, MapDesiredTokenAccess((AccessMask)DesiredAccess) | AccessMask.TokenDuplicate, Flags);

            if (!Helper.WritePointer(TokenHandlePtr, Handle.Handle))
            {
                Helper.CloseHandle(Handle.Handle);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static AccessMask MapDesiredTokenAccess(AccessMask DesiredAccess)
        {
            if (DesiredAccess == AccessMask.None || (DesiredAccess & AccessMask.MaximumAllowed) != 0 || (DesiredAccess & AccessMask.GenericAll) != 0)
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

    }
}
