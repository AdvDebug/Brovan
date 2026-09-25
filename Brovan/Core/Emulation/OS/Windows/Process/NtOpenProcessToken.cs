using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtOpenProcessToken : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            return Open(Instance, 2);
        }

        internal static NTSTATUS Open(BinaryEmulator Instance, int TokenHandleArgIndex)
        {
            ulong ProcessHandle = Instance.WinHelper.GetArg(0);
            AccessMask DesiredAccess = (AccessMask)(uint)Instance.WinHelper.GetArg(1);
            ulong TokenHandlePtr = Instance.WinHelper.GetArg(TokenHandleArgIndex);

            if (TokenHandlePtr == 0 || !Instance.IsRegionMapped(TokenHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = Instance.WinHelper.ResolveProcessHandle(ProcessHandle, AccessMask.ProcessQueryLimitedInformation, out WinProcess TargetProcess);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (DesiredAccess == AccessMask.None || TargetProcess.RunningUser != Instance.WinHelper.CurrentUser)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            TargetProcess.PrimaryToken ??= new WinToken { Type = TokenType.Primary, SessionId = 1, OwningProcessId = TargetProcess.PID };

            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(TargetProcess.PrimaryToken, MapDesiredTokenAccess(DesiredAccess));
            if (!Instance.WinHelper.WritePointer(TokenHandlePtr, Handle.Handle))
            {
                Instance.WinHelper.CloseHandle(Handle.Handle);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static AccessMask MapDesiredTokenAccess(AccessMask DesiredAccess)
        {
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
    }
}
