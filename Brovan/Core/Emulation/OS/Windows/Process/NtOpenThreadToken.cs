using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenThreadToken : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            WinSysHelper Helper = Instance.WinHelper;
            if (Helper == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            ulong ThreadHandle = Instance.ReadRegister(Registers.UC_X86_REG_RCX);
            ulong DesiredAccess = Instance.WinHelper.GetArg(1);
            ulong OpenAsSelf = Instance.WinHelper.GetArg(2);
            ulong TokenHandlePtr = Instance.WinHelper.GetArg(3);

            if (TokenHandlePtr == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            EmulatedThread Thread = null;
            if (HandleManager.IsCurrentThreadPseudoHandle(ThreadHandle))
            {
                Thread = Instance.Threads.Values.FirstOrDefault(EmuThread => EmuThread.ThreadId == Instance.CurrentThreadId);
            }
            else
            {
                Thread = Helper.HandleManager.GetObjectByHandle<EmulatedThread>(ThreadHandle);
            }

            if (Thread == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            WinToken Token = WinEmulatedThread.GetState(Thread).ImpersonationToken;

            if (Token == null)
            {
                if (OpenAsSelf == 0)
                    return NTSTATUS.STATUS_NO_TOKEN;

                WinProcess Process = Helper.WinProcesses.FirstOrDefault(Proc => Proc.PID == Helper.PID);
                if (Process == null || Process.PrimaryToken == null)
                    return NTSTATUS.STATUS_NO_TOKEN;

                Token = new WinToken
                {
                    Type = TokenType.Impersonation,
                    SessionId = Process.PrimaryToken.SessionId,
                    IsElevated = Process.PrimaryToken.IsElevated,
                    IsRestricted = Process.PrimaryToken.IsRestricted,
                    EffectiveOnly = Process.PrimaryToken.EffectiveOnly,
                    ImpersonationLevel = SecurityImpersonationLevel.SecurityImpersonation,
                    OwningProcessId = Process.PrimaryToken.OwningProcessId,
                    OwningThreadId = (ulong)Thread.ThreadId
                };
            }

            var Handle = Helper.HandleManager.AddHandle(Token, MapDesiredTokenAccess((AccessMask)(uint)DesiredAccess) | AccessMask.TokenDuplicate);
            Instance._emulator.WriteMemory(TokenHandlePtr, Handle.Handle, 8);

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