using System.Linq;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtOpenProcessToken : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            bool Is64 = Instance._binary.Architecture == BinaryArchitecture.x64;

            ulong ProcessHandle;
            ulong DesiredAccess;
            ulong TokenHandlePtr;

            if (Is64)
            {
                ProcessHandle = Instance.WinHelper.GetArg64(0);
                DesiredAccess = (uint)Instance.WinHelper.GetArg64(1);
                TokenHandlePtr = Instance.WinHelper.GetArg64(2);

                if (TokenHandlePtr == 0 || !Instance.IsRegionMapped(TokenHandlePtr, 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }
            else
            {
                uint ESP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);

                ProcessHandle = Instance.ReadMemoryUInt(ESP + 4);
                DesiredAccess = Instance.ReadMemoryUInt(ESP + 8);
                TokenHandlePtr = Instance.ReadMemoryUInt(ESP + 12);

                if (TokenHandlePtr == 0 || !Instance.IsRegionMapped(TokenHandlePtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            WinProcess TargetProcess = null;

            if (ProcessHandle == ulong.MaxValue || ProcessHandle == uint.MaxValue)
            {
                TargetProcess = Instance.WinHelper.WinProcesses.FirstOrDefault(p => p.PID == Instance.WinHelper.PID);
            }
            else
            {
                if (!Instance.WinHelper.HandleExists(ProcessHandle, HandleType.ProcessHandle))
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                TargetProcess = Instance.WinHelper.HandleManager.GetObjectByHandle<WinProcess>(ProcessHandle);
                if (TargetProcess == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                if (Instance.WinHelper.WinProcesses.FirstOrDefault(p => p.PID == TargetProcess.PID) == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                bool HasQuery = Instance.WinHelper.HandleManager.CheckAccess(ProcessHandle, AccessMask.ProcessQueryInformation)
                    || Instance.WinHelper.HandleManager.CheckAccess(ProcessHandle, AccessMask.ProcessQueryLimitedInformation);

                if (!HasQuery)
                    return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            if (TargetProcess == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            WinToken Token = TargetProcess.PrimaryToken;
            if (Token == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(Token, MapDesiredTokenAccess((AccessMask)(uint)DesiredAccess));

            if (Is64)
            {
                if (!Instance._emulator.WriteMemory(TokenHandlePtr, (ulong)Handle.Handle))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }
            else
            {
                if (!Instance._emulator.WriteMemory(TokenHandlePtr, (uint)Handle.Handle))
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