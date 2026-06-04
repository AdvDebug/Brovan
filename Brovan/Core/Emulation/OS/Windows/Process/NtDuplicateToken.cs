using System.Linq;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtDuplicateToken : IWinSyscall
    {
        private const uint OBJ_PROTECT_CLOSE = 0x00000001;
        private const uint OBJ_INHERIT = 0x00000002;
        private const uint TokenPrimary = 1;
        private const uint TokenImpersonation = 2;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            bool Is64 = Instance._binary.Architecture == BinaryArchitecture.x64;

            ulong ExistingTokenHandle;
            ulong DesiredAccess;
            ulong ObjectAttributesPtr;
            bool EffectiveOnly;
            uint RequestedTokenType;
            ulong NewTokenHandlePtr;

            if (Is64)
            {
                ExistingTokenHandle = Instance.WinHelper.GetArg64(0);
                DesiredAccess = (uint)Instance.WinHelper.GetArg64(1);
                ObjectAttributesPtr = Instance.WinHelper.GetArg64(2);
                EffectiveOnly = (uint)Instance.WinHelper.GetArg64(3) != 0;
                RequestedTokenType = (uint)Instance.WinHelper.GetArg64(4);
                NewTokenHandlePtr = Instance.WinHelper.GetArg64(5);
            }
            else
            {
                ExistingTokenHandle = Instance.WinHelper.GetArg32(0);
                DesiredAccess = Instance.WinHelper.GetArg32(1);
                ObjectAttributesPtr = Instance.WinHelper.GetArg32(2);
                EffectiveOnly = Instance.WinHelper.GetArg32(3) != 0;
                RequestedTokenType = Instance.WinHelper.GetArg32(4);
                NewTokenHandlePtr = Instance.WinHelper.GetArg32(5);
            }

            uint HandleSize = Is64 ? 8u : 4u;
            if (NewTokenHandlePtr == 0 || !Instance.IsRegionMapped(NewTokenHandlePtr, HandleSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (RequestedTokenType != TokenPrimary && RequestedTokenType != TokenImpersonation)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!TryResolveToken(Instance, ExistingTokenHandle, out WinToken SourceToken, out AccessMask SourceAccess))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (!HasTokenDuplicateAccess(SourceToken, SourceAccess))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            NTSTATUS Status = ReadObjectAttributes(Instance, ObjectAttributesPtr, Is64, out uint HandleAttributes, out SecurityImpersonationLevel ImpersonationLevel);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            AccessMask NewAccess = MapDesiredTokenAccess((AccessMask)(uint)DesiredAccess, SourceAccess);
            WinToken NewToken = new WinToken
            {
                Type = RequestedTokenType == TokenPrimary ? TokenType.Primary : TokenType.Impersonation,
                SessionId = SourceToken.SessionId,
                IsElevated = SourceToken.IsElevated,
                IsRestricted = SourceToken.IsRestricted,
                EffectiveOnly = EffectiveOnly,
                ImpersonationLevel = ImpersonationLevel,
                OwningProcessId = SourceToken.OwningProcessId,
                OwningThreadId = SourceToken.OwningThreadId
            };

            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(NewToken, NewAccess);
            Instance.WinHelper.HandleManager.SetHandleFlags(Handle.Handle, ConvertObjectHandleAttributes(HandleAttributes));
            Instance.WinHelper.WinHandles.Add(Handle);

            bool Written = Is64
                ? Instance._emulator.WriteMemory(NewTokenHandlePtr, Handle.Handle, 8)
                : Instance._emulator.WriteMemory(NewTokenHandlePtr, (uint)Handle.Handle, 4);

            if (!Written)
            {
                Instance.WinHelper.CloseHandle(Handle.Handle);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            Instance.TriggerEventMessage($"[+] NtDuplicateToken: Token=0x{ExistingTokenHandle:X} -> 0x{Handle.Handle:X}, Type={NewToken.Type}, Access=0x{(uint)NewAccess:X}.", LogFlags.Syscall);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool TryResolveToken(BinaryEmulator Instance, ulong TokenHandle, out WinToken Token, out AccessMask Access)
        {
            Token = null;
            Access = AccessMask.None;

            long SignedHandle = Instance._binary.Architecture == BinaryArchitecture.x64
                ? unchecked((long)TokenHandle)
                : unchecked((int)(uint)TokenHandle);

            if (SignedHandle == -4 || SignedHandle == -5 || SignedHandle == -6)
            {
                WinProcess CurrentProcess = Instance.WinHelper.WinProcesses.FirstOrDefault(Process => Process.PID == Instance.WinHelper.PID);
                WinToken ProcessToken = CurrentProcess?.PrimaryToken;

                EmulatedThread CurrentThread = Instance.Threads.Values.FirstOrDefault(Thread => Thread.ThreadId == Instance.CurrentThreadId);
                WinToken ThreadToken = WinEmulatedThread.TryGetState(CurrentThread)?.ImpersonationToken;

                if (SignedHandle == -4)
                    Token = ProcessToken;
                else if (SignedHandle == -5)
                    Token = ThreadToken;
                else
                    Token = ThreadToken ?? ProcessToken;

                Access = AccessMask.TokenAllAccess;
                return Token != null;
            }

            if (!Instance.WinHelper.HandleManager.HandleExists(TokenHandle, HandleType.TokenHandle))
                return false;

            Token = Instance.WinHelper.HandleManager.GetObjectByHandle<WinToken>(TokenHandle);
            if (Token == null)
                return false;

            Access = Instance.WinHelper.HandleManager.GetPermissionsByHandle(TokenHandle);
            return true;
        }

        private static bool HasTokenDuplicateAccess(WinToken Token, AccessMask Access)
        {
            if (Access == AccessMask.GiveTemp)
                return true;

            if ((Access & AccessMask.GenericAll) != 0)
                return true;

            if ((Access & AccessMask.MaximumAllowed) != 0)
                return true;

            if ((Access & AccessMask.TokenAllAccess) == AccessMask.TokenAllAccess)
                return true;

            if ((Access & AccessMask.TokenDuplicate) == AccessMask.TokenDuplicate)
                return true;

            AccessMask UsableAccess = AccessMask.TokenImpersonate | AccessMask.TokenQuery | AccessMask.TokenAssignPrimary;
            return (Access & UsableAccess) != 0;
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

        private static NTSTATUS ReadObjectAttributes(BinaryEmulator Instance, ulong ObjectAttributesPtr, bool Is64, out uint HandleAttributes, out SecurityImpersonationLevel ImpersonationLevel)
        {
            HandleAttributes = 0;
            ImpersonationLevel = SecurityImpersonationLevel.SecurityImpersonation;

            if (ObjectAttributesPtr == 0)
                return NTSTATUS.STATUS_SUCCESS;

            uint ObjectAttributesSize = Is64 ? 0x30u : 0x18u;
            if (!Instance.IsRegionMapped(ObjectAttributesPtr, ObjectAttributesSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            HandleAttributes = Is64
                ? Instance._emulator.ReadMemoryUInt(ObjectAttributesPtr + 0x18)
                : Instance._emulator.ReadMemoryUInt(ObjectAttributesPtr + 0x0C);

            ulong SecurityQosPtr = Is64
                ? Instance._emulator.ReadMemoryULong(ObjectAttributesPtr + 0x28)
                : Instance._emulator.ReadMemoryUInt(ObjectAttributesPtr + 0x14);

            if (SecurityQosPtr == 0)
                return NTSTATUS.STATUS_SUCCESS;

            const uint SecurityQosMinimumSize = 0x0C;
            if (!Instance.IsRegionMapped(SecurityQosPtr, SecurityQosMinimumSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint Length = Instance._emulator.ReadMemoryUInt(SecurityQosPtr);
            if (Length < SecurityQosMinimumSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Level = Instance._emulator.ReadMemoryUInt(SecurityQosPtr + 0x04);
            if (Level <= (uint)SecurityImpersonationLevel.SecurityDelegation)
                ImpersonationLevel = (SecurityImpersonationLevel)Level;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static ObjectHandleFlags ConvertObjectHandleAttributes(uint HandleAttributes)
        {
            ObjectHandleFlags Flags = ObjectHandleFlags.None;

            if ((HandleAttributes & OBJ_INHERIT) != 0)
                Flags |= ObjectHandleFlags.Inherit;

            if ((HandleAttributes & OBJ_PROTECT_CLOSE) != 0)
                Flags |= ObjectHandleFlags.ProtectFromClose;

            return Flags;
        }
    }
}
