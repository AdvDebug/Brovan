using System;
using System.Linq;
using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtQueryInformationToken : IWinSyscall
    {
        private const uint SeGroupEnabled = 0x4;
        private const uint SeGroupIntegrityEnabled = 0x20;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            bool Is64 = Instance._binary.Architecture == BinaryArchitecture.x64;

            ulong TokenHandle;
            uint TokenInformationClass;
            ulong TokenInformation;
            uint TokenInformationLength;
            ulong ReturnLengthPtr;

            if (Is64)
            {
                TokenHandle = Instance.WinHelper.GetArg(0);
                TokenInformationClass = (uint)Instance.WinHelper.GetArg(1);
                TokenInformation = Instance.WinHelper.GetArg(2);
                TokenInformationLength = (uint)Instance.WinHelper.GetArg(3);
                ReturnLengthPtr = Instance.WinHelper.GetArg(4);
            }
            else
            {
                TokenHandle = (uint)Instance.WinHelper.GetArg(0);
                TokenInformationClass = (uint)Instance.WinHelper.GetArg(1);
                TokenInformation = (uint)Instance.WinHelper.GetArg(2);
                TokenInformationLength = (uint)Instance.WinHelper.GetArg(3);
                ReturnLengthPtr = (uint)Instance.WinHelper.GetArg(4);
            }

            if (ReturnLengthPtr != 0 && !Instance.IsRegionMapped(ReturnLengthPtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (TokenInformation != 0 && TokenInformationLength != 0)
            {
                if (!Instance.IsRegionMapped(TokenInformation, TokenInformationLength))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            NTSTATUS ResolveStatus = ResolveToken(Instance, TokenHandle, out WinToken Token);
            if (ResolveStatus != NTSTATUS.STATUS_SUCCESS)
                return ResolveStatus;

            void WriteReturnLength(uint Length)
            {
                if (ReturnLengthPtr != 0)
                    Instance._emulator.WriteMemory(ReturnLengthPtr, Length);
            }

            static byte[] SidLocalSystem() => BuildSid(1, 5, 18);
            static byte[] SidIntegrity(uint Rid) => BuildSid(1, 16, Rid);

            WinProcess OwnerProcess = Instance.WinHelper.WinProcesses.FirstOrDefault(p => p.PID == (uint)Token.OwningProcessId);

            byte[] UserSid = InteractiveUserSid();
            if (Token.IsAnonymous)
            {
                UserSid = BuildSid(1, 5, 7);
            }
            else if (OwnerProcess != null)
            {
                if (OwnerProcess.RunningUser == User.System || OwnerProcess.RunningUser == User.LocalService || OwnerProcess.RunningUser == User.WindowManager)
                    UserSid = SidLocalSystem();
            }

            uint IntegrityRid = 0x2000;
            if (Token.IsAnonymous)
                IntegrityRid = 0;
            else if (Token.IsAppContainer)
                IntegrityRid = 0x1000;
            else if (OwnerProcess != null)
            {
                if (OwnerProcess.RunningUser == User.System || OwnerProcess.RunningUser == User.LocalService || OwnerProcess.RunningUser == User.WindowManager)
                    IntegrityRid = 0x4000;
                else if (Token.IsElevated || OwnerProcess.RunningUser == User.Admin)
                    IntegrityRid = 0x3000;
            }

            uint PointerSize = (uint)Instance.WinHelper.PointerSize;

            uint AlignPointer(uint Value)
            {
                uint Mask = PointerSize - 1;
                return (Value + Mask) & ~Mask;
            }

            void WritePointer(Span<byte> Buffer, int Offset, ulong Value)
            {
                if (Is64)
                    BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(Offset, 8), Value);
                else
                    BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(Offset, 4), (uint)Value);
            }

            NTSTATUS WriteUInt32Info(uint Value)
            {
                const uint RequiredSize = 4;
                WriteReturnLength(RequiredSize);

                if (TokenInformationLength < RequiredSize)
                    return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                if (!Instance._emulator.WriteMemory(TokenInformation, Value))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            NTSTATUS WriteEmptyCountedInfo()
            {
                const uint RequiredSize = 4;
                WriteReturnLength(RequiredSize);

                if (TokenInformationLength < RequiredSize)
                    return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                if (!Instance._emulator.WriteMemory(TokenInformation, 0u))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            NTSTATUS WritePointerOnlyInfo(ulong Value = 0)
            {
                uint RequiredSize = PointerSize;
                WriteReturnLength(RequiredSize);

                if (TokenInformationLength < RequiredSize)
                    return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(RequiredSize);
                Buffer.Clear();
                WritePointer(Buffer, 0, Value);

                if (!Instance.WriteMemory(TokenInformation, Buffer))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            NTSTATUS WriteSidPointerInfo(byte[] Sid)
            {
                uint SidOffset = AlignPointer(PointerSize);
                uint RequiredSize = SidOffset + (uint)Sid.Length;
                WriteReturnLength(RequiredSize);

                if (TokenInformationLength < RequiredSize)
                    return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(RequiredSize);
                Buffer.Clear();
                WritePointer(Buffer, 0, TokenInformation + SidOffset);
                Sid.AsSpan().CopyTo(Buffer.Slice((int)SidOffset, Sid.Length));

                if (!Instance.WriteMemory(TokenInformation, Buffer))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            // SID_AND_ATTRIBUTES keeps the SID on an 8 byte boundary on both architectures.
            NTSTATUS WriteSidAndAttributesInfo(byte[] Sid, uint Attributes)
            {
                uint SidOffset = (PointerSize + 4 + 7u) & ~7u;
                uint RequiredSize = SidOffset + (uint)Sid.Length;
                WriteReturnLength(RequiredSize);

                if (TokenInformationLength < RequiredSize)
                    return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(RequiredSize);
                Buffer.Clear();
                WritePointer(Buffer, 0, TokenInformation + SidOffset);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice((int)PointerSize, 4), Attributes);
                Sid.AsSpan().CopyTo(Buffer.Slice((int)SidOffset, Sid.Length));

                if (!Instance.WriteMemory(TokenInformation, Buffer))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            NTSTATUS WriteSecurityAttributesInfo(WinTokenSecurityAttribute[] Attributes)
            {
                uint RequiredSize = NtQuerySecurityAttributesToken.GetAttributesInformationSize(Attributes, Is64);
                WriteReturnLength(RequiredSize);

                if (TokenInformationLength < RequiredSize)
                    return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(RequiredSize);
                NtQuerySecurityAttributesToken.WriteAttributesInformation(Buffer.Slice(0, (int)RequiredSize), TokenInformation, Attributes, Is64);

                if (!Instance.WriteMemory(TokenInformation, Buffer.Slice(0, (int)RequiredSize)))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            // TOKEN_GROUPS, with the SIDs after the array.
            NTSTATUS WriteSidGroupsInfo(byte[][] Sids)
            {
                uint EntrySize = PointerSize * 2;
                uint ArrayOffset = PointerSize;
                uint SidOffset = ArrayOffset + EntrySize * (uint)Sids.Length;
                uint RequiredSize = SidOffset;
                foreach (byte[] Sid in Sids)
                    RequiredSize += (uint)Sid.Length;

                WriteReturnLength(RequiredSize);
                if (TokenInformationLength < RequiredSize)
                    return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(RequiredSize);
                Buffer.Slice(0, (int)RequiredSize).Clear();
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer, (uint)Sids.Length);

                for (int Index = 0; Index < Sids.Length; Index++)
                {
                    int Entry = (int)(ArrayOffset + EntrySize * (uint)Index);
                    WritePointer(Buffer, Entry, TokenInformation + SidOffset);
                    BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(Entry + (int)PointerSize, 4), SeGroupEnabled);
                    Sids[Index].AsSpan().CopyTo(Buffer.Slice((int)SidOffset));
                    SidOffset += (uint)Sids[Index].Length;
                }

                if (!Instance.WriteMemory(TokenInformation, Buffer.Slice(0, (int)RequiredSize)))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            switch ((TOKEN_INFORMATION_CLASS)TokenInformationClass)
            {
                case TOKEN_INFORMATION_CLASS.TokenCapabilities:
                    return WriteSidGroupsInfo(Token.CapabilitySids);

                case TOKEN_INFORMATION_CLASS.TokenAppContainerSid:
                    return Token.IsAppContainer ? WriteSidPointerInfo(Token.AppContainerSid) : WritePointerOnlyInfo();

                case TOKEN_INFORMATION_CLASS.TokenAppContainerNumber:
                    return WriteUInt32Info(Token.AppContainerNumber);

                case TOKEN_INFORMATION_CLASS.TokenGroups:
                case TOKEN_INFORMATION_CLASS.TokenRestrictedSids:
                case TOKEN_INFORMATION_CLASS.TokenDeviceGroups:
                case TOKEN_INFORMATION_CLASS.TokenRestrictedDeviceGroups:
                case TOKEN_INFORMATION_CLASS.TokenLogonSid:
                case TOKEN_INFORMATION_CLASS.TokenPrivileges:
                    return WriteEmptyCountedInfo();

                case TOKEN_INFORMATION_CLASS.TokenOwner:
                case TOKEN_INFORMATION_CLASS.TokenPrimaryGroup:
                    return WriteSidPointerInfo(UserSid);

                case TOKEN_INFORMATION_CLASS.TokenDefaultDacl:
                case TOKEN_INFORMATION_CLASS.TokenProcessTrustLevel:
                    return WritePointerOnlyInfo();

                case TOKEN_INFORMATION_CLASS.TokenSource:
                    {
                        const uint RequiredSize = 16;
                        WriteReturnLength(RequiredSize);

                        if (TokenInformationLength < RequiredSize)
                            return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                        Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(RequiredSize);
                        Buffer.Clear();
                        "User32 "u8.CopyTo(Buffer);
                        BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(8), WinToken.InteractiveSourceId);

                        if (!Instance.WriteMemory(TokenInformation, Buffer))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case TOKEN_INFORMATION_CLASS.TokenOrigin:
                    {
                        const uint RequiredSize = 8;
                        WriteReturnLength(RequiredSize);

                        if (TokenInformationLength < RequiredSize)
                            return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                        Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(RequiredSize);
                        Buffer.Clear();

                        if (!Instance.WriteMemory(TokenInformation, Buffer))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case TOKEN_INFORMATION_CLASS.TokenElevationType:
                    return WriteUInt32Info(Token.IsElevated ? 2u : 1u);

                case TOKEN_INFORMATION_CLASS.TokenHasRestrictions:
                case TOKEN_INFORMATION_CLASS.TokenVirtualizationAllowed:
                case TOKEN_INFORMATION_CLASS.TokenVirtualizationEnabled:
                case TOKEN_INFORMATION_CLASS.TokenUIAccess:
                case TOKEN_INFORMATION_CLASS.TokenIsRestricted:
                case TOKEN_INFORMATION_CLASS.TokenSandBoxInert:
                case TOKEN_INFORMATION_CLASS.TokenChildProcessFlags:
                case TOKEN_INFORMATION_CLASS.TokenIsLessPrivilegedAppContainer:
                case TOKEN_INFORMATION_CLASS.TokenIsSandboxed:
                case TOKEN_INFORMATION_CLASS.TokenIsAppSilo:
                    return WriteUInt32Info(0);

                case TOKEN_INFORMATION_CLASS.TokenMandatoryPolicy:
                    return WriteUInt32Info(3);

                case TOKEN_INFORMATION_CLASS.TokenSecurityAttributes:
                    return WriteSecurityAttributesInfo(Token.SecurityAttributes);

                case TOKEN_INFORMATION_CLASS.TokenUserClaimAttributes:
                case TOKEN_INFORMATION_CLASS.TokenDeviceClaimAttributes:
                case TOKEN_INFORMATION_CLASS.TokenRestrictedUserClaimAttributes:
                case TOKEN_INFORMATION_CLASS.TokenRestrictedDeviceClaimAttributes:
                case TOKEN_INFORMATION_CLASS.TokenSingletonAttributes:
                    return WriteSecurityAttributesInfo(Array.Empty<WinTokenSecurityAttribute>());

                case TOKEN_INFORMATION_CLASS.TokenType:
                    {
                        uint RequiredSize = 4;
                        WriteReturnLength(RequiredSize);

                        if (TokenInformationLength < RequiredSize)
                            return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                        uint Value = Token.Type == TokenType.Primary ? 1u : 2u;

                        if (!Instance._emulator.WriteMemory(TokenInformation, Value))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case TOKEN_INFORMATION_CLASS.TokenImpersonationLevel:
                    {
                        if (Token.Type == TokenType.Primary)
                            return NTSTATUS.STATUS_INVALID_INFO_CLASS;

                        uint RequiredSize = 4;
                        WriteReturnLength(RequiredSize);

                        if (TokenInformationLength < RequiredSize)
                            return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                        uint Value = (uint)Token.ImpersonationLevel;

                        if (!Instance._emulator.WriteMemory(TokenInformation, Value))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case TOKEN_INFORMATION_CLASS.TokenIsAppContainer:
                    return WriteUInt32Info(Token.IsAppContainer ? 1u : 0u);

                case TOKEN_INFORMATION_CLASS.TokenSessionId:
                    {
                        uint RequiredSize = 4;
                        WriteReturnLength(RequiredSize);

                        if (TokenInformationLength < RequiredSize)
                            return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                        if (!Instance._emulator.WriteMemory(TokenInformation, Token.SessionId))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case TOKEN_INFORMATION_CLASS.TokenElevation:
                    {
                        uint RequiredSize = 4;
                        WriteReturnLength(RequiredSize);

                        if (TokenInformationLength < RequiredSize)
                            return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                        uint Value = Token.IsElevated ? 1u : 0u;

                        if (!Instance._emulator.WriteMemory(TokenInformation, Value))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case TOKEN_INFORMATION_CLASS.TokenBnoIsolation:
                    {
                        uint RequiredSize = (uint)(PointerSize * 2);

                        WriteReturnLength(RequiredSize);

                        if (TokenInformationLength < RequiredSize)
                            return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                        Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(RequiredSize);
                        Buffer.Clear();

                        if (!Instance.WriteMemory(TokenInformation, Buffer))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case TOKEN_INFORMATION_CLASS.TokenStatistics:
                    {
                        uint RequiredSize = 56;
                        WriteReturnLength(RequiredSize);

                        if (TokenInformationLength < RequiredSize)
                            return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                        Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(RequiredSize);
                        Buffer.Clear();

                        User Owner = OwnerProcess?.RunningUser ?? Instance.WinHelper.CurrentUser;
                        ulong AuthenticationId = Owner == User.System ? WinToken.SystemLogonId : Owner == User.LocalService ? WinToken.LocalServiceLogonId : WinToken.InteractiveLogonId;
                        bool Primary = Token.Type == TokenType.Primary;

                        BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x00, 8), Token.TokenId);
                        BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x08, 8), AuthenticationId);
                        BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(0x10, 8), long.MaxValue);
                        BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x18, 4), Primary ? 1u : 2u);
                        BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x1C, 4), Primary ? 0u : (uint)Token.ImpersonationLevel);
                        BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x30, 8), Token.ModifiedId);

                        if (!Instance.WriteMemory(TokenInformation, Buffer))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case TOKEN_INFORMATION_CLASS.TokenUser:
                    return WriteSidAndAttributesInfo(UserSid, 0);

                case TOKEN_INFORMATION_CLASS.TokenIntegrityLevel:
                    return WriteSidAndAttributesInfo(SidIntegrity(IntegrityRid), SeGroupIntegrityEnabled);

                case TOKEN_INFORMATION_CLASS.TokenPrivateNameSpace:
                    return WriteUInt32Info(0);

                default:
                    return NTSTATUS.STATUS_INVALID_INFO_CLASS;
            }
        }

        internal static NTSTATUS ResolveToken(BinaryEmulator Instance, ulong TokenHandle, out WinToken Token)
        {
            Token = null;
            long TokenHandleSigned = HandleManager.ToSignedHandle(TokenHandle);

            if (TokenHandleSigned == -4 || TokenHandleSigned == -5 || TokenHandleSigned == -6)
            {
                WinToken ThreadToken = TokenHandleSigned == -4 ? null : WinEmulatedThread.TryGetState(Instance.CurrentThread)?.ImpersonationToken;
                if (TokenHandleSigned == -5 && ThreadToken == null)
                    return NTSTATUS.STATUS_NO_TOKEN;

                Token = ThreadToken ?? Instance.WinHelper.OwnProcess?.PrimaryToken;
                return Token == null ? NTSTATUS.STATUS_INVALID_HANDLE : NTSTATUS.STATUS_SUCCESS;
            }

            if (!Instance.WinHelper.HandleManager.HandleExists(TokenHandle, HandleType.TokenHandle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            Token = Instance.WinHelper.HandleManager.GetObjectByHandle<WinToken>(TokenHandle);
            return Token == null ? NTSTATUS.STATUS_INVALID_HANDLE : NTSTATUS.STATUS_SUCCESS;
        }

        internal static byte[] InteractiveUserSid() => BuildSid(1, 5, 21, 1000, 1000, 1000, 1001);

        internal static byte[] BuildSid(byte Revision, ulong IdentifierAuthority, params uint[] SubAuthorities)
        {
            byte SubAuthCount = (byte)(SubAuthorities?.Length ?? 0);
            int Size = 8 + (4 * SubAuthCount);

            byte[] Sid = new byte[Size];
            Sid[0] = Revision;
            Sid[1] = SubAuthCount;

            for (int i = 0; i < 6; i++)
                Sid[2 + i] = (byte)(IdentifierAuthority >> ((5 - i) * 8));

            for (int i = 0; i < SubAuthCount; i++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Sid.AsSpan(8 + (i * 4), 4), SubAuthorities[i]);
            }

            return Sid;
        }
    }
}