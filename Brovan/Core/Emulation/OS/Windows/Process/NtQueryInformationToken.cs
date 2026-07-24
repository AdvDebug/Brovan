using System;
using System.Linq;
using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtQueryInformationToken : IWinSyscall
    {
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

            WinToken Token = null;

            long TokenHandleSigned = HandleManager.ToSignedHandle(TokenHandle);

            if (TokenHandleSigned == -4 || TokenHandleSigned == -5 || TokenHandleSigned == -6)
            {
                WinProcess CurrentProcess = Instance.WinHelper.WinProcesses.FirstOrDefault(p => p.PID == Instance.WinHelper.PID);
                WinToken ProcessToken = CurrentProcess?.PrimaryToken;

                EmulatedThread CurrentThread = Instance.Threads.Values.FirstOrDefault(t => t.ThreadId == Instance.CurrentThreadId);
                WinToken ThreadToken = WinEmulatedThread.TryGetState(CurrentThread)?.ImpersonationToken;

                if (TokenHandleSigned == -4)
                {
                    Token = ProcessToken;
                }
                else if (TokenHandleSigned == -5)
                {
                    if (ThreadToken == null)
                        return NTSTATUS.STATUS_NO_TOKEN;

                    Token = ThreadToken;
                }
                else if (TokenHandleSigned == -6)
                {
                    Token = ThreadToken ?? ProcessToken;
                }

                if (Token == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;
            }
            else
            {
                if (!Instance.WinHelper.HandleManager.HandleExists(TokenHandle, HandleType.TokenHandle))
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                Token = Instance.WinHelper.HandleManager.GetObjectByHandle<WinToken>(TokenHandle);
                if (Token == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;
            }

            void WriteReturnLength(uint Length)
            {
                if (ReturnLengthPtr != 0)
                    Instance._emulator.WriteMemory(ReturnLengthPtr, Length);
            }

            static byte[] BuildSid(byte Revision, byte[] IdentifierAuthority, params uint[] SubAuthorities)
            {
                byte SubAuthCount = (byte)(SubAuthorities?.Length ?? 0);
                int Size = 8 + (4 * SubAuthCount);

                byte[] Sid = new byte[Size];
                Sid[0] = Revision;
                Sid[1] = SubAuthCount;

                for (int i = 0; i < 6; i++)
                    Sid[2 + i] = (i < IdentifierAuthority.Length) ? IdentifierAuthority[i] : (byte)0;

                for (int i = 0; i < SubAuthCount; i++)
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(Sid.AsSpan(8 + (i * 4), 4), SubAuthorities[i]);
                }

                return Sid;
            }

            static byte[] SidLocalSystem() => BuildSid(1, new byte[] { 0, 0, 0, 0, 0, 5 }, 18);
            static byte[] SidIntegrity(uint Rid) => BuildSid(1, new byte[] { 0, 0, 0, 0, 0, 16 }, Rid);
            static byte[] SidFallbackUser() => BuildSid(1, new byte[] { 0, 0, 0, 0, 0, 5 }, 21, 1000, 1000, 1000, 1001);

            WinProcess OwnerProcess = Instance.WinHelper.WinProcesses.FirstOrDefault(p => p.PID == (uint)Token.OwningProcessId);

            byte[] UserSid = SidFallbackUser();
            if (OwnerProcess != null)
            {
                if (OwnerProcess.RunningUser == User.System || OwnerProcess.RunningUser == User.LocalService || OwnerProcess.RunningUser == User.WindowManager)
                    UserSid = SidLocalSystem();
            }

            uint IntegrityRid = 0x2000;
            if (OwnerProcess != null)
            {
                if (OwnerProcess.RunningUser == User.System || OwnerProcess.RunningUser == User.LocalService || OwnerProcess.RunningUser == User.WindowManager)
                    IntegrityRid = 0x4000;
                else if (Token.IsElevated || OwnerProcess.RunningUser == User.Admin)
                    IntegrityRid = 0x3000;
            }

            uint PointerSize = (uint)(Is64 ? 8 : 4);

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
                    return NTSTATUS.STATUS_BUFFER_OVERFLOW;

                if (!Instance._emulator.WriteMemory(TokenInformation, Value))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            NTSTATUS WriteEmptyCountedInfo()
            {
                const uint RequiredSize = 4;
                WriteReturnLength(RequiredSize);

                if (TokenInformationLength < RequiredSize)
                    return NTSTATUS.STATUS_BUFFER_OVERFLOW;

                if (!Instance._emulator.WriteMemory(TokenInformation, 0u))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            NTSTATUS WritePointerOnlyInfo(ulong Value = 0)
            {
                uint RequiredSize = PointerSize;
                WriteReturnLength(RequiredSize);

                if (TokenInformationLength < RequiredSize)
                    return NTSTATUS.STATUS_BUFFER_OVERFLOW;

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
                    return NTSTATUS.STATUS_BUFFER_OVERFLOW;

                Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(RequiredSize);
                Buffer.Clear();
                WritePointer(Buffer, 0, TokenInformation + SidOffset);
                Sid.AsSpan().CopyTo(Buffer.Slice((int)SidOffset, Sid.Length));

                if (!Instance.WriteMemory(TokenInformation, Buffer))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            NTSTATUS WriteSecurityAttributesInfo()
            {
                uint RequiredSize = 8 + PointerSize;
                WriteReturnLength(RequiredSize);

                if (TokenInformationLength < RequiredSize)
                    return NTSTATUS.STATUS_BUFFER_OVERFLOW;

                Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(RequiredSize);
                Buffer.Clear();

                if (!Instance.WriteMemory(TokenInformation, Buffer))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            switch ((TOKEN_INFORMATION_CLASS)TokenInformationClass)
            {
                case TOKEN_INFORMATION_CLASS.TokenGroups:
                case TOKEN_INFORMATION_CLASS.TokenRestrictedSids:
                case TOKEN_INFORMATION_CLASS.TokenCapabilities:
                case TOKEN_INFORMATION_CLASS.TokenDeviceGroups:
                case TOKEN_INFORMATION_CLASS.TokenRestrictedDeviceGroups:
                case TOKEN_INFORMATION_CLASS.TokenLogonSid:
                case TOKEN_INFORMATION_CLASS.TokenPrivileges:
                    return WriteEmptyCountedInfo();

                case TOKEN_INFORMATION_CLASS.TokenOwner:
                case TOKEN_INFORMATION_CLASS.TokenPrimaryGroup:
                    return WriteSidPointerInfo(UserSid);

                case TOKEN_INFORMATION_CLASS.TokenDefaultDacl:
                case TOKEN_INFORMATION_CLASS.TokenAppContainerSid:
                case TOKEN_INFORMATION_CLASS.TokenProcessTrustLevel:
                    return WritePointerOnlyInfo();

                case TOKEN_INFORMATION_CLASS.TokenSource:
                    {
                        const uint RequiredSize = 16;
                        WriteReturnLength(RequiredSize);

                        if (TokenInformationLength < RequiredSize)
                            return NTSTATUS.STATUS_BUFFER_OVERFLOW;

                        Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(RequiredSize);
                        Buffer.Clear();
                        Buffer[0] = (byte)'B';
                        Buffer[1] = (byte)'r';
                        Buffer[2] = (byte)'o';
                        Buffer[3] = (byte)'v';
                        Buffer[4] = (byte)'a';
                        Buffer[5] = (byte)'n';
                        Buffer[6] = (byte)' ';
                        Buffer[7] = (byte)' ';

                        if (!Instance.WriteMemory(TokenInformation, Buffer))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case TOKEN_INFORMATION_CLASS.TokenOrigin:
                    {
                        const uint RequiredSize = 8;
                        WriteReturnLength(RequiredSize);

                        if (TokenInformationLength < RequiredSize)
                            return NTSTATUS.STATUS_BUFFER_OVERFLOW;

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
                case TOKEN_INFORMATION_CLASS.TokenAppContainerNumber:
                case TOKEN_INFORMATION_CLASS.TokenIsRestricted:
                case TOKEN_INFORMATION_CLASS.TokenSandBoxInert:
                case TOKEN_INFORMATION_CLASS.TokenChildProcessFlags:
                case TOKEN_INFORMATION_CLASS.TokenIsLessPrivilegedAppContainer:
                case TOKEN_INFORMATION_CLASS.TokenIsSandboxed:
                case TOKEN_INFORMATION_CLASS.TokenIsAppSilo:
                    return WriteUInt32Info(0);

                case TOKEN_INFORMATION_CLASS.TokenMandatoryPolicy:
                    return WriteUInt32Info(3);

                case TOKEN_INFORMATION_CLASS.TokenUserClaimAttributes:
                case TOKEN_INFORMATION_CLASS.TokenDeviceClaimAttributes:
                case TOKEN_INFORMATION_CLASS.TokenRestrictedUserClaimAttributes:
                case TOKEN_INFORMATION_CLASS.TokenRestrictedDeviceClaimAttributes:
                case TOKEN_INFORMATION_CLASS.TokenSecurityAttributes:
                case TOKEN_INFORMATION_CLASS.TokenSingletonAttributes:
                    return WriteSecurityAttributesInfo();

                case TOKEN_INFORMATION_CLASS.TokenType:
                    {
                        uint RequiredSize = 4;
                        WriteReturnLength(RequiredSize);

                        if (TokenInformationLength < RequiredSize)
                            return NTSTATUS.STATUS_BUFFER_OVERFLOW;

                        uint Value = Token.Type == TokenType.Primary ? 1u : 2u;

                        if (!Instance._emulator.WriteMemory(TokenInformation, Value))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case TOKEN_INFORMATION_CLASS.TokenImpersonationLevel:
                    {
                        uint RequiredSize = 4;
                        WriteReturnLength(RequiredSize);

                        if (TokenInformationLength < RequiredSize)
                            return NTSTATUS.STATUS_BUFFER_OVERFLOW;

                        uint Value = (uint)Token.ImpersonationLevel;

                        if (!Instance._emulator.WriteMemory(TokenInformation, Value))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case TOKEN_INFORMATION_CLASS.TokenIsAppContainer:
                    {
                        uint RequiredSize = 4;
                        WriteReturnLength(RequiredSize);

                        if (TokenInformationLength < RequiredSize)
                            return NTSTATUS.STATUS_BUFFER_OVERFLOW;

                        uint Value = 0;

                        if (!Instance._emulator.WriteMemory(TokenInformation, Value))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case TOKEN_INFORMATION_CLASS.TokenSessionId:
                    {
                        uint RequiredSize = 4;
                        WriteReturnLength(RequiredSize);

                        if (TokenInformationLength < RequiredSize)
                            return NTSTATUS.STATUS_BUFFER_OVERFLOW;

                        if (!Instance._emulator.WriteMemory(TokenInformation, Token.SessionId))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case TOKEN_INFORMATION_CLASS.TokenElevation:
                    {
                        uint RequiredSize = 4;
                        WriteReturnLength(RequiredSize);

                        if (TokenInformationLength < RequiredSize)
                            return NTSTATUS.STATUS_BUFFER_OVERFLOW;

                        uint Value = Token.IsElevated ? 1u : 0u;

                        if (!Instance._emulator.WriteMemory(TokenInformation, Value))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case TOKEN_INFORMATION_CLASS.TokenBnoIsolation:
                    {
                        int PtrSize = Is64 ? 8 : 4;
                        uint RequiredSize = (uint)(Is64 ? 16 : 8);

                        WriteReturnLength(RequiredSize);

                        if (TokenInformationLength < RequiredSize)
                            return NTSTATUS.STATUS_BUFFER_OVERFLOW;

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
                            return NTSTATUS.STATUS_BUFFER_OVERFLOW;

                        Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(RequiredSize);
                        Buffer.Clear();

                        ulong TokenIdLow = (ulong)((uint)Token.OwningProcessId);
                        ulong TokenIdHigh = (ulong)((uint)Token.OwningThreadId);
                        BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x00, 8), TokenIdLow);
                        BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x08, 8), TokenIdHigh);

                        uint TokenTypeValue = Token.Type == TokenType.Primary ? 1u : 2u;
                        BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x18, 4), TokenTypeValue);

                        uint ImpersonationLevel = (uint)Token.ImpersonationLevel;
                        BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x1C, 4), ImpersonationLevel);

                        if (!Instance.WriteMemory(TokenInformation, Buffer))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case TOKEN_INFORMATION_CLASS.TokenUser:
                    {
                        int PtrSize = Is64 ? 8 : 4;
                        uint HeaderSize = (uint)(PtrSize + 4);
                        uint SidOffset = (uint)((HeaderSize + 7) & ~7u);
                        uint RequiredSize = SidOffset + (uint)UserSid.Length;

                        WriteReturnLength(RequiredSize);

                        if (TokenInformationLength < RequiredSize)
                            return NTSTATUS.STATUS_BUFFER_OVERFLOW;

                        Span<byte> BufferData = Instance.WinHelper.Shared.GetSpan(RequiredSize);
                        BufferData.Clear();

                        ulong SidPtr = TokenInformation + SidOffset;
                        if (Is64)
                            BinaryPrimitives.WriteUInt64LittleEndian(BufferData.Slice(0x00, 8), SidPtr);
                        else
                            BinaryPrimitives.WriteUInt32LittleEndian(BufferData.Slice(0x00, 4), (uint)SidPtr);

                        UserSid.AsSpan().CopyTo(BufferData.Slice((int)SidOffset, UserSid.Length));

                        if (!Instance.WriteMemory(TokenInformation, BufferData))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case TOKEN_INFORMATION_CLASS.TokenIntegrityLevel:
                    {
                        byte[] IntegritySid = SidIntegrity(IntegrityRid);

                        int PtrSize = Is64 ? 8 : 4;
                        uint HeaderSize = (uint)(PtrSize + 4);
                        uint SidOffset = (uint)((HeaderSize + 7) & ~7u);
                        uint RequiredSize = SidOffset + (uint)IntegritySid.Length;

                        WriteReturnLength(RequiredSize);

                        if (TokenInformationLength < RequiredSize)
                            return NTSTATUS.STATUS_BUFFER_OVERFLOW;

                        Span<byte> BufferData = Instance.WinHelper.Shared.GetSpan(RequiredSize);
                        BufferData.Clear();

                        ulong SidPtr = TokenInformation + SidOffset;
                        if (Is64)
                            BinaryPrimitives.WriteUInt64LittleEndian(BufferData.Slice(0x00, 8), SidPtr);
                        else
                            BinaryPrimitives.WriteUInt32LittleEndian(BufferData.Slice(0x00, 4), (uint)SidPtr);

                        BinaryPrimitives.WriteUInt32LittleEndian(BufferData.Slice(PtrSize, 4), 0x20u);

                        IntegritySid.AsSpan().CopyTo(BufferData.Slice((int)SidOffset, IntegritySid.Length));

                        if (!Instance.WriteMemory(TokenInformation, BufferData))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case TOKEN_INFORMATION_CLASS.TokenPrivateNameSpace:
                    {
                        uint RequiredSize = 8;
                        WriteReturnLength(RequiredSize);

                        if (TokenInformationLength < RequiredSize)
                            return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                        if (!Instance._emulator.WriteMemory(TokenInformation, 0u, 4))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                default:
                    return NTSTATUS.STATUS_INVALID_INFO_CLASS;
            }
        }
    }
}