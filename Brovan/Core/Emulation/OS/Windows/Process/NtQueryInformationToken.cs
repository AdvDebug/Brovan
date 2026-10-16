using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal readonly record struct TokenGroup(byte[] Sid, uint Attributes);

    // SECURITY_QUALITY_OF_SERVICE has one layout on x86 and x64.
    internal readonly record struct SecurityQos(SecurityImpersonationLevel Level, bool DynamicTracking, bool EffectiveOnly)
    {
        internal const int Size = 12;
        private const int OffLevel = 4;
        private const int OffTracking = 8;
        private const int OffEffectiveOnly = 9;
        private const byte DynamicTrackingMode = 1;

        // NT checks the tracking mode before the level (SeCaptureSecurityQos, SepCreateClientSecurityEx).
        internal static NTSTATUS Read(ReadOnlySpan<byte> Raw, out SecurityQos Qos)
        {
            Qos = default;
            if (Raw[OffTracking] > DynamicTrackingMode)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Level = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(OffLevel));
            if (Level > (uint)SecurityImpersonationLevel.SecurityDelegation)
                return NTSTATUS.STATUS_BAD_IMPERSONATION_LEVEL;

            Qos = new SecurityQos((SecurityImpersonationLevel)Level, Raw[OffTracking] == DynamicTrackingMode, Raw[OffEffectiveOnly] != 0);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }

    internal sealed class NtQueryInformationToken : IWinSyscall
    {
        internal const uint SeGroupEnabled = 0x4;
        private const uint SeGroupOwner = 0x8;
        internal const uint SeGroupUseForDenyOnly = 0x10;
        private const uint SeGroupStandard = 0x7;
        private const uint SeGroupIntegrity = 0x60;
        private const uint SeGroupLogonId = 0xC0000000;

        internal const uint UntrustedIntegrityRid = 0;
        internal const uint LowIntegrityRid = 0x1000;
        internal const uint MediumIntegrityRid = 0x2000;
        internal const uint HighIntegrityRid = 0x3000;
        internal const uint SystemIntegrityRid = 0x4000;

        internal const byte SidRevision = 1;
        internal const int MaxSubAuthorities = 15;
        internal const byte AppPackageAuthority = 15;
        internal const uint AppPackageBaseRid = 2;
        internal const uint AppCapabilityBaseRid = 3;

        internal const uint DomainUsersRid = 513;
        internal const uint InteractiveUserRid = 1001;

        // The SID arrays below are shared, so callers copy them and never change them.
        internal static readonly byte[] AccountDomainSid = BuildSid(5, 21, 1000, 1000, 1000);
        internal static readonly byte[] InteractiveUserSid = AccountSid(InteractiveUserRid);
        internal static readonly byte[] DomainUsersSid = AccountSid(DomainUsersRid);
        internal static readonly string InteractiveUserSidText = FormatSid(InteractiveUserSid);

        internal static readonly byte[] EveryoneSid = BuildSid(1, 0);
        internal static readonly byte[] LocalSid = BuildSid(2, 0);
        internal static readonly byte[] ConsoleLogonSid = BuildSid(2, 1);
        internal static readonly byte[] OwnerRightsSid = BuildSid(3, 4);
        internal static readonly byte[] NetworkSid = BuildSid(5, 2);
        internal static readonly byte[] InteractiveSid = BuildSid(5, 4);
        internal static readonly byte[] AnonymousLogonSid = BuildSid(5, 7);
        internal static readonly byte[] PrincipalSelfSid = BuildSid(5, 10);
        internal static readonly byte[] AuthenticatedUsersSid = BuildSid(5, 11);
        internal static readonly byte[] ThisOrganizationSid = BuildSid(5, 15);
        internal static readonly byte[] LocalSystemSid = BuildSid(5, 18);
        internal static readonly byte[] LocalAccountSid = BuildSid(5, 113);
        internal static readonly byte[] LocalAccountAndAdministratorSid = BuildSid(5, 114);
        internal static readonly byte[] AdministratorsSid = BuildSid(5, 32, 544);
        internal static readonly byte[] UsersSid = BuildSid(5, 32, 545);
        internal static readonly byte[] NtlmAuthenticationSid = BuildSid(5, 64, 10);
        internal static readonly byte[] AllApplicationPackagesSid = BuildSid(15, 2, 1);
        internal static readonly byte[] AllRestrictedApplicationPackagesSid = BuildSid(15, 2, 2);
        private static readonly byte[][] LabelSids =
        {
            BuildSid(16, UntrustedIntegrityRid), BuildSid(16, LowIntegrityRid), BuildSid(16, MediumIntegrityRid), BuildSid(16, HighIntegrityRid),
            BuildSid(16, SystemIntegrityRid),
        };

        // A native token lists its groups in this order, with the integrity label last.
        private static readonly TokenGroup[] InteractiveGroups =
        {
            new TokenGroup(DomainUsersSid, SeGroupStandard),
            new TokenGroup(EveryoneSid, SeGroupStandard),
            new TokenGroup(UsersSid, SeGroupStandard),
            new TokenGroup(InteractiveSid, SeGroupStandard),
            new TokenGroup(ConsoleLogonSid, SeGroupStandard),
            new TokenGroup(AuthenticatedUsersSid, SeGroupStandard),
            new TokenGroup(ThisOrganizationSid, SeGroupStandard),
            new TokenGroup(LocalAccountSid, SeGroupStandard),
            new TokenGroup(BuildSid(5, 5, 0, (uint)WinToken.InteractiveLogonId), SeGroupLogonId | SeGroupStandard),
            new TokenGroup(LocalSid, SeGroupStandard),
            new TokenGroup(NtlmAuthenticationSid, SeGroupStandard),
        };

        private static readonly TokenGroup[] ElevatedInteractiveGroups =
        [
            .. InteractiveGroups.AsSpan(0, 2),
            new TokenGroup(LocalAccountAndAdministratorSid, SeGroupStandard),
            new TokenGroup(AdministratorsSid, SeGroupStandard | SeGroupOwner),
            .. InteractiveGroups.AsSpan(2),
        ];

        private static readonly TokenGroup[] ServiceGroups =
        {
            new TokenGroup(AdministratorsSid, SeGroupStandard | SeGroupOwner),
            new TokenGroup(EveryoneSid, SeGroupStandard),
            new TokenGroup(AuthenticatedUsersSid, SeGroupStandard),
        };

        private static readonly TokenGroup[] AnonymousGroups =
        {
            new TokenGroup(EveryoneSid, SeGroupStandard),
            new TokenGroup(NetworkSid, SeGroupStandard),
        };

        private enum LogonKind
        {
            Anonymous,
            Service,
            Elevated,
            Interactive,
        }

        private static readonly TokenGroup[][] GroupSets = BuildGroupSets();

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

            NTSTATUS WriteEmptyCountedInfo() => WriteUInt32Info(0);

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

            NTSTATUS WriteSidGroupsInfo(ReadOnlySpan<TokenGroup> Groups, byte[][] Sids, uint SidAttributes)
            {
                int Count = Sids?.Length ?? Groups.Length;
                uint EntrySize = PointerSize * 2;
                uint ArrayOffset = PointerSize;
                uint SidOffset = ArrayOffset + EntrySize * (uint)Count;
                uint RequiredSize = SidOffset;
                for (int Index = 0; Index < Count; Index++)
                    RequiredSize += (uint)(Sids?[Index] ?? Groups[Index].Sid).Length;

                WriteReturnLength(RequiredSize);
                if (TokenInformationLength < RequiredSize)
                    return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(RequiredSize);
                Buffer.Slice(0, (int)SidOffset).Clear();
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer, (uint)Count);

                for (int Index = 0; Index < Count; Index++)
                {
                    int Entry = (int)(ArrayOffset + EntrySize * (uint)Index);
                    byte[] Sid = Sids?[Index] ?? Groups[Index].Sid;
                    WritePointer(Buffer, Entry, TokenInformation + SidOffset);
                    BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(Entry + (int)PointerSize, 4), Sids != null ? SidAttributes : Groups[Index].Attributes);
                    Sid.AsSpan().CopyTo(Buffer.Slice((int)SidOffset));
                    SidOffset += (uint)Sid.Length;
                }

                if (!Instance.WriteMemory(TokenInformation, Buffer.Slice(0, (int)RequiredSize)))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            switch ((TOKEN_INFORMATION_CLASS)TokenInformationClass)
            {
                case TOKEN_INFORMATION_CLASS.TokenCapabilities:
                    return WriteSidGroupsInfo(default, Token.CapabilitySids, SeGroupEnabled);

                case TOKEN_INFORMATION_CLASS.TokenAppContainerSid:
                    return Token.IsAppContainer ? WriteSidPointerInfo(Token.AppContainerSid) : WritePointerOnlyInfo();

                case TOKEN_INFORMATION_CLASS.TokenAppContainerNumber:
                    return WriteUInt32Info(Token.AppContainerNumber);

                case TOKEN_INFORMATION_CLASS.TokenGroups:
                    return WriteSidGroupsInfo(GroupsOf(Token, OwnerOf(Instance, Token)), null, 0);

                case TOKEN_INFORMATION_CLASS.TokenLogonSid:
                    {
                        TokenGroup[] Groups = GroupsOf(Token, OwnerOf(Instance, Token));
                        for (int Index = 0; Index < Groups.Length; Index++)
                        {
                            if ((Groups[Index].Attributes & SeGroupLogonId) == SeGroupLogonId)
                                return WriteSidGroupsInfo(Groups.AsSpan(Index, 1), null, 0);
                        }

                        return WriteEmptyCountedInfo();
                    }

                case TOKEN_INFORMATION_CLASS.TokenRestrictedSids:
                case TOKEN_INFORMATION_CLASS.TokenDeviceGroups:
                case TOKEN_INFORMATION_CLASS.TokenRestrictedDeviceGroups:
                case TOKEN_INFORMATION_CLASS.TokenPrivileges:
                    return WriteEmptyCountedInfo();

                case TOKEN_INFORMATION_CLASS.TokenOwner:
                    return WriteSidPointerInfo(UserSidOf(Token, OwnerOf(Instance, Token)));

                case TOKEN_INFORMATION_CLASS.TokenPrimaryGroup:
                    return WriteSidPointerInfo(PrimaryGroupOf(Token, OwnerOf(Instance, Token)));

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
                    return WriteUInt32Info(Token.Type == TokenType.Primary ? 1u : 2u);

                case TOKEN_INFORMATION_CLASS.TokenImpersonationLevel:
                    if (Token.Type == TokenType.Primary)
                        return NTSTATUS.STATUS_INVALID_INFO_CLASS;
                    return WriteUInt32Info((uint)Token.ImpersonationLevel);

                case TOKEN_INFORMATION_CLASS.TokenIsAppContainer:
                    return WriteUInt32Info(Token.IsAppContainer ? 1u : 0u);

                case TOKEN_INFORMATION_CLASS.TokenSessionId:
                    return WriteUInt32Info(Token.SessionId);

                case TOKEN_INFORMATION_CLASS.TokenElevation:
                    return WriteUInt32Info(Token.IsElevated ? 1u : 0u);

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

                        WinProcess OwnerProcess = OwnerOf(Instance, Token);
                        bool Primary = Token.Type == TokenType.Primary;

                        BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x00, 8), Token.TokenId);
                        BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x08, 8), AuthenticationIdOf(Instance, OwnerProcess));
                        BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(0x10, 8), long.MaxValue);
                        BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x18, 4), Primary ? 1u : 2u);
                        BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x1C, 4), Primary ? 0u : (uint)Token.ImpersonationLevel);
                        BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x28, 4), (uint)GroupsOf(Token, OwnerProcess).Length);
                        BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x30, 8), Token.ModifiedId);

                        if (!Instance.WriteMemory(TokenInformation, Buffer))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case TOKEN_INFORMATION_CLASS.TokenUser:
                    return WriteSidAndAttributesInfo(UserSidOf(Token, OwnerOf(Instance, Token)), 0);

                case TOKEN_INFORMATION_CLASS.TokenIntegrityLevel:
                    return WriteSidAndAttributesInfo(LabelSidOf(IntegrityRidOf(Token, OwnerOf(Instance, Token))), SeGroupIntegrity);

                case TOKEN_INFORMATION_CLASS.TokenPrivateNameSpace:
                    return WriteUInt32Info(0);

                default:
                    return NTSTATUS.STATUS_INVALID_INFO_CLASS;
            }
        }

        internal static NTSTATUS ResolveToken(BinaryEmulator Instance, ulong TokenHandle, out WinToken Token)
        {
            if (HandleManager.IsTokenPseudoHandle(TokenHandle))
                return ResolvePseudoToken(Instance, TokenHandle, out Token);

            Token = Instance.WinHelper.HandleManager.GetObjectByHandle<WinToken>(TokenHandle);
            return Token == null ? NTSTATUS.STATUS_INVALID_HANDLE : NTSTATUS.STATUS_SUCCESS;
        }

        internal static NTSTATUS ResolvePseudoToken(BinaryEmulator Instance, ulong TokenHandle, out WinToken Token)
        {
            long Pseudo = HandleManager.ToSignedHandle(TokenHandle);
            WinToken ThreadToken = Pseudo == HandleManager.CurrentProcessToken ? null : CallerImpersonationToken(Instance);
            Token = null;
            if (Pseudo == HandleManager.CurrentThreadToken && ThreadToken == null)
                return NTSTATUS.STATUS_NO_TOKEN;

            Token = ThreadToken ?? Instance.WinHelper.OwnProcess?.PrimaryToken;
            return Token == null ? NTSTATUS.STATUS_INVALID_HANDLE : NTSTATUS.STATUS_SUCCESS;
        }

        private static TokenGroup[][] BuildGroupSets()
        {
            TokenGroup[][] Sets = new TokenGroup[GroupSetIndex(LogonKind.Interactive, true) + 1][];
            for (LogonKind Kind = LogonKind.Anonymous; Kind <= LogonKind.Interactive; Kind++)
            {
                TokenGroup[] Base = Kind switch
                {
                    LogonKind.Anonymous => AnonymousGroups,
                    LogonKind.Service => ServiceGroups,
                    LogonKind.Elevated => ElevatedInteractiveGroups,
                    _ => InteractiveGroups,
                };

                Sets[GroupSetIndex(Kind, false)] = [.. Base, new TokenGroup(LabelSidOf(IntegrityRidOf(Kind, false)), SeGroupIntegrity)];
                Sets[GroupSetIndex(Kind, true)] = [.. Base, new TokenGroup(LabelSidOf(IntegrityRidOf(Kind, true)), SeGroupIntegrity)];
            }

            return Sets;
        }

        private static int GroupSetIndex(LogonKind Kind, bool AppContainer) => (int)Kind * 2 + (AppContainer ? 1 : 0);

        internal static WinToken CallerImpersonationToken(BinaryEmulator Instance) => WinEmulatedThread.TryGetState(Instance.CurrentThread)?.ImpersonationToken;

        internal static WinToken EffectiveToken(BinaryEmulator Instance)
        {
            return CallerImpersonationToken(Instance) ?? Instance.WinHelper.OwnProcess?.GetPrimaryToken();
        }

        internal static WinProcess OwnerOf(BinaryEmulator Instance, WinToken Token)
        {
            uint ProcessId = (uint)Token.OwningProcessId;
            WinSysHelper Helper = Instance.WinHelper;
            if (Helper.OwnProcess?.PID == ProcessId)
                return Helper.OwnProcess;
            if (Helper.ShellProcess?.PID == ProcessId)
                return Helper.ShellProcess;

            foreach (WinProcess Process in Helper.WinProcesses)
            {
                if (Process.PID == ProcessId)
                    return Process;
            }

            return null;
        }

        private static bool IsServiceUser(WinProcess OwnerProcess) => OwnerProcess?.RunningUser is User.System or User.LocalService or User.WindowManager;

        private static bool IsElevated(WinToken Token, WinProcess OwnerProcess) => Token.IsElevated || OwnerProcess?.RunningUser == User.Admin;

        private static bool HoldsImpersonatePrivilege(WinToken Token, WinProcess OwnerProcess) => IsServiceUser(OwnerProcess) || IsElevated(Token, OwnerProcess);

        internal static byte[] UserSidOf(WinToken Token, WinProcess OwnerProcess)
        {
            return KindOf(Token, OwnerProcess) switch
            {
                LogonKind.Anonymous => AnonymousLogonSid,
                LogonKind.Service => LocalSystemSid,
                _ => InteractiveUserSid,
            };
        }

        internal static byte[] PrimaryGroupOf(WinToken Token, WinProcess OwnerProcess)
        {
            return KindOf(Token, OwnerProcess) switch
            {
                LogonKind.Anonymous => AnonymousLogonSid,
                LogonKind.Service => LocalSystemSid,
                _ => DomainUsersSid,
            };
        }

        private static LogonKind KindOf(WinToken Token, WinProcess OwnerProcess)
        {
            if (Token.IsAnonymous)
                return LogonKind.Anonymous;
            if (IsServiceUser(OwnerProcess))
                return LogonKind.Service;
            return IsElevated(Token, OwnerProcess) ? LogonKind.Elevated : LogonKind.Interactive;
        }

        private static uint IntegrityRidOf(LogonKind Kind, bool AppContainer)
        {
            return (Kind, AppContainer) switch
            {
                (LogonKind.Anonymous, _) => UntrustedIntegrityRid,
                (_, true) => LowIntegrityRid,
                (LogonKind.Service, _) => SystemIntegrityRid,
                (LogonKind.Elevated, _) => HighIntegrityRid,
                _ => MediumIntegrityRid,
            };
        }

        // NT lowers the level to identification when the server may not impersonate the client (SeTokenCanImpersonate).
        internal static SecurityImpersonationLevel PermittedImpersonationLevel(BinaryEmulator Instance, WinToken Client, SecurityImpersonationLevel Level)
        {
            WinToken Server = Instance.WinHelper.OwnProcess?.GetPrimaryToken();
            if (Level < SecurityImpersonationLevel.SecurityImpersonation || Server == null)
                return Level;

            if (CanImpersonate(Instance, Server, Client))
                return Level;

            return Client.Type == TokenType.Impersonation && Client.ImpersonationLevel < SecurityImpersonationLevel.SecurityIdentification
                ? Client.ImpersonationLevel
                : SecurityImpersonationLevel.SecurityIdentification;
        }

        private static bool CanImpersonate(BinaryEmulator Instance, WinToken Server, WinToken Client)
        {
            bool AppContainerAllows = !Server.IsAppContainer || (Client.IsAppContainer && Server.AppContainerSid.AsSpan().SequenceEqual(Client.AppContainerSid));
            if (Client.IsAnonymous)
                return AppContainerAllows;

            WinProcess ServerOwner = OwnerOf(Instance, Server);
            if (HoldsImpersonatePrivilege(Server, ServerOwner))
                return true;

            WinProcess ClientOwner = OwnerOf(Instance, Client);
            return AppContainerAllows && IntegrityRidOf(Server, ServerOwner) >= IntegrityRidOf(Client, ClientOwner)
                && UserSidOf(Server, ServerOwner).AsSpan().SequenceEqual(UserSidOf(Client, ClientOwner));
        }

        internal static uint IntegrityRidOf(WinToken Token, WinProcess OwnerProcess) => IntegrityRidOf(KindOf(Token, OwnerProcess), Token.IsAppContainer);

        internal static byte[] LabelSidOf(uint IntegrityRid) => LabelSids[IntegrityRid >> 12];

        internal static TokenGroup[] GroupsOf(WinToken Token, WinProcess OwnerProcess) => GroupSets[GroupSetIndex(KindOf(Token, OwnerProcess), Token.IsAppContainer)];

        internal static ulong AuthenticationIdOf(BinaryEmulator Instance, WinProcess OwnerProcess)
        {
            return (OwnerProcess?.RunningUser ?? Instance.WinHelper.CurrentUser) switch
            {
                User.System => WinToken.SystemLogonId,
                User.LocalService => WinToken.LocalServiceLogonId,
                _ => WinToken.InteractiveLogonId,
            };
        }

        internal static int SidLength(int SubAuthorityCount) => 8 + 4 * SubAuthorityCount;

        internal static uint SubAuthority(ReadOnlySpan<byte> Sid, int Index) => BinaryPrimitives.ReadUInt32LittleEndian(Sid.Slice(SidLength(Index)));

        // The 48-bit identifier authority is big endian, after the revision and the sub-authority count.
        private static ulong AuthorityOf(ReadOnlySpan<byte> Sid) => BinaryPrimitives.ReadUInt64BigEndian(Sid) & 0xFFFF_FFFF_FFFF;

        internal static uint? FirstSubAuthority(ReadOnlySpan<byte> Sid, byte Authority)
        {
            if (Sid.Length < SidLength(1) || Sid[1] == 0 || AuthorityOf(Sid) != Authority)
                return null;

            return SubAuthority(Sid, 0);
        }

        // NT writes an authority of 2^32 or more in hex without padding (RtlConvertSidToUnicodeString).
        internal static string FormatSid(ReadOnlySpan<byte> Sid)
        {
            const int MaxLength = 24 + MaxSubAuthorities * 11;
            DefaultInterpolatedStringHandler Text = new DefaultInterpolatedStringHandler(0, 0, null, stackalloc char[MaxLength]);
            Text.AppendLiteral("S-");
            Text.AppendFormatted(Sid[0]);
            Text.AppendLiteral("-");

            ulong Authority = AuthorityOf(Sid);
            if (Authority >> 32 == 0)
            {
                Text.AppendFormatted(Authority);
            }
            else
            {
                Text.AppendLiteral("0x");
                Text.AppendFormatted(Authority, "X");
            }

            for (int Index = 0; Index < Sid[1]; Index++)
            {
                Text.AppendLiteral("-");
                Text.AppendFormatted(SubAuthority(Sid, Index));
            }

            return Text.ToStringAndClear();
        }

        private static byte[] AccountSid(uint Rid)
        {
            byte[] Sid = new byte[AccountDomainSid.Length + sizeof(uint)];
            AccountDomainSid.CopyTo(Sid, 0);
            Sid[1]++;
            BinaryPrimitives.WriteUInt32LittleEndian(Sid.AsSpan(AccountDomainSid.Length), Rid);
            return Sid;
        }

        internal static bool TryGetAccountRid(ReadOnlySpan<byte> Sid, out uint Rid)
        {
            Rid = 0;
            int DomainLength = AccountDomainSid.Length;
            if (Sid.Length != DomainLength + sizeof(uint) || Sid[1] != AccountDomainSid[1] + 1 || !Sid.Slice(2, DomainLength - 2).SequenceEqual(AccountDomainSid.AsSpan(2)))
                return false;

            Rid = BinaryPrimitives.ReadUInt32LittleEndian(Sid.Slice(DomainLength));
            return true;
        }

        internal static byte[] BuildSid(ulong IdentifierAuthority, params ReadOnlySpan<uint> SubAuthorities)
        {
            byte[] Sid = new byte[SidLength(SubAuthorities.Length)];
            BinaryPrimitives.WriteUInt64BigEndian(Sid, IdentifierAuthority);
            Sid[0] = SidRevision;
            Sid[1] = (byte)SubAuthorities.Length;

            for (int i = 0; i < SubAuthorities.Length; i++)
                BinaryPrimitives.WriteUInt32LittleEndian(Sid.AsSpan(SidLength(i)), SubAuthorities[i]);

            return Sid;
        }
    }
}