using System;
using Brovan.Core.Emulation.OS.Windows.RPC.UserManager;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Ports
{
    internal static class UserManagerRpcPortHandler
    {
        private static readonly Guid UserMarshalData = new Guid("0d3c7f20-1c8d-4654-a1b3-51563b298bda");
        private static readonly Guid UserManagerClient = new Guid("b18fbab6-56f8-4702-84e0-41053293a869");

        internal static readonly EndpointMapper.RpcInterface[] Interfaces =
        {
            new EndpointMapper.RpcInterface(UserMarshalData, 1, 0),
            new EndpointMapper.RpcInterface(UserManagerClient, 1, 0),
        };
        private static readonly Guid[] InterfaceIds = { UserMarshalData, UserManagerClient };

        private const uint ProcGetUserMarshalData = 0;

        private enum ClientProc : uint
        {
            QueryUserToken = 0,
            GetConstrainedUserToken = 1,
            IsAllowedToActivateAsUser = 2,
            QueryDefaultAccountToken = 3,
            QuerySessionVirtualAccountToken = 4,
            LaunchShell = 5,
            LaunchShellInfrastructureHost = 6,
            SetShellInformation = 7,
            InformUserLogon = 8,
            InformUserLogoff = 9,
            QueryUserContext = 10,
            LogonUser = 11,
            QuerySessionUserToken = 12,
            GetConstrainedUserTokenFromAppcontainer = 13,
            EnumerateSessionUsers = 14,
            QueryUserTokenFromName = 15,
            QueryUserContextFromName = 16,
            QueryUserTokenFromSid = 17,
            QueryUserContextFromSid = 18,
            OpenProcessHandleForAccess = 19,
            OpenProcessTokenForQuery = 20,
            SetCachedCredentials = 21,
            GetCachedCredentials = 22,
            InformFlags = 23,
            ChangeSessionUserToken = 24,
            ConnectLocalUser = 25,
            DisconnectLocalUser = 26,
            GetImpersonationTokenForContext = 27,
            GetDefaultSignInAccount = 28,
            ClearDefaultSignInAccount = 29,
            GetSessionActiveShellUserToken = 30,
            ChangeSessionActiveShellUser = 31,
            IsCandidateUser = 32,
            IsEphemeralCandidateUser = 33,
            GetCandidateAccountCredz = 34,
            ConnectCandidateUser = 35,
            GetNonCandidateUserSessionIds = 36,
            GetCandidateUserSessionIds = 37,
            RefreshCandidateUser = 38,
            CleanupDiscardedCandidateAccounts = 39,
            GetStandardAccessImpersonationTokenForContext = 40,
            NotImplemented41 = 41,
            InformSecondaryUserLogoff = 42,
        }

        // The token access in usermgr's format strings for the shell and impersonation token procedures.
        private const AccessMask ShellTokenAccess = (AccessMask)0x2001E;

        private const int QuotaLimitsSize = 0x30;

        public static NTSTATUS Handle(WinPort Port, byte[] SendData, PortReply Reply, BinaryEmulator Instance)
        {
            if (!LrpcPacket.TryParse(SendData, out LrpcMessage Message))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            switch (Message.Type)
            {
                case LrpcMessageType.Bind:
                    if (!LrpcBindings.TryAccept(Reply.Client.Bindings, Message, InterfaceIds, out _, out Reply.Data))
                        Reply.Data = LrpcPacket.BuildFault(Message, LrpcPacket.RpcSUnknownIf);
                    break;

                case LrpcMessageType.Request:
                    Reply.Data = HandleRequest(Port, Message, Reply, Instance);
                    break;
            }

            Reply.Data ??= LrpcPacket.EchoHeader(SendData);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static byte[] HandleRequest(WinPort Port, in LrpcMessage Message, PortReply Reply, BinaryEmulator Instance)
        {
            if (!LrpcBindings.TryResolve(Reply.Client.Bindings, Message, out Guid Interface, out _))
                return LrpcPacket.BuildFault(Message, LrpcPacket.RpcSUnknownIf);

            if (Interface == UserMarshalData && Message.ProcNumber == ProcGetUserMarshalData)
                return GetUserMarshalData(Message, Instance);

            if (Interface == UserManagerClient)
                return HandleClientRequest(Port, Message, Reply, Instance) ?? Unserved(Port, Message, Instance, Interface);

            return Unserved(Port, Message, Instance, Interface);
        }

        private static byte[] Unserved(WinPort Port, in LrpcMessage Message, BinaryEmulator Instance, Guid Interface)
        {
            if ((Instance.Settings.Flags & LogFlags.General) != 0)
                Instance.TriggerEventMessage($"[!] No server for proc {Message.ProcNumber} of {Interface} on \"{Port?.Name}\"; faulting.", LogFlags.General);
            return LrpcPacket.BuildFault(Message, LrpcPacket.RpcSProcnumOutOfRange);
        }

        private static byte[] NotPerformed(in LrpcMessage Message, ClientProc Proc)
        {
            Utils.LogError($"[-] UserManager: UserMgrCli {Proc} passes its caller checks, and Brovan does not do its work; faulting.");
            return LrpcPacket.BuildFault(Message, LrpcPacket.RpcSProcnumOutOfRange);
        }

        private static byte[] HandleClientRequest(WinPort Port, in LrpcMessage Message, PortReply Reply, BinaryEmulator Instance)
        {
            UserManagerService Service = Instance.WinHelper.UserManager;
            UserManagerService.Caller Caller = Service.CallerOf(Instance);
            Ndr20Reader Reader = new Ndr20Reader(Message.StubData);
            ClientProc Proc = (ClientProc)Message.ProcNumber;
            uint Result;
            WinToken Token;
            WinToken Target;
            ulong Context;

            switch (Proc)
            {
                case ClientProc.QueryUserToken:
                    if (!Reader.TryReadUInt64(out Context))
                        return BadStub(Message);
                    Result = Service.QueryUserToken(Caller, Context, out Token);
                    return TokenAnswer(Message, Reply, Instance, Result, Token, AccessMask.TokenAllAccess);

                case ClientProc.GetConstrainedUserToken:
                {
                    if (!TryReadToken(ref Reader, Reply, Instance, out Target) || !Reader.TryReadUInt64(out Context) || !Reader.TryReadUInt32(out uint Capabilities))
                        return BadStub(Message);
                    Result = UserManagerService.CheckRestrictions(Caller, UserManagerService.AppContainerRefused);
                    Token = null;
                    if (Result == Orpc.SOk)
                    {
                        uint? Constrained = Service.GetConstrainedUserToken(Caller, Target, Capabilities != 0, Context, out Token);
                        if (Constrained == null)
                            return NotPerformed(Message, Proc);
                        Result = Constrained.Value;
                    }

                    return TokenAnswer(Message, Reply, Instance, Result, Token, AccessMask.TokenAllAccess);
                }

                case ClientProc.GetConstrainedUserTokenFromAppcontainer:
                {
                    if (!Reader.TryReadUInt64(out Context))
                        return BadStub(Message);
                    Result = Service.GetConstrainedUserToken(Caller, null, false, Context, out Token).Value;
                    return TokenAnswer(Message, Reply, Instance, Result, Token, AccessMask.TokenAllAccess);
                }

                case ClientProc.IsAllowedToActivateAsUser:
                {
                    if (!TryReadToken(ref Reader, Reply, Instance, out Target) || !Reader.TryReadUInt64(out Context))
                        return BadStub(Message);
                    Result = Service.IsAllowedToActivateAsUser(Caller, Target, Context, out bool Allowed);
                    Ndr20Writer Writer = new Ndr20Writer(0x10);
                    Writer.WriteByte(Allowed ? (byte)1 : (byte)0);
                    Writer.AlignTo(4);
                    Writer.WriteUInt32(Result);
                    return LrpcPacket.BuildResponse(Message, Writer.Written);
                }

                case ClientProc.QueryDefaultAccountToken:
                {
                    uint? Refused = UserManagerService.QueryDefaultAccountToken(Instance, Caller);
                    return Refused == null ? NotPerformed(Message, Proc) : NullHandleAnswer(Message, Refused.Value);
                }

                case ClientProc.QuerySessionVirtualAccountToken:
                    return NullHandleAnswer(Message, UserManagerService.QuerySessionVirtualAccountToken(Caller));

                case ClientProc.QueryUserContext:
                    if (!TryReadToken(ref Reader, Reply, Instance, out Target))
                        return BadStub(Message);
                    Result = Service.QueryUserContext(Caller, Target, out Context);
                    return ContextAnswer(Message, Result, Context);

                case ClientProc.QuerySessionUserToken:
                {
                    if (!Reader.TryReadUInt32(out uint SessionId))
                        return BadStub(Message);
                    return NullHandleAnswer(Message, UserManagerService.QuerySessionUserToken(Caller, SessionId));
                }

                case ClientProc.EnumerateSessionUsers:
                    return SessionUsersAnswer(Message, UserManagerService.EnumerateSessionUsers(Caller));

                case ClientProc.QueryUserTokenFromName:
                case ClientProc.QueryUserTokenFromSid:
                {
                    if (!Reader.TryReadConformantWideString(out string Key))
                        return BadStub(Message);
                    Result = Service.QueryUserTokenFrom(Caller, Key, Proc == ClientProc.QueryUserTokenFromName, out Token);
                    return TokenAnswer(Message, Reply, Instance, Result, Token, AccessMask.TokenAllAccess);
                }

                case ClientProc.QueryUserContextFromName:
                case ClientProc.QueryUserContextFromSid:
                {
                    if (!Reader.TryReadConformantWideString(out string Key))
                        return BadStub(Message);
                    Result = Service.QueryUserContextFrom(Caller, Key, Proc == ClientProc.QueryUserContextFromName, out Context);
                    return ContextAnswer(Message, Result, Context);
                }

                case ClientProc.OpenProcessHandleForAccess:
                case ClientProc.OpenProcessTokenForQuery:
                    // NT refuses both on a multi-session SKU before it checks the caller.
                    if (!UserManagerService.IsMultiSessionSku(Instance))
                        return NotPerformed(Message, Proc);
                    return NullHandleAnswer(Message, Orpc.EUnexpected);

                case ClientProc.GetImpersonationTokenForContext:
                case ClientProc.GetStandardAccessImpersonationTokenForContext:
                {
                    if (!TryReadToken(ref Reader, Reply, Instance, out Target) || !Reader.TryReadUInt64(out Context))
                        return BadStub(Message);
                    uint? Impersonation = Service.GetImpersonationTokenForContext(Caller, Target, Context, out Token);
                    if (Impersonation == null)
                        return NotPerformed(Message, Proc);
                    return TokenAnswer(Message, Reply, Instance, Impersonation.Value, Token, ShellTokenAccess);
                }

                case ClientProc.GetSessionActiveShellUserToken:
                {
                    if (!Reader.TryReadUInt32(out uint SessionId))
                        return BadStub(Message);
                    Result = Service.GetSessionActiveShellUserToken(Caller, SessionId, out Token);
                    return TokenAnswer(Message, Reply, Instance, Result, Token, ShellTokenAccess);
                }

                case ClientProc.ChangeSessionUserToken:
                    if (UserManagerService.IsMultiSessionSku(Instance))
                        return ResultAnswer(Message, Orpc.EUnexpected);
                    return RefusedOrNotPerformed(Message, Proc, Caller, UserManagerService.TcbRequired, ResultAnswer);

                case ClientProc.LaunchShell:
                    return RefusedOrNotPerformed(Message, Proc, Caller, UserManagerService.AppContainerRefused, NullHandleAnswer);

                case ClientProc.SetShellInformation:
                    // NT lets an AppContainer caller set it on a client SKU.
                    return RefusedOrNotPerformed(Message, Proc, Caller,
                        UserManagerService.IsMultiSessionSku(Instance) ? UserManagerService.AppContainerRefused : UserManagerService.AppContainerAllowed, ResultAnswer);

                case ClientProc.ChangeSessionActiveShellUser:
                    return RefusedOrNotPerformed(Message, Proc, Caller, UserManagerService.AppContainerRefused, ResultAnswer);

                case ClientProc.LaunchShellInfrastructureHost:
                case ClientProc.InformUserLogon:
                case ClientProc.InformUserLogoff:
                case ClientProc.SetCachedCredentials:
                case ClientProc.InformFlags:
                case ClientProc.CleanupDiscardedCandidateAccounts:
                case ClientProc.InformSecondaryUserLogoff:
                    return RefusedOrNotPerformed(Message, Proc, Caller, UserManagerService.TcbRequired, ResultAnswer);

                case ClientProc.GetCachedCredentials:
                    return RefusedOrNotPerformed(Message, Proc, Caller, UserManagerService.TcbRequired, ZeroLongAnswer);

                case ClientProc.LogonUser:
                    return RefusedOrNotPerformed(Message, Proc, Caller, UserManagerService.TcbRequired, LogonUserAnswer);

                case ClientProc.GetCandidateAccountCredz:
                case ClientProc.GetNonCandidateUserSessionIds:
                    return Caller.IsLocalSystem ? NotPerformed(Message, Proc) : CountAndPointerAnswer(Message, Orpc.EAccessDenied);

                // No Brovan session signs in a shared-PC candidate account.
                case ClientProc.IsCandidateUser:
                case ClientProc.IsEphemeralCandidateUser:
                    return ZeroLongAnswer(Message, Orpc.SOk);

                case ClientProc.GetCandidateUserSessionIds:
                    return CountAndPointerAnswer(Message, Orpc.SOk);

                case ClientProc.ConnectLocalUser:
                case ClientProc.DisconnectLocalUser:
                case ClientProc.GetDefaultSignInAccount:
                case ClientProc.ClearDefaultSignInAccount:
                    return ResultAnswer(Message, Orpc.EUnexpected);

                case ClientProc.ConnectCandidateUser:
                case ClientProc.RefreshCandidateUser:
                case ClientProc.NotImplemented41:
                    return ResultAnswer(Message, Orpc.ENotImpl);

                default:
                    return null;
            }
        }

        private delegate byte[] Answer(in LrpcMessage Message, uint Result);

        private static byte[] RefusedOrNotPerformed(in LrpcMessage Message, ClientProc Proc, in UserManagerService.Caller Caller, UserManagerService.CallerRestrictions Restrictions, Answer Refusal)
        {
            uint Result = UserManagerService.CheckRestrictions(Caller, Restrictions);
            return Result == Orpc.SOk ? NotPerformed(Message, Proc) : Refusal(Message, Result);
        }

        private static byte[] BadStub(in LrpcMessage Message) => LrpcPacket.BuildFault(Message, LrpcPacket.RpcXBadStubData);

        private static bool TryReadToken(ref Ndr20Reader Reader, PortReply Reply, BinaryEmulator Instance, out WinToken Token)
        {
            Token = null;
            if (!Reader.TryReadSystemHandle(out uint IndexPlusOne))
                return false;

            if (IndexPlusOne == 0)
                return true;

            if (Reply.SentHandles == null || IndexPlusOne > (uint)Reply.SentHandles.Count)
                return false;

            Token = Instance.WinHelper.HandleManager.GetObjectByHandle(Reply.SentHandles[(int)IndexPlusOne - 1]) as WinToken;
            return Token != null;
        }

        private static byte[] ResultAnswer(in LrpcMessage Message, uint Result)
        {
            Ndr20Writer Writer = new Ndr20Writer(0x8);
            Writer.WriteUInt32(Result);
            return LrpcPacket.BuildResponse(Message, Writer.Written);
        }

        private static byte[] NullHandleAnswer(in LrpcMessage Message, uint Result)
        {
            Ndr20Writer Writer = new Ndr20Writer(0x10);
            Writer.WriteSystemHandle(-1);
            Writer.WriteUInt32(Result);
            return LrpcPacket.BuildResponse(Message, Writer.Written);
        }

        // A FALSE long and a null unique pointer are the same four zero bytes.
        private static byte[] ZeroLongAnswer(in LrpcMessage Message, uint Result)
        {
            Ndr20Writer Writer = new Ndr20Writer(0x10);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(Result);
            return LrpcPacket.BuildResponse(Message, Writer.Written);
        }

        // A count, then a unique pointer to that many elements.
        private static byte[] CountAndPointerAnswer(in LrpcMessage Message, uint Result)
        {
            Ndr20Writer Writer = new Ndr20Writer(0x10);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(Result);
            return LrpcPacket.BuildResponse(Message, Writer.Written);
        }

        private static byte[] ContextAnswer(in LrpcMessage Message, uint Result, ulong Context)
        {
            Ndr20Writer Writer = new Ndr20Writer(0x10);
            Writer.WriteUInt64(Context);
            Writer.WriteUInt32(Result);
            return LrpcPacket.BuildResponse(Message, Writer.Written);
        }

        private static byte[] TokenAnswer(in LrpcMessage Message, PortReply Reply, BinaryEmulator Instance, uint Result, WinToken Token, AccessMask Access)
        {
            int TokenIndex = -1;
            if (Token != null)
            {
                TokenIndex = Reply.Handles?.Count ?? 0;
                Reply.AttachHandle(Instance.WinHelper.OpenObjectHandle(Token, Access).Handle);
            }

            Ndr20Writer Writer = new Ndr20Writer(0x20);
            Writer.WriteSystemHandle(TokenIndex);
            Writer.WriteUInt32(Result);
            return LrpcPacket.BuildResponse(Message, Writer.Written);
        }

        // One _RPC_SESSION_USER_CONTEXT, which is the user context, the session id and a reserved long.
        private static byte[] SessionUsersAnswer(in LrpcMessage Message, uint Result)
        {
            if (Result != Orpc.SOk)
                return CountAndPointerAnswer(Message, Result);

            Ndr20Writer Writer = new Ndr20Writer(0x40);
            Writer.WriteUInt32(1);
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32(1);
            Writer.WriteUInt64(WinToken.InteractiveUserContext);
            Writer.WriteUInt32(WinToken.InteractiveSessionId);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(Result);
            return LrpcPacket.BuildResponse(Message, Writer.Written);
        }

        // Three longs, a null profile buffer, the hyper, the LUID from the last 8 bytes of the request, a null token and
        // zero quota limits.
        private static byte[] LogonUserAnswer(in LrpcMessage Message, uint Result)
        {
            ReadOnlySpan<byte> Request = Message.StubData;
            if (Request.Length < 8)
                return BadStub(Message);

            Ndr20Writer Writer = new Ndr20Writer(0x80);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt64(0);
            Writer.WriteBytes(Request.Slice(Request.Length - 8));
            Writer.WriteSystemHandle(-1);
            Writer.AlignTo(8);
            Writer.WriteZeros(QuotaLimitsSize);
            Writer.WriteUInt32(Result);
            return LrpcPacket.BuildResponse(Message, Writer.Written);
        }

        // USER_DATA is a unique pointer, allocated whole, to two unique strings: NonRoamableId and AccountName.
        private static byte[] GetUserMarshalData(in LrpcMessage Message, BinaryEmulator Instance)
        {
            Ndr20Reader Reader = new Ndr20Reader(Message.StubData);
            if (!Reader.TryReadUInt32(out uint MarshalId))
                return LrpcPacket.BuildFault(Message, LrpcPacket.RpcXBadStubData);

            uint Result = Instance.WinHelper.UserManager.GetUserData(Instance, MarshalId, out string NonRoamableId, out string AccountName);
            Ndr20Writer Writer = new Ndr20Writer(0x80);
            if (Result != Orpc.SOk)
            {
                Writer.WriteUInt32(0);
            }
            else
            {
                Writer.WriteUniqueReferent();
                Writer.WriteUniqueReferent();
                Writer.WriteUniqueReferent();
                Writer.WriteConformantWideString(NonRoamableId);
                Writer.WriteConformantWideString(AccountName);
            }

            Writer.WriteUInt32(Result);
            return LrpcPacket.BuildResponse(Message, Writer.Written);
        }
    }
}
