using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Brovan.Core.Emulation.OS.Windows.RPC.Ports;
using Brovan.Core.Helpers;
using static Brovan.Core.Emulation.OS.Windows.NtQueryInformationToken;

namespace Brovan.Core.Emulation.OS.Windows.RPC.UserManager
{
    internal sealed class UserManagerService
    {
        internal const string StaticsClassId = "Windows.System.Internal.UserManager";

        private const uint ErrorNoSuchLogonSession = 0x80070520;
        private const uint ErrorNoPackage = 0x80073D54;
        private const uint ErrorNotSupported = 0x80070032;
        private const uint ErrorPrivilegeNotHeld = 0x80070522;
        private const uint ErrorNoToken = 0x800703F0;
        private const uint NteNotFound = 0x80090011;
        private const uint ServiceSessionId = 0;

        private const uint CallerAccess = 1;

        // NT: usermgr checks its callers against SYSTEM as owner and group, a medium label with NO_READ_UP, and access 1
        // for SYSTEM and PRINCIPAL_SELF.
        private static readonly byte[] CallerDescriptor = NtAccessCheck.BuildSelfRelative(LocalSystemSid, LocalSystemSid,
            NtAccessCheck.BuildAcl(NtAccessCheck.AceEntry.Allow(LocalSystemSid, CallerAccess), NtAccessCheck.AceEntry.Allow(PrincipalSelfSid, CallerAccess)),
            NtAccessCheck.BuildAcl(NtAccessCheck.AceEntry.MandatoryLabel(BuildSid(16, MediumIntegrityRid), NtAccessCheck.MandatoryNoReadUp)));
        private static readonly GENERIC_MAPPING CallerMapping = new GENERIC_MAPPING { GenericRead = 0x20001, GenericWrite = 0x20000, GenericExecute = 0x20000, GenericAll = 0x1F0001 };

        private static readonly byte[] SignInSupportCapability = AppxPackageModel.DeriveCapabilitySid("userSigninSupport");
        private static readonly byte[] ShellExperienceCapability = AppxPackageModel.DeriveCapabilitySid("shellExperience");

        // NT: a user's NonRoamableId is the decimal user id.
        private static readonly string UserNonRoamableId = WinToken.InteractiveUserId.ToString(CultureInfo.InvariantCulture);

        internal SessionUserObject User { get; }

        private readonly WinProcess Process;

        // NT keeps the limited token of the user's logon.
        private readonly WinToken UserToken = WinToken.CreatePrimary(Windows.User.Standard, 0);

        // NT: GetFromId finds a per-app id for any caller (UserStatics::GetNonRoamableIdForUserAndApp).
        private readonly HashSet<string> AppNonRoamableIds = new(StringComparer.OrdinalIgnoreCase);

        private UserManagerService(WinProcess Process)
        {
            this.Process = Process;
            User = new SessionUserObject(Process.PID);
        }

        internal static UserManagerService Create(WinSysHelper Helper, WinProcess Process, HostApartment Apartment)
        {
            UserManagerService Service = new UserManagerService(Process);
            string Endpoint = LrpcClient.NewDynamicEndpoint();
            Helper.WinPorts.Add(new WinPort { Name = LrpcClient.GetPortName(Endpoint), Handler = UserManagerRpcPortHandler.Handle });
            foreach (EndpointMapper.RpcInterface Served in UserManagerRpcPortHandler.Interfaces)
            {
                if (!EndpointMapper.RegisterEndpoint(Helper, Served, Endpoint, Process))
                    Utils.LogError($"[-] UserManager: interface {Served.Id} could not be mapped to {Endpoint}.");
            }

            RpcssPortHandler.RegisterActivatableClass(Helper, StaticsClassId, Apartment, new UserManagerStatics(Service.User));
            RpcssPortHandler.RegisterActivatableClass(Helper, UserStatics.ClassId, Apartment, new UserStatics(Service));
            return Service;
        }

        // NT: UserStatics::GetDefault gives the default account's user, else the user of the caller's token.
        internal SessionUserObject DefaultUser(BinaryEmulator Instance, out uint Result)
        {
            WinToken Caller = EffectiveToken(Instance);
            bool SessionUser = Caller != null && IsSessionUser(Caller);
            Result = SessionUser ? Orpc.SOk : ErrorNoSuchLogonSession;
            return SessionUser ? User : null;
        }

        // The checks and their order follow UserStatics::TryFindUserByNonRoamableId.
        internal SessionUserObject FindUser(BinaryEmulator Instance, ReadOnlySpan<char> NonRoamableId)
        {
            WinToken Caller = EffectiveToken(Instance);
            if (Caller == null)
                return null;

            if ((PassesAccessCheck(Caller, out _) || HasSignInCapability(Caller)) && IsSameSession(Caller)
                && NonRoamableId.Equals(UserNonRoamableId, StringComparison.OrdinalIgnoreCase))
                return User;

            return AppNonRoamableIds.GetAlternateLookup<ReadOnlySpan<char>>().Contains(NonRoamableId) ? User : null;
        }

        private bool IsSameSession(WinToken Caller) => Caller.SessionId == Process.GetPrimaryToken().SessionId || Caller.SessionId == WinToken.InteractiveSessionId;

        private static bool PassesAccessCheck(WinToken Caller, out byte[] CallerSid)
        {
            CallerSid = UserSidOf(Caller);
            return NtAccessCheck.CheckHost(CallerDescriptor, Caller, CallerSid, CallerAccess, CallerMapping, out _) == NTSTATUS.STATUS_SUCCESS;
        }

        private static bool HasSignInCapability(WinToken Caller) => Caller.HasCapability(SignInSupportCapability) || Caller.HasCapability(ShellExperienceCapability);

        internal readonly record struct Caller(WinToken Token, bool PassesAccessCheck)
        {
            internal bool HoldsTcb => Token != null && HoldsTcbPrivilege(Token);
            internal bool IsAppContainer => Token?.IsAppContainer == true;
            internal bool HoldsImpersonate => Token != null && HoldsImpersonatePrivilege(Token);
            internal bool IsLocalSystem => Token?.User == Windows.User.System;
        }

        internal readonly record struct CallerRestrictions(bool RequireTcb, bool AllowAppContainer, bool RequireImpersonate);

        internal static readonly CallerRestrictions TcbRequired = new(true, false, false);
        internal static readonly CallerRestrictions AppContainerAllowed = new(false, true, false);
        internal static readonly CallerRestrictions AppContainerRefused = new(false, false, false);
        internal static readonly CallerRestrictions ImpersonateRequired = new(false, false, true);

        internal Caller CallerOf(BinaryEmulator Instance)
        {
            WinToken Token = EffectiveToken(Instance);
            return Token == null ? default : new Caller(Token, PassesAccessCheck(Token, out _));
        }

        // The checks and their order follow UserMgrCli::CheckApiRestrictionsForCaller.
        internal static uint CheckRestrictions(in Caller Caller, CallerRestrictions Restrictions)
        {
            if (!Caller.HoldsTcb && Restrictions.RequireTcb)
                return ErrorPrivilegeNotHeld;

            if (Caller.IsAppContainer && !Restrictions.AllowAppContainer)
                return Orpc.EAccessDenied;

            if (!Caller.PassesAccessCheck && !Caller.IsAppContainer)
                return Orpc.EAccessDenied;

            if (!Caller.HoldsImpersonate && Restrictions.RequireImpersonate)
                return ErrorPrivilegeNotHeld;

            return Orpc.SOk;
        }

        // No Brovan token holds the multi-user capability, so the caller must be the user.
        private bool IsValidCallerForUser(in Caller Caller) => Caller.Token != null && IsSameSession(Caller.Token) && IsSessionUser(Caller.Token);

        private static bool IsSessionUser(WinToken Token) => UserSidOf(Token).AsSpan().SequenceEqual(InteractiveUserSid);

        // NT matches the user in any session for a lookup from the service session.
        private static bool IsUserSession(uint SessionId) => SessionId == ServiceSessionId || SessionId == WinToken.InteractiveSessionId;

        private WinToken DuplicateUserToken(in Caller Caller) => Caller.HoldsTcb
            ? UserToken.Duplicate(TokenType.Primary, SecurityImpersonationLevel.SecurityImpersonation, false)
            : UserToken.Duplicate(TokenType.Impersonation, SecurityImpersonationLevel.SecurityIdentification, false);

        internal uint QueryUserToken(in Caller Caller, ulong Context, out WinToken Token)
        {
            Token = null;
            if (!Caller.PassesAccessCheck && !Caller.IsAppContainer)
                return Orpc.EAccessDenied;

            if (Context == 0)
                return Orpc.EInvalidArg;

            // NT then tries the default account's user, which no Brovan session signs in.
            if (Context != WinToken.InteractiveUserContext)
                return ErrorNotSupported;

            if (!IsValidCallerForUser(Caller))
                return ErrorNoSuchLogonSession;

            Token = DuplicateUserToken(Caller);
            return Orpc.SOk;
        }

        internal uint QueryUserContext(in Caller Caller, WinToken Target, out ulong Context)
        {
            Context = 0;
            if (!Caller.PassesAccessCheck && !Caller.IsAppContainer)
                return Orpc.EAccessDenied;

            if (Caller.IsAppContainer && Target != null)
                return Orpc.EAccessDenied;

            Target ??= Caller.Token;
            if (Target == null || !IsSessionUser(Target) || !IsUserSession(Target.SessionId) || !IsValidCallerForUser(Caller))
                return ErrorNoSuchLogonSession;

            Context = WinToken.InteractiveUserContext;
            return Orpc.SOk;
        }

        // The checks and their order follow UserMgrCli::QueryUserTokenFromSid and QueryUserTokenFromName.
        private uint LookUpUser(in Caller Caller, string Key, bool ByName)
        {
            uint Result = CheckRestrictions(Caller, AppContainerAllowed);
            if (Result != Orpc.SOk)
                return Result;

            bool Found = Caller.Token != null && (ByName
                ? Caller.Token.SessionId == WinToken.InteractiveSessionId && string.Equals(Key, WinSysHelper.CurrentUserName, StringComparison.OrdinalIgnoreCase)
                : IsUserSession(Caller.Token.SessionId) && string.Equals(Key, InteractiveUserSidText, StringComparison.OrdinalIgnoreCase));
            return Found && IsValidCallerForUser(Caller) ? Orpc.SOk : ErrorNoSuchLogonSession;
        }

        internal uint QueryUserTokenFrom(in Caller Caller, string Key, bool ByName, out WinToken Token)
        {
            uint Result = LookUpUser(Caller, Key, ByName);
            Token = Result == Orpc.SOk ? DuplicateUserToken(Caller) : null;
            return Result;
        }

        internal uint QueryUserContextFrom(in Caller Caller, string Key, bool ByName, out ulong Context)
        {
            uint Result = LookUpUser(Caller, Key, ByName);
            Context = Result == Orpc.SOk ? WinToken.InteractiveUserContext : 0;
            return Result;
        }

        // Brovan keeps no token for the service session.
        internal static uint QuerySessionUserToken(in Caller Caller, uint SessionId)
        {
            if (SessionId != ServiceSessionId)
                return ErrorNotSupported;

            uint Result = CheckRestrictions(Caller, AppContainerRefused);
            return Result != Orpc.SOk ? Result : ErrorNoToken;
        }

        // No Brovan session has a virtual account.
        internal static uint QuerySessionVirtualAccountToken(in Caller Caller)
        {
            uint Result = CheckRestrictions(Caller, TcbRequired);
            return Result != Orpc.SOk ? Result : NteNotFound;
        }

        // NT signs in no default account on a multi-session SKU.
        internal static uint? QueryDefaultAccountToken(BinaryEmulator Instance, in Caller Caller)
        {
            uint Result = CheckRestrictions(Caller, TcbRequired);
            if (Result != Orpc.SOk)
                return Result;

            return IsMultiSessionSku(Instance) ? ErrorNoSuchLogonSession : null;
        }

        internal uint GetSessionActiveShellUserToken(in Caller Caller, uint SessionId, out WinToken Token)
        {
            Token = null;
            uint Result = CheckRestrictions(Caller, AppContainerRefused);
            if (Result != Orpc.SOk)
                return Result;

            if (SessionId != WinToken.InteractiveSessionId || !IsValidCallerForUser(Caller))
                return ErrorNoSuchLogonSession;

            Token = DuplicateUserToken(Caller);
            return Orpc.SOk;
        }

        // No Brovan token holds the constrainedImpersonation capability, so NT gives a plain copy of the token.
        internal uint? GetConstrainedUserToken(in Caller Caller, WinToken Target, bool HasCapabilities, ulong Context, out WinToken Token)
        {
            Token = null;
            if (Context == 0)
                return Orpc.EInvalidArg;

            if (HasCapabilities)
                return null;

            if (Context != WinToken.InteractiveUserContext || !IsValidCallerForUser(Caller))
                return ErrorNoSuchLogonSession;

            if (Target == null)
            {
                Token = Caller.Token.Duplicate(TokenType.Impersonation, SecurityImpersonationLevel.SecurityImpersonation, false);
                return Orpc.SOk;
            }

            // NT copies the passed token through a TOKEN_QUERY handle, which fails, and gives none for another user.
            return IsSessionUser(Target) ? Orpc.EAccessDenied : Orpc.SOk;
        }

        internal uint IsAllowedToActivateAsUser(in Caller Caller, WinToken Target, ulong Context, out bool Allowed)
        {
            Allowed = false;
            if (Context == 0 || Target == null)
                return Orpc.EInvalidArg;

            // NT then tries the default account's user, which no Brovan session signs in.
            if (Context != WinToken.InteractiveUserContext)
                return ErrorNotSupported;

            if (!IsValidCallerForUser(Caller))
                return ErrorNoSuchLogonSession;

            Allowed = IsSessionUser(Target) || (!Target.IsAppContainer && HoldsImpersonatePrivilege(Target));
            return Orpc.SOk;
        }

        internal static uint EnumerateSessionUsers(in Caller Caller)
        {
            if (Caller.IsAppContainer || !Caller.PassesAccessCheck || (!Caller.HoldsTcb && Caller.Token.SessionId != ServiceSessionId))
                return Orpc.EAccessDenied;

            return Orpc.SOk;
        }

        internal uint? GetImpersonationTokenForContext(in Caller Caller, WinToken Target, ulong Context, out WinToken Token)
        {
            Token = null;
            uint Result = CheckRestrictions(Caller, ImpersonateRequired);
            if (Result != Orpc.SOk)
                return Result;

            if (Target == null || Target.IsAppContainer)
                return Orpc.EAccessDenied;

            if (Target.SessionId != WinToken.InteractiveSessionId)
                return null;

            if (!IsSessionUser(Target))
                return Orpc.EAccessDenied;

            if (Context != WinToken.InteractiveUserContext)
                return ErrorNoSuchLogonSession;

            Token = UserToken.Duplicate(TokenType.Impersonation, SecurityImpersonationLevel.SecurityImpersonation, false);
            return Orpc.SOk;
        }

        internal static bool IsMultiSessionSku(BinaryEmulator Instance) => Instance.WinHelper.KuserSharedData?.IsMultiSessionSku == true;

        internal uint GetUserData(BinaryEmulator Instance, uint MarshalId, out string NonRoamableId, out string AccountName)
        {
            NonRoamableId = null;
            AccountName = null;
            WinToken Caller = EffectiveToken(Instance);
            if (MarshalId != SessionUserObject.MarshalId || Caller == null)
                return ErrorNoSuchLogonSession;

            bool AccessGranted = PassesAccessCheck(Caller, out byte[] CallerSid);

            // No Brovan token holds the multi-user capability, so every caller must be the session user.
            if (!CallerSid.AsSpan().SequenceEqual(InteractiveUserSid) || (AccessGranted && !IsSameSession(Caller)))
                return ErrorNoSuchLogonSession;

            if (!Caller.IsAppContainer || AccessGranted || HasSignInCapability(Caller))
            {
                NonRoamableId = UserNonRoamableId;
                AccountName = WinSysHelper.CurrentUserName;
                return Orpc.SOk;
            }

            string Family = Caller.PackageFamilyName;
            if (Family == null)
                return ErrorNoPackage;

            // NT hashes the user id, the package family and the session into an app's id (UserStatics::GetNonRoamableIdForUserAndApp).
            string Source = UserNonRoamableId + Family + WinToken.InteractiveSessionId.ToString(CultureInfo.InvariantCulture);
            NonRoamableId = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(Source)));
            AppNonRoamableIds.Add(NonRoamableId);
            AccountName = string.Empty;
            return Orpc.SOk;
        }
    }
}
