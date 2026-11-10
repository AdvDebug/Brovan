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
            if (!EndpointMapper.RegisterEndpoint(Helper, UserManagerRpcPortHandler.Interface, Endpoint, Process))
                Utils.LogError($"[-] UserManager: interface {UserManagerRpcPortHandler.Interface.Id} could not be mapped to {Endpoint}.");

            RpcssPortHandler.RegisterActivatableClass(Helper, StaticsClassId, Apartment, new UserManagerStatics(Service.User));
            RpcssPortHandler.RegisterActivatableClass(Helper, UserStatics.ClassId, Apartment, new UserStatics(Service));
            return Service;
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
