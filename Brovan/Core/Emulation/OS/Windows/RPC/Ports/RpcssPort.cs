using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Ports
{
    // The RPCSS object resolver on the endpoint mapper port.
    internal static class RpcssPortHandler
    {
        public const string PortName = "\\RPC Control\\epmapper";

        private static readonly Guid LocalObjectExporter = new Guid("e60c73e6-88f9-11cf-9af1-0020af6e72f4");
        private static readonly Guid Scm = new Guid("412f241e-c12a-11ce-abff-0020af6e7a17");
        private static readonly Guid ScmLocalActivator = new Guid("00000136-0000-0000-c000-000000000046");
        private static readonly Guid LocalSystemActivator = new Guid("00000132-0000-0000-c000-000000000046");
        private static readonly Guid ErrorExtension = new Guid("0000031c-0000-0000-c000-000000000046");
        private static readonly Guid RestrictedErrorObject = new Guid("00000352-0000-0000-c000-000000000046");
        private static readonly Guid ActivationPropertiesOut = new Guid("00000339-0000-0000-c000-000000000046");
        private static readonly Guid ActivationPropertiesOutInterface = new Guid("000001a3-0000-0000-c000-000000000046");
        private static readonly Guid InstantiationInfo = new Guid("000001ab-0000-0000-c000-000000000046");
        private static readonly Guid ScmReplyInfo = new Guid("000001b6-0000-0000-c000-000000000046");
        private static readonly Guid WinRtActivationProperties = new Guid("9fc104cb-0379-43b5-a1a0-ce1260700e0a");
        private static readonly Guid[] ServedInterfaces = { LocalObjectExporter, Scm, ScmLocalActivator, EndpointMapper.Interface };

        // The flat part of ComWinRTActivationProperties on the wire. The class id is the first pointee after it.
        private const int WinRtPropertiesFlatSize = 64;

        // Opnums from this build's combase lclor and scm format strings.
        private const uint ProcConnect = 0;
        private const uint ProcSetAppId = 1;
        private const uint ProcAllocateReservedIds = 3;
        private const uint ProcBulkUpdateOIDs = 4;
        private const uint ProcClientResolveOXID = 5;
        private const uint ProcServerAllocateOXIDAndOIDs = 6;
        private const uint ProcServerAllocateOIDs = 7;
        private const uint ProcServerFreeOXIDAndOIDs = 8;
        private const uint ProcDisconnect = 10;
        private const uint ProcNotifyStarted = 0;
        private const uint ProcNotifyStopped = 1;
        private const uint ProcRegisterWindowPropInterface = 6;
        private const uint ProcGetWindowPropInterface = 7;
        private const uint ProcNotifyDragDropStartOrStop = 13;
        private const uint ProcGetClassObject = 3;
        private const uint ProcCreateInstance = 4;

        private const int ProxyDecodeInfoSize = 96;
        private const int PingPeriodSeconds = 120;
        private const uint ScmProcessId = 0x3F8;

        // Any rpcss thread id works, because a server reads only the process id of its caller.
        private const uint ScmThreadId = 0x400;
        private const uint AuthnLevelConnect = 2;
        private const uint ImpLevelIdentify = 2;
        private const uint MaximumIds = 0x100000;

        internal const uint ComRightsExecute = 0x1;
        private const uint ComRightsExecuteLocal = 0x2;
        private const uint ComRightsExecuteRemote = 0x4;
        private const uint ComRightsActivateLocal = 0x8;
        private const uint ComRightsActivateRemote = 0x10;

        private const string OleKey = "\\Registry\\Machine\\Software\\Microsoft\\Ole";
        private const string DcomPolicyKey = "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows NT\\DCOM";
        private const string MachineAccessRestriction = "MachineAccessRestriction";
        private const int MinimumRegistryDescriptorBytes = 0x28;

        // NDR carries __int3264 in four bytes.
        private const int HwndOffset = Ndr20Writer.ContextHandleSize;
        private const int StdObjRefOffset = HwndOffset + 4;
        private const int RevokeOffset = HwndOffset + 8;

        private const uint OrOk = 0;
        private const uint OrBadOxid = 1910;
        private const uint RpcETooLate = 0x80010119;
        private const int FreeOxidOffset = 24;

        private const uint RegdbEClassNotReg = 0x80040154;
        private const uint CoEServerStopping = 0x80080008;

        // _RegInput entries: CLSID, OXID, IPID, REGCLS flags and service id.
        private const int RegistrationEntrySize = 48;
        private const int RegistrationFormOffset = Ndr20Writer.ContextHandleSize;
        private const int OldFormEntriesOffset = (RegistrationFormOffset + 2 * sizeof(uint) + 7) & ~7;
        private const uint MaxRegistrations = 0x1000;
        private const uint MaxPackageGraph = 0x400;

        // REGCLS_SINGLEUSE is the value 0 of these bits.
        private const uint RegclsUseMask = 3;

        // NT: rpcss sets this ORPCTHIS flag on the activation it forwards and gives its LOCALTHIS a new call id
        // (CServerListEntry::CallServer).
        private const uint ForwardedOrpcFlag = 0x8;
        private const int OrpcThisFlagsOffset = 4;

        private const int SerializationHeaderSize = 0x10;
        private const int ActivationBlobPrefixSize = 8;
        private const ulong SerializationCommonHeader = 0xCCCCCCCC00081001;
        private const uint MaxActivationProperties = 10;

        // The flat part of an OXID_INFO as NDR lays it out.
        internal const int OxidInfoSize = 0x80;
        private const int OxidInfoProcessId = 0x04;
        private const int OxidInfoAuthnHint = 0x08;
        private const int OxidInfoVersion = 0x0C;
        private const int OxidInfoContainerVersion = 0x10;
        private const int OxidInfoExtensions = 0x20;
        private const int OxidInfoRemUnknownIpid = 0x24;
        private const int OxidInfoFlags = 0x34;
        private const int OxidInfoBindings = 0x38;
        private const int OxidInfoProcessIdentifier = 0x3C;
        private const int OxidInfoHstrings = 0x5C;
        private const int OxidInfoPrimaryOxid = 0x68;
        private const int OxidInfoPrimaryRemUnknownIpid = 0x70;

        // The package name, the user SID and the AppContainer SID of an OXID_INFO.
        private const int OxidInfoHstringCount = 3;
        private const string LocalBindingPrefix = "ncalrpc:[";

        private const uint MultithreadedApartmentTid = 0xFFFFFFFF;
        private const uint ContainerVersion = 3;
        private const uint HostOxidFlags = 0x02000000;
        private const ushort AuthnWinNt = 10;
        private const ushort AuthzNone = 0xFFFF;

        // rpcss sends the system message text as the error description.
        private const string ClassNotRegisteredText = "Class not registered\r\n";
        private static readonly byte[] ClassNotRegisteredReply = BuildActivationFailure(RegdbEClassNotReg, ClassNotRegisteredText);
        private static readonly byte[][] BuiltInDescriptors = BuildBuiltInDescriptors();

        private static readonly Dictionary<uint, byte[]> WindowProps = new Dictionary<uint, byte[]>();
        private static readonly Guid ResolverHandle = Guid.NewGuid();
        private static readonly Guid ProcessIdentifier = Guid.NewGuid();
        private static readonly ulong ProcessSignature = Orpc.NewId();

        // NT: one resolver serves the machine, so every process of the session reports one MID.
        private static readonly ulong LocalMachineId = SessionNames.Hash(GuestSession.SessionId);

        // SecurityBindings keeps the two terminators of the list.
        internal readonly record struct ServerOxid(byte[] Info, string Endpoint, string SecurityBindings, string PackageFullName, string UserSid, string AppContainerSid)
        {
            internal Guid RemUnknownIpid => new Guid(Info.AsSpan(OxidInfoRemUnknownIpid, 16));
        }

        internal readonly record struct HostClass(HostApartment Apartment, HostObject Object);

        private static readonly Dictionary<ulong, ServerOxid> ServerOxids = new Dictionary<ulong, ServerOxid>();

        internal readonly record struct ClassRegistration(uint Key, Guid Class, ulong Oxid, Guid Ipid, uint Flags, uint ProcessId, byte[] UserSid,
            string PackageFullName);

        internal readonly struct LaunchKey
        {
            internal LaunchKey(Guid Class, bool PerPackage, string PackageFullName, byte[] UserSid)
            {
                this.Class = Class;
                this.PerPackage = PerPackage;
                this.PackageFullName = PerPackage ? PackageFullName ?? string.Empty : string.Empty;
                this.UserSid = UserSid;
            }

            internal Guid Class { get; }
            internal bool PerPackage { get; }
            internal string PackageFullName { get; }
            internal byte[] UserSid { get; }
        }

        private static readonly Dictionary<uint, ClassRegistration> Registrations = new Dictionary<uint, ClassRegistration>();
        private static uint NextRegistrationKey;

        private static readonly List<PendingActivation> Launching = new List<PendingActivation>();

        // rpcss makes one primary OXID per process at its first registration and returns it from every one.
        private static ulong PrimaryOxid;
        private static Guid ProcessAppId;
        private static uint NextCookie = 1;

        internal static void RegisterClass(WinSysHelper Helper, Guid Class, HostApartment Apartment, HostObject Object)
        {
            Helper.HostClasses[Class] = new HostClass(Apartment, Object);
        }

        internal static void RegisterActivatableClass(WinSysHelper Helper, string ClassId, HostApartment Apartment, HostObject Factory)
        {
            Helper.HostActivatableClasses[ClassId] = new HostClass(Apartment, Factory);
        }

        public static bool TryHandle(WinPort Port, PortReply Served, in LrpcMessage Message, BinaryEmulator Instance, out byte[] Reply)
        {
            Reply = null;

            if (Port == null || !string.Equals(Port.Name, PortName, StringComparison.OrdinalIgnoreCase))
                return false;

            if (Message.Type == LrpcMessageType.Bind)
                return LrpcBindings.TryAccept(Served.Client.Bindings, Message, ServedInterfaces, out _, out Reply);

            if (Message.Type != LrpcMessageType.Request || !LrpcBindings.TryResolve(Served.Client.Bindings, Message, out Guid Target, out _))
                return false;

            if (Target == ScmLocalActivator)
            {
                Reply = HandleScmLocalActivator(Message, Served, Instance);
                return Reply != null || Served.Deferred != null;
            }

            if (Target == EndpointMapper.Interface)
            {
                Reply = EndpointMapper.Handle(Message, Instance);
                return Reply != null;
            }

            byte[] Stub = null;
            if (Target == LocalObjectExporter)
                Stub = HandleLocalObjectExporter(Message.ProcNumber, Message.StubData, Instance);
            else if (Target == Scm)
                Stub = HandleScm(Message.ProcNumber, Message.StubData, Instance);

            if (Stub == null)
                return false;

            Reply = LrpcPacket.BuildResponse(Message, Stub);
            return true;
        }

        private static byte[] HandleLocalObjectExporter(uint ProcNumber, ReadOnlySpan<byte> Stub, BinaryEmulator Instance)
        {
            switch (ProcNumber)
            {
                case ProcConnect:
                    return Connect(Stub, Instance.WinHelper);

                case ProcSetAppId:
                    return SetAppId(Stub);

                case ProcAllocateReservedIds:
                    return AllocateReservedIds(Stub);

                case ProcBulkUpdateOIDs:
                    return BulkUpdateOIDs(Stub);

                case ProcClientResolveOXID:
                    return ClientResolveOXID(Stub, Instance);

                case ProcServerAllocateOXIDAndOIDs:
                    return ServerAllocateOXIDAndOIDs(Stub);

                case ProcServerAllocateOIDs:
                    return ServerAllocateOIDs(Stub);

                case ProcServerFreeOXIDAndOIDs:
                    return ServerFreeOXIDAndOIDs(Stub);

                case ProcDisconnect:
                    return Disconnect();
            }

            return null;
        }

        private static byte[] HandleScm(uint ProcNumber, ReadOnlySpan<byte> Stub, BinaryEmulator Instance)
        {
            switch (ProcNumber)
            {
                case ProcNotifyStarted:
                    return NotifyStarted(Stub, Instance);

                case ProcNotifyStopped:
                    return NotifyStopped(Stub);

                case ProcRegisterWindowPropInterface:
                    return RegisterWindowPropInterface(Stub);

                case ProcGetWindowPropInterface:
                    return GetWindowPropInterface(Stub);

                case ProcNotifyDragDropStartOrStop:
                    return BuildStatusAndResult(OrOk, 0);
            }

            return null;
        }

        private static byte[] HandleScmLocalActivator(in LrpcMessage Message, PortReply Served, BinaryEmulator Instance)
        {
            uint ProcNumber = Message.ProcNumber;
            if (ProcNumber != ProcGetClassObject && ProcNumber != ProcCreateInstance)
                return null;

            if (!TryReadActivationBlob(Message.StubData, ProcNumber == ProcCreateInstance, out ReadOnlySpan<byte> Blob)
                || !TryFindProperty(Blob, InstantiationInfo, out ReadOnlySpan<byte> Info) || !TryReadInstantiationInfo(Info, out Guid Class, out ReadOnlySpan<byte> Interfaces))
                return null;

            if (TryResolveHostClass(Instance.WinHelper, ProcNumber, Class, Blob, out HostClass Host))
                return BuildActivationReply(Message, Instance, Host, Interfaces);

            PendingActivation Forward = Class == Guid.Empty ? null : StartForward(Message, Class, Instance);
            if (Forward == null)
                return LrpcPacket.BuildResponse(Message, ClassNotRegisteredReply);

            if (Forward.Reply != null)
                return Forward.Reply;

            DeferredAnswer Answer = Served.TakeDeferredAnswer();
            if (Answer == null)
            {
                Forward.End();
                Utils.LogError($"[-] RPCSS: the activation of {Class} cannot wait for its server here.");
                return LrpcPacket.BuildResponse(Message, ClassNotRegisteredReply);
            }

            Forward.AnswerThrough(Answer);
            return null;
        }

        private static byte[] NotifyStarted(ReadOnlySpan<byte> Stub, BinaryEmulator Instance)
        {
            if (!TryReadRegistrations(Stub, out ReadOnlySpan<byte> Entries, out uint Count))
                return null;

            if (Registrations.Count + Count > MemoryBudget.RpcssRegistrations)
            {
                Utils.LogError($"[-] RPCSS: a process registers more than {MemoryBudget.RpcssRegistrations} class objects.");
                Ndr20Writer Refused = new Ndr20Writer(12);
                Refused.WriteUInt32(0);
                Refused.WriteUInt32(OrOk);
                Refused.WriteUInt32(Orpc.EOutOfMemory);
                return Refused.ToArray();
            }

            WinToken Token = NtQueryInformationToken.EffectiveToken(Instance);
            byte[] UserSid = Token == null ? Array.Empty<byte>() : NtQueryInformationToken.UserSidOf(Token);
            string Package = Token?.PackageFullName ?? string.Empty;

            Ndr20Writer Writer = new Ndr20Writer(32 + (int)Count * sizeof(uint));
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32(Count);
            Writer.WriteUInt32(Count);
            for (int i = 0; i < Count; i++)
            {
                ReadOnlySpan<byte> Entry = Entries.Slice(i * RegistrationEntrySize, RegistrationEntrySize);
                if (++NextRegistrationKey == 0)
                    NextRegistrationKey = 1;

                ClassRegistration Registration = new ClassRegistration(NextRegistrationKey, new Guid(Entry.Slice(0, 16)), BinaryPrimitives.ReadUInt64LittleEndian(Entry.Slice(16)),
                    new Guid(Entry.Slice(24, 16)), BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(40)), Instance.WinHelper.PID, UserSid, Package);
                Registrations[Registration.Key] = Registration;

                if ((Registration.Flags & RegclsUseMask) == 0)
                    Utils.LogError($"[-] RPCSS: {Registration.Class} is registered for a single use; other processes do not see it.");
                else
                    RpcssSessionTable.PublishRegistration(Registration);

                Writer.WriteUInt32(Registration.Key);
            }

            // Activations in any process may wait for this server.
            SessionPump.RingAll();

            Writer.WriteUInt32(OrOk);
            Writer.WriteUInt32(Orpc.SOk);
            return Writer.ToArray();
        }

        // Newer builds send the package graph before _RegInput. The old form is only _RegInput, whose conformance
        // equals its count.
        private static bool TryReadRegistrations(ReadOnlySpan<byte> Stub, out ReadOnlySpan<byte> Entries, out uint Count)
        {
            Entries = default;
            Count = 0;
            if (Stub.Length < RegistrationFormOffset + 8)
                return false;

            uint First = BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(RegistrationFormOffset));
            uint Second = BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(RegistrationFormOffset + 4));
            bool OldForm = First != 0 && First == Second && First <= MaxRegistrations && Stub.Length == OldFormEntriesOffset + RegistrationEntrySize * (int)First;

            Ndr20Reader Reader = new Ndr20Reader(Stub);
            if (!Reader.TryReadContextHandle(out _))
                return false;

            if (!OldForm)
            {
                if (!Reader.TryReadUInt32(out uint Packages) || !Reader.TryReadUInt32(out uint Graph) || (Packages == 0) != (Graph == 0) || Packages > MaxPackageGraph)
                    return false;

                if (Graph != 0)
                {
                    if (!Reader.TryReadUInt32(out uint Conformance) || Conformance != Packages || !Reader.TrySkip((int)Packages * sizeof(uint)))
                        return false;

                    for (int i = 0; i < Packages; i++)
                    {
                        if (!Orpc.TrySkipHstringBody(ref Reader))
                            return false;
                    }
                }
            }

            if (!Reader.TryReadUInt32(out uint Size) || !Reader.TryReadUInt32(out Count) || Size != Count || Count == 0 || Count > MaxRegistrations)
                return false;

            Reader.Align(8);
            return Reader.TryReadBytes((int)Count * RegistrationEntrySize, out Entries);
        }

        // NT: rpcss finds a registration by its key, and newer builds send its CLSID as zero.
        private static byte[] NotifyStopped(ReadOnlySpan<byte> Stub)
        {
            const int RevokedClassSize = 16;
            Ndr20Reader Reader = new Ndr20Reader(Stub);
            if (!Reader.TryReadContextHandle(out _) || !Reader.TryReadUInt32(out uint Conformance) || !Reader.TryReadUInt32(out uint Count)
                || Conformance != Count || Count > MaxRegistrations)
                return null;

            for (int i = 0; i < Count; i++)
            {
                if (!Reader.TrySkip(RevokedClassSize) || !Reader.TryReadUInt32(out uint Key))
                    return null;

                if (Registrations.Remove(Key))
                    RpcssSessionTable.WithdrawRegistration(Key);
            }

            return BuildStatus(OrOk);
        }

        internal static bool Matches(in LaunchKey Key, Guid Class, string PackageFullName, ReadOnlySpan<byte> UserSid)
            => Class == Key.Class && UserSid.SequenceEqual(Key.UserSid)
                && (!Key.PerPackage || string.Equals(PackageFullName, Key.PackageFullName, StringComparison.OrdinalIgnoreCase));

        internal static bool SameKey(in LaunchKey Key, in LaunchKey Other) => Key.PerPackage == Other.PerPackage && Matches(Key, Other.Class, Other.PackageFullName, Other.UserSid);

        private static bool Serves(in ClassRegistration Registration, in LaunchKey Key)
            => (Registration.Flags & RegclsUseMask) != 0 && Matches(Key, Registration.Class, Registration.PackageFullName, Registration.UserSid);

        private static List<ClassRegistration> FindServers(in LaunchKey Key)
        {
            List<ClassRegistration> Servers = new List<ClassRegistration>();
            foreach (ClassRegistration Own in Registrations.Values)
            {
                if (Serves(Own, Key))
                    Servers.Add(Own);
            }

            AddSessionServers(Key, Servers);
            return Servers;
        }

        // Reads only the session table, so a launch task may call it off KernelLock.
        internal static bool IsServedInSession(in LaunchKey Key)
        {
            List<ClassRegistration> Found = new List<ClassRegistration>();
            AddSessionServers(Key, Found);
            return Found.Count != 0;
        }

        private static void AddSessionServers(in LaunchKey Key, List<ClassRegistration> Servers)
        {
            int First = Servers.Count;
            RpcssSessionTable.FindRegistrations(Key.Class, Servers);
            for (int i = Servers.Count - 1; i >= First; i--)
            {
                if (!Serves(Servers[i], Key))
                    Servers.RemoveAt(i);
            }
        }

        internal static void Advance()
        {
            RpcssLaunch.Advance();
            for (int Index = Launching.Count - 1; Index >= 0; Index--)
            {
                if (Index < Launching.Count)
                    Launching[Index].AdvanceLaunch();
            }
        }

        private static PendingActivation StartForward(in LrpcMessage Message, Guid Class, BinaryEmulator Instance)
        {
            WinToken Client = NtQueryInformationToken.EffectiveToken(Instance);
            byte[] Request = Message.StubData.ToArray();
            if (Client == null || Request.Length < OrpcThisFlagsOffset + sizeof(uint))
                return null;

            LocalServer Launchable = RpcssLaunch.TryReadServer(Instance.WinHelper, Class);
            bool PerPackage = Launchable?.PerPackage == true;
            LaunchKey Key = new LaunchKey(Class, PerPackage, Client.PackageFullName, NtQueryInformationToken.UserSidOf(Client));
            List<ClassRegistration> Servers = FindServers(Key);
            if ((Servers.Count == 0 && Launchable == null) || !Orpc.TryRenewCallId(Request))
                return null;

            uint Flags = BinaryPrimitives.ReadUInt32LittleEndian(Request.AsSpan(OrpcThisFlagsOffset));
            BinaryPrimitives.WriteUInt32LittleEndian(Request.AsSpan(OrpcThisFlagsOffset), Flags | ForwardedOrpcFlag);

            PendingActivation Activation = new PendingActivation(Instance, Message, Key, Client, Request, Servers, Launchable);
            Activation.TryNextServer();
            return Activation;
        }

        private sealed class PendingActivation
        {
            // NT: rpcss passes no directory, so the server starts in the one of the service host.
            private static readonly string LaunchDirectory = WindowsVersionInfo.SystemRoot + "\\system32\\";

            private readonly BinaryEmulator Instance;
            private readonly LrpcMessage Request;
            private readonly LaunchKey Key;
            private readonly WinToken Client;
            private readonly byte[] Stub;
            private readonly LocalServer Launchable;
            private List<ClassRegistration> Servers;

            // A server that was gone or stopping is not tried again when the registrations are read again.
            private readonly HashSet<(uint ProcessId, uint Key)> Tried = new HashSet<(uint ProcessId, uint Key)>();
            private int Next;
            private ClassRegistration Server;
            private LrpcClient Connection;
            private DeferredAnswer Answer;
            private RpcssLaunch Launch;
            private Timer Deadline;
            private bool DeadlinePassed;
            private bool Ended;

            internal byte[] Reply { get; private set; }

            internal PendingActivation(BinaryEmulator Instance, in LrpcMessage Request, in LaunchKey Key, WinToken Client, byte[] Stub, List<ClassRegistration> Servers,
                LocalServer Launchable)
            {
                this.Instance = Instance;
                this.Request = Request;
                this.Key = Key;
                this.Client = Client;
                this.Stub = Stub;
                this.Servers = Servers;
                this.Launchable = Launchable;
            }

            internal void AnswerThrough(DeferredAnswer Deferred)
            {
                Answer = Deferred;
                Deferred.Abandoned = End;
            }

            // NT: a server that is gone or stopping passes the activation to the next one, and when none is left the
            // class's server is launched once.
            internal void TryNextServer()
            {
                while (!Ended && Next < Servers.Count)
                {
                    Server = Servers[Next++];
                    Tried.Add((Server.ProcessId, Server.Key));
                    if (!TryGetServerOxid(Instance, Server.Oxid, out ServerOxid Exporter))
                        continue;

                    if (LrpcClient.Connect(Instance, LrpcClient.GetPortName(Exporter.Endpoint), ScmProcessId, ScmThreadId, Client,
                            SecurityImpersonationLevel.SecurityImpersonation, Connected, out Connection) == LrpcPacket.RpcOk)
                        return;
                }

                if (Ended)
                    return;

                if (Launchable != null && Launch == null)
                    StartLaunch();
                else
                    Finish(ClassNotRegisteredReply, 0);
            }

            private void StartLaunch()
            {
                WinToken Token = AlpcMessaging.Supported(Instance) && GuestSession.OwnSlot >= 0
                    ? RpcssLaunch.ServerToken(Instance, Launchable, Client, Key.PackageFullName)
                    : null;
                if (Token == null)
                {
                    Utils.LogError($"[-] RPCSS: the server of {Key.Class} cannot be launched for this process.");
                    Finish(ClassNotRegisteredReply, 0);
                    return;
                }

                LaunchRequest Launched = new LaunchRequest(Launchable.ImagePath, Launchable.CommandLine, LaunchDirectory, false, Token,
                    GuestProcessLauncher.EmulatorOptions(Instance), ScmProcessId, GuestProcessLauncher.MachineAmd64);
                Launch = RpcssLaunch.Start(Key, Launched);
                if (Launch == null)
                {
                    Finish(ClassNotRegisteredReply, 0);
                    return;
                }

                int Slot = GuestSession.OwnSlot;
                Deadline = new Timer(_ =>
                {
                    Volatile.Write(ref DeadlinePassed, true);
                    SessionPump.Ring(Slot);
                }, null, RpcssLaunch.ServerStartTimeoutMilliseconds, Timeout.Infinite);
                Launching.Add(this);
            }

            internal void AdvanceLaunch()
            {
                if (Ended)
                    return;

                List<ClassRegistration> Found = FindServers(Key);
                Found.RemoveAll(Each => Tried.Contains((Each.ProcessId, Each.Key)));
                if (Found.Count != 0)
                {
                    StopWaiting();
                    Servers = Found;
                    Next = 0;
                    TryNextServer();
                    return;
                }

                uint Failure = Launch.FailureStatus();
                if (Failure == 0 && !Volatile.Read(ref DeadlinePassed))
                    return;

                if (Failure == 0)
                {
                    Utils.LogError($"[-] RPCSS: no server of {Key.Class} registered before the activation's deadline.");
                    Failure = RpcssLaunch.CoEServerExecFailure;
                }

                Finish(BuildActivationFailure(Failure, RpcssLaunch.DescribeFailure(Failure)), 0);
            }

            // A callback of a closed connection still runs, after Close cleared Connection.
            private void Connected(uint Status)
            {
                if (Ended || Connection == null)
                    return;

                if (Status != LrpcPacket.RpcOk || Connection.Bind(LocalSystemActivator, Bound) != LrpcPacket.RpcOk)
                    Retry();
            }

            private void Bound(uint Status, ushort Context)
            {
                if (Ended || Connection == null)
                    return;

                if (Status != LrpcPacket.RpcOk)
                {
                    Retry();
                    return;
                }

                uint Sent = Connection.Call(Context, Request.ProcNumber, Server.Ipid, Stub, Called);
                if (Sent == LrpcPacket.RpcSCannotSupport)
                {
                    Utils.LogError($"[-] RPCSS: the activation of {Key.Class} needs a view to reach its server, which is not supported.");
                    Finish(null, LrpcPacket.RpcSCannotSupport);
                }
                else if (Sent != LrpcPacket.RpcOk)
                {
                    Retry();
                }
            }

            // NT: rpcss passes on what the call into the server returned. Only a server that is stopping sends the
            // activation on to another server or to a launch.
            private void Called(uint Status, ReadOnlySpan<byte> Response)
            {
                if (Ended || Connection == null)
                    return;

                if (Status != LrpcPacket.RpcOk)
                {
                    Finish(null, Status);
                    return;
                }

                byte[] Forwarded = BuildForwardedReply(Instance, Response);
                if (Forwarded == null)
                    Retry();
                else
                    Finish(Forwarded, 0);
            }

            private void Retry()
            {
                Close();
                TryNextServer();
            }

            private void Finish(byte[] Answered, uint Fault)
            {
                End();
                byte[] Message = Answered != null ? LrpcPacket.BuildResponse(Request, Answered) : LrpcPacket.BuildFault(Request, Fault);
                if (Answer == null)
                    Reply = Message;
                else
                    Answer.Send(Instance, Message);
            }

            internal void End()
            {
                Ended = true;
                StopWaiting();
                Close();
            }

            private void StopWaiting()
            {
                Launching.Remove(this);
                Deadline?.Dispose();
                Deadline = null;
            }

            private void Close()
            {
                LrpcClient Closing = Connection;
                Connection = null;
                Closing?.Close();
            }
        }

        // Null for a server that is stopping, so the activation moves on to the next server.
        private static byte[] BuildForwardedReply(BinaryEmulator Instance, ReadOnlySpan<byte> Response)
        {
            if (!Orpc.TryGetResponseParameters(Response, out int Offset))
                return Response.ToArray();

            Ndr20Reader Reader = new Ndr20Reader(Response.Slice(Offset));
            if (!Orpc.TryReadUniqueInterfacePointer(ref Reader, out ReadOnlySpan<byte> ObjRef) || !Reader.TryReadUInt32(out uint Result))
                return Response.ToArray();

            if (Result == CoEServerStopping)
                return null;

            if (ObjRef.IsEmpty || !Orpc.TryGetCustomObjRefData(ObjRef, out ReadOnlySpan<byte> Blob) || Blob.Length < ActivationBlobPrefixSize + SerializationHeaderSize
                || !TryFindProperty(Blob, ActivationPropertiesOut, out ReadOnlySpan<byte> PropsOut) || !TryFindReturnedOxid(PropsOut, out ulong Oxid)
                || !TryGetServerOxid(Instance, Oxid, out ServerOxid Server))
                return Response.ToArray();

            byte[] Properties = BuildPropertiesContainer(PropsOut, Serialize(BuildScmReplyInfo(Oxid, Server).Written));
            Ndr20Writer Writer = new Ndr20Writer(0xB0 + Properties.Length);
            Orpc.WriteResponseHeader(ref Writer);
            Writer.WriteUniqueReferent();
            Orpc.WriteCustomInterfacePointer(ref Writer, ActivationPropertiesOutInterface, ActivationPropertiesOut, (uint)Properties.Length, Properties);
            Writer.WriteUInt32(Result);
            return Writer.ToArray();
        }

        private static bool TryFindReturnedOxid(ReadOnlySpan<byte> Property, out ulong Oxid)
        {
            Oxid = 0;
            Ndr20Reader Reader = new Ndr20Reader(Property.Slice(SerializationHeaderSize));
            if (!Reader.TryReadUInt32(out uint Count) || Count == 0 || Count > Orpc.MaxRequestedInterfaces || !Reader.TryReadUInt32(out uint Iids)
                || !Reader.TryReadUInt32(out uint Results) || !Reader.TryReadUInt32(out uint Pointers) || Pointers == 0)
                return false;

            if ((Iids != 0 && !TrySkipConformantArray(ref Reader, Count, Orpc.InterfaceIdSize)) || (Results != 0 && !TrySkipConformantArray(ref Reader, Count, sizeof(uint))))
                return false;

            if (!Reader.TryReadUInt32(out uint Conformance) || Conformance != Count || !Reader.TryReadBytes((int)Count * sizeof(uint), out ReadOnlySpan<byte> Referents))
                return false;

            for (int i = 0; i < Count; i++)
            {
                if (BinaryPrimitives.ReadUInt32LittleEndian(Referents.Slice(i * sizeof(uint))) == 0)
                    continue;

                if (!Reader.TryReadUInt32(out uint Length) || !Reader.TryReadUInt32(out uint Size) || Length != Size
                    || !Reader.TryReadBytes((int)Math.Min(Length, int.MaxValue), out ReadOnlySpan<byte> First) || !Orpc.TryReadStandardObjRef(First, out StdObjRef Std))
                    return false;

                Oxid = Std.Oxid;
                return true;
            }

            return false;
        }

        private static bool TrySkipConformantArray(ref Ndr20Reader Reader, uint Count, int ElementSize)
            => Reader.TryReadUInt32(out uint Conformance) && Conformance == Count && Reader.TrySkip((int)Count * ElementSize);

        // combase asks for the class object of a WinRT class with CLSID GUID_NULL.
        private static bool TryResolveHostClass(WinSysHelper Helper, uint ProcNumber, Guid Class, ReadOnlySpan<byte> Blob, out HostClass Host)
        {
            if (ProcNumber == ProcCreateInstance)
                return Helper.HostClasses.TryGetValue(Class, out Host);

            Host = default;
            if (Class == Guid.Empty)
            {
                return TryFindProperty(Blob, WinRtActivationProperties, out ReadOnlySpan<byte> WinRt) && TryReadActivatableClassId(WinRt, out ReadOnlySpan<char> ClassId)
                    && Helper.HostActivatableClasses.GetAlternateLookup<ReadOnlySpan<char>>().TryGetValue(ClassId, out Host);
            }

            if (Helper.HostClasses.ContainsKey(Class))
                Utils.LogError($"[-] RPCSS: the class object of {Class} is not served.");
            return false;
        }

        // dwSize and a reserved DWORD, then the serialized CustomHeader and the properties it lists.
        private static bool TryReadActivationBlob(ReadOnlySpan<byte> Stub, bool HasOuter, out ReadOnlySpan<byte> Blob)
        {
            Blob = default;
            if (!Orpc.TryGetRequestParameters(Stub, out int Offset))
                return false;

            Ndr20Reader Reader = new Ndr20Reader(Stub.Slice(Offset));
            if (HasOuter && (!Orpc.TryReadUniqueInterfacePointer(ref Reader, out ReadOnlySpan<byte> Outer) || !Outer.IsEmpty))
                return false;

            return Orpc.TryReadUniqueInterfacePointer(ref Reader, out ReadOnlySpan<byte> ObjRef) && Orpc.TryGetCustomObjRefData(ObjRef, out Blob)
                && Blob.Length >= ActivationBlobPrefixSize + SerializationHeaderSize;
        }

        private static bool TryFindProperty(ReadOnlySpan<byte> Blob, Guid PropertyClass, out ReadOnlySpan<byte> Property)
        {
            Property = default;
            Ndr20Reader Header = new Ndr20Reader(Blob.Slice(ActivationBlobPrefixSize + SerializationHeaderSize));
            if (!Header.TryReadUInt32(out _) || !Header.TryReadUInt32(out uint HeaderSize) || !Header.TrySkip(8) || !Header.TryReadUInt32(out uint Count)
                || !Header.TrySkip(16) || !Header.TryReadUInt32(out uint ClassesReferent) || !Header.TryReadUInt32(out uint SizesReferent) || !Header.TryReadUInt32(out _))
                return false;

            if (Count == 0 || Count > MaxActivationProperties || ClassesReferent == 0 || SizesReferent == 0 || HeaderSize > Blob.Length - ActivationBlobPrefixSize)
                return false;

            if (!Header.TryReadUInt32(out uint ClassCount) || ClassCount != Count)
                return false;

            int Index = -1;
            for (int i = 0; i < Count; i++)
            {
                if (!Header.TryReadGuid(out Guid Each))
                    return false;
                if (Index < 0 && Each == PropertyClass)
                    Index = i;
            }

            if (Index < 0 || !Header.TryReadUInt32(out uint SizeCount) || SizeCount != Count)
                return false;

            int Position = ActivationBlobPrefixSize + (int)HeaderSize;
            for (int i = 0; i <= Index; i++)
            {
                if (!Header.TryReadUInt32(out uint Size) || Size > (uint)(Blob.Length - Position))
                    return false;

                if (i == Index)
                    Property = Blob.Slice(Position, (int)Size);
                Position += (int)Size;
            }

            return Property.Length >= SerializationHeaderSize;
        }

        private static bool TryReadActivatableClassId(ReadOnlySpan<byte> Property, out ReadOnlySpan<char> ClassId)
        {
            ClassId = default;
            Ndr20Reader Reader = new Ndr20Reader(Property.Slice(SerializationHeaderSize));
            return Reader.TryReadUInt32(out uint Referent) && Referent != 0 && Reader.TrySkip(WinRtPropertiesFlatSize - sizeof(uint))
                && Orpc.TryReadHstringBody(ref Reader, out ClassId) && !ClassId.IsEmpty;
        }

        private static bool TryReadInstantiationInfo(ReadOnlySpan<byte> Property, out Guid Class, out ReadOnlySpan<byte> Interfaces)
        {
            Class = Guid.Empty;
            Interfaces = default;
            Ndr20Reader Info = new Ndr20Reader(Property.Slice(SerializationHeaderSize));
            if (!Info.TryReadGuid(out Class) || !Info.TrySkip(12) || !Info.TryReadUInt32(out uint InterfaceCount) || !Info.TrySkip(4)
                || !Info.TryReadUInt32(out uint InterfacesReferent) || !Info.TrySkip(8) || !Info.TryReadUInt32(out uint InterfaceConformance))
                return false;

            if (InterfaceCount == 0 || InterfaceCount > Orpc.MaxRequestedInterfaces || InterfaceCount > (uint)Property.Length / Orpc.InterfaceIdSize
                || InterfacesReferent == 0 || InterfaceConformance != InterfaceCount)
                return false;

            return Info.TryReadBytes((int)InterfaceCount * Orpc.InterfaceIdSize, out Interfaces);
        }

        private static byte[] BuildActivationReply(in LrpcMessage Message, BinaryEmulator Instance, HostClass Host, ReadOnlySpan<byte> Interfaces)
        {
            // Each interface takes at least 24 bytes of PropsOutInfo, so a long list needs a view and can only fault.
            int Count = Interfaces.Length / Orpc.InterfaceIdSize;
            if (Count > LrpcPacket.MaxResponseStubLength / (Orpc.InterfaceIdSize + 2 * sizeof(uint)))
            {
                Utils.LogError($"[-] RPCSS: an activation reply for {Count} interfaces needs a view, which is not supported.");
                return LrpcPacket.BuildFault(Message, LrpcPacket.RpcSCannotSupport);
            }

            HostCall Call = new HostCall(Host.Apartment, Instance);
            byte[] Properties = BuildActivationPropertiesOut(Instance, Call, Host.Object, Interfaces);
            Ndr20Writer Writer = new Ndr20Writer(0xB0 + Properties.Length);
            Orpc.WriteResponseHeader(ref Writer);
            Writer.WriteUniqueReferent();
            Orpc.WriteCustomInterfacePointer(ref Writer, ActivationPropertiesOutInterface, ActivationPropertiesOut, (uint)Properties.Length, Properties);
            Writer.WriteUInt32(Orpc.SOk);
            return Host.Apartment.Respond(Message, Call, Writer.Written);
        }

        private static byte[] BuildActivationPropertiesOut(BinaryEmulator Instance, HostCall Call, HostObject Object, ReadOnlySpan<byte> Interfaces)
        {
            byte[] PropsOut = Serialize(BuildPropsOutInfo(Call, Object, Interfaces).Written);
            byte[] ScmReply = Serialize(BuildScmReplyInfo(Call.Apartment.Oxid, DescribeHostApartment(Instance, Call.Apartment)).Written);
            return BuildPropertiesContainer(PropsOut, ScmReply);
        }

        private static byte[] BuildPropertiesContainer(ReadOnlySpan<byte> PropsOut, ReadOnlySpan<byte> ScmReply)
        {
            const uint PropertyCount = 2;
            Ndr20Writer Writer = new Ndr20Writer(0x60);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(PropertyCount);
            Writer.WriteGuid(Guid.Empty);
            Writer.WriteUniqueReferent();
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(PropertyCount);
            Writer.WriteGuid(ActivationPropertiesOut);
            Writer.WriteGuid(ScmReplyInfo);
            Writer.WriteUInt32(PropertyCount);
            Writer.WriteUInt32((uint)PropsOut.Length);
            Writer.WriteUInt32((uint)ScmReply.Length);
            byte[] Header = Serialize(Writer.Written);

            uint TotalSize = (uint)(Header.Length + PropsOut.Length + ScmReply.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.AsSpan(SerializationHeaderSize), TotalSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.AsSpan(SerializationHeaderSize + 4), (uint)Header.Length);

            byte[] Blob = new byte[ActivationBlobPrefixSize + TotalSize];
            BinaryPrimitives.WriteUInt32LittleEndian(Blob, TotalSize);
            Header.CopyTo(Blob, ActivationBlobPrefixSize);
            PropsOut.CopyTo(Blob.AsSpan(ActivationBlobPrefixSize + Header.Length));
            ScmReply.CopyTo(Blob.AsSpan(ActivationBlobPrefixSize + Header.Length + PropsOut.Length));
            return Blob;
        }

        // BuildActivationReply bounds the interface count, so the stackallocs stay small.
        private static Ndr20Writer BuildPropsOutInfo(HostCall Call, HostObject Object, ReadOnlySpan<byte> Interfaces)
        {
            int Count = Interfaces.Length / Orpc.InterfaceIdSize;
            Span<uint> Results = stackalloc uint[Count];
            Span<StdObjRef> Objects = stackalloc StdObjRef[Count];
            for (int i = 0; i < Count; i++)
                Results[i] = Call.Query(Object, Orpc.InterfaceAt(Interfaces, i), HostObject.PublicRefs, out Objects[i]);

            Ndr20Writer Writer = new Ndr20Writer(0x40 + Count * 0x70);
            Writer.WriteUInt32((uint)Count);
            Writer.WriteUniqueReferent();
            Writer.WriteUniqueReferent();
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32((uint)Count);
            Writer.WriteBytes(Interfaces);

            Writer.WriteUInt32((uint)Count);
            foreach (uint Result in Results)
                Writer.WriteUInt32(Result);

            Writer.WriteUInt32((uint)Count);
            foreach (uint Result in Results)
            {
                if (Result == Orpc.SOk)
                    Writer.WriteUniqueReferent();
                else
                    Writer.WriteUInt32(0);
            }

            for (int i = 0; i < Count; i++)
            {
                if (Results[i] == Orpc.SOk)
                    Object.WriteInterfacePointer(ref Writer, Orpc.InterfaceAt(Interfaces, i), Objects[i]);
            }

            return Writer;
        }

        // _PRIV_RESOLVER_INFO carries the server's OXID_INFO, so the client never asks the resolver.
        private static Ndr20Writer BuildScmReplyInfo(ulong Oxid, in ServerOxid Server)
        {
            Ndr20Writer Writer = new Ndr20Writer(0x180);
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32(0);
            Writer.WriteUInt64(Oxid);
            Writer.WriteUInt32(0);

            WriteOxidInfoFlat(ref Writer, Server);
            Writer.WriteUInt64(LocalMachineId);
            Writer.WriteUInt32(0);
            WriteOxidInfoPointees(ref Writer, Server);
            return Writer;
        }

        internal static void PublishHostApartment(BinaryEmulator Instance, HostApartment Apartment)
        {
            RpcssSessionTable.PublishOxid(Apartment.Oxid, DescribeHostApartment(Instance, Apartment));
        }

        private static ServerOxid DescribeHostApartment(BinaryEmulator Instance, HostApartment Apartment)
        {
            byte[] Info = new byte[OxidInfoSize];
            BinaryPrimitives.WriteUInt32LittleEndian(Info, MultithreadedApartmentTid);
            BinaryPrimitives.WriteUInt32LittleEndian(Info.AsSpan(OxidInfoProcessId), (uint)Apartment.ProcessId);
            BinaryPrimitives.WriteUInt32LittleEndian(Info.AsSpan(OxidInfoAuthnHint), AuthnLevelConnect);
            BinaryPrimitives.WriteUInt16LittleEndian(Info.AsSpan(OxidInfoVersion), Orpc.ComVersionMajor);
            BinaryPrimitives.WriteUInt16LittleEndian(Info.AsSpan(OxidInfoVersion + 2), Orpc.ComVersionMinor);
            BinaryPrimitives.WriteUInt32LittleEndian(Info.AsSpan(OxidInfoContainerVersion), ContainerVersion);
            Apartment.RemUnknownIpid.TryWriteBytes(Info.AsSpan(OxidInfoRemUnknownIpid));
            BinaryPrimitives.WriteUInt32LittleEndian(Info.AsSpan(OxidInfoFlags), HostOxidFlags);
            Apartment.ProcessIdentifier.TryWriteBytes(Info.AsSpan(OxidInfoProcessIdentifier));
            BinaryPrimitives.WriteUInt64LittleEndian(Info.AsSpan(OxidInfoPrimaryOxid), Apartment.Oxid);
            Apartment.RemUnknownIpid.TryWriteBytes(Info.AsSpan(OxidInfoPrimaryRemUnknownIpid));

            string Security = string.Concat(stackalloc char[] { (char)AuthnWinNt, (char)AuthzNone }, HostApartment.GetPrincipal(Instance), "\0\0");
            return new ServerOxid(Info, Apartment.Endpoint, Security, null, null, null);
        }

        // NDR puts the pointees after the whole structure that holds the OXID_INFO.
        private static void WriteOxidInfoFlat(ref Ndr20Writer Writer, in ServerOxid Server)
        {
            ReadOnlySpan<byte> Info = Server.Info;
            Writer.AlignTo(8);
            Writer.WriteBytes(Info.Slice(0, OxidInfoBindings));
            Writer.WriteUniqueReferent();
            Writer.WriteBytes(Info.Slice(OxidInfoBindings + 4, OxidInfoHstrings - OxidInfoBindings - 4));
            for (int i = 0; i < OxidInfoHstringCount; i++)
                Writer.WriteUInt32(Orpc.UserMarshalMarker);
            Writer.WriteBytes(Info.Slice(OxidInfoPrimaryOxid));
        }

        private static void WriteOxidInfoPointees(ref Ndr20Writer Writer, in ServerOxid Server)
        {
            WriteResolverBindings(ref Writer, Server.Endpoint, Server.SecurityBindings);
            Orpc.WriteHstringBody(ref Writer, Server.PackageFullName);
            Orpc.WriteHstringBody(ref Writer, Server.UserSid);
            Orpc.WriteHstringBody(ref Writer, Server.AppContainerSid);
        }

        // Local OXIDs use protseq:[endpoint] bindings without tower ids.
        private static void WriteResolverBindings(ref Ndr20Writer Writer, string Endpoint, string SecurityBindings)
        {
            const int ListTerminators = 2;
            int SecurityOffset = LocalBindingPrefix.Length + Endpoint.Length + "]".Length + ListTerminators;
            int Entries = SecurityOffset + SecurityBindings.Length;
            Writer.WriteUInt32((uint)Entries);
            Writer.WriteUInt16((ushort)Entries);
            Writer.WriteUInt16((ushort)SecurityOffset);
            Writer.WriteUtf16(LocalBindingPrefix);
            Writer.WriteUtf16(Endpoint);
            Writer.WriteUInt16(']');
            Writer.WriteUInt16(0);
            Writer.WriteUInt16(0);
            Writer.WriteUtf16(SecurityBindings);
        }

        private static bool IsSecurityBindingList(ReadOnlySpan<char> Bindings) => Bindings.Length >= 2 && Bindings[^1] == '\0' && Bindings[^2] == '\0';

        // The NDR type serialization header is version 1, little endian, 8 bytes, then the padded data length.
        private static byte[] Serialize(ReadOnlySpan<byte> Data)
        {
            int Padded = (Data.Length + 7) & ~7;
            byte[] Result = new byte[SerializationHeaderSize + Padded];
            BinaryPrimitives.WriteUInt64LittleEndian(Result, SerializationCommonHeader);
            BinaryPrimitives.WriteUInt32LittleEndian(Result.AsSpan(8), (uint)Padded);
            Data.CopyTo(Result.AsSpan(SerializationHeaderSize));
            return Result;
        }

        // combase turns the error extent of the ORPCTHAT into the thread's error info.
        private static byte[] BuildActivationFailure(uint Result, string Description)
        {
            const uint ExtentCount = 1;
            byte[] ErrorData = BuildRestrictedErrorData(Result, Description);
            int ExtentSize = Orpc.CustomObjRefHeaderSize + ErrorData.Length;

            Ndr20Writer Writer = new Ndr20Writer(0x80 + ExtentSize);
            Writer.WriteUInt32(Orpc.OrpcfLocal);
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32(ExtentCount);
            Writer.WriteUInt32(0);
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32((ExtentCount + 1) & ~1u);
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32(0);

            Writer.WriteUInt32(((uint)ExtentSize + 7) & ~7u);
            Writer.WriteGuid(ErrorExtension);
            Writer.WriteUInt32((uint)ExtentSize);
            Orpc.WriteCustomObjRef(ref Writer, Orpc.IUnknownId, RestrictedErrorObject, (uint)ErrorData.Length, ErrorData);
            Writer.AlignTo(8);

            Orpc.WriteEmptyLocalThat(ref Writer);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(Result);
            return Writer.ToArray();
        }

        // The marshal data combase's CRestrictedError::UnmarshalInterface reads.
        private static byte[] BuildRestrictedErrorData(uint Result, string Description)
        {
            Ndr20Writer Writer = new Ndr20Writer(0x40 + Description.Length * sizeof(char) * 2);
            Writer.WriteUInt32(Result);
            for (int i = 0; i < 2; i++)
            {
                Writer.WriteUtf16(Description);
                Writer.WriteUInt16(0);
            }

            // The capability SID, signature, process name and stack text are empty, and each is a 4-byte length and a NUL.
            Writer.WriteZeros(4 * 6);

            // There is no section name and no section, and the originating process id follows.
            Writer.WriteZeros(4);
            Writer.WriteUInt32(ScmProcessId);

            // The optional error parts that follow are all absent.
            Writer.WriteZeros(20);
            return Writer.ToArray();
        }

        private static byte[] Connect(ReadOnlySpan<byte> Stub, WinSysHelper Helper)
        {
            if (!TryReadConnectIdCount(Stub, out uint IdCount))
                return null;

            Ndr20Writer Writer = new Ndr20Writer(512);

            Writer.WriteContextHandle(ResolverHandle);
            Writer.WriteUInt32(PingPeriodSeconds);

            Writer.WriteUniqueReferent();
            WriteEmptyDualStringArray(ref Writer);

            Writer.WriteUInt64(LocalMachineId);

            Writer.AlignTo(4);
            Writer.WriteUInt32(IdCount);
            Writer.AlignArray(IdCount, 8);
            for (uint i = 0; i < IdCount; i++)
                Writer.WriteUInt64(NextObjectId());

            Writer.WriteUInt32(IdCount);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(AuthnLevelConnect);
            Writer.WriteUInt32(ImpLevelIdentify);

            // No security packages and no channel hooks: a zero count and a null list each.
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);

            Writer.WriteUInt32(Helper.PID);
            Writer.WriteUInt32(ScmProcessId);
            Writer.WriteUInt64(ProcessSignature);

            Span<byte> Identifier = stackalloc byte[16];
            ProcessIdentifier.TryWriteBytes(Identifier);
            Writer.AlignTo(4);
            Writer.WriteBytes(Identifier);

            ReadOnlySpan<byte> Restrictions = ReadMachineAccessRestriction(Helper);
            uint DescriptorsSize = (uint)Restrictions.Length;
            foreach (byte[] Descriptor in BuiltInDescriptors)
            {
                Writer.WriteUInt32((uint)Descriptor.Length);
                DescriptorsSize += (uint)Descriptor.Length;
            }

            Writer.WriteUInt32((uint)Restrictions.Length);
            Writer.WriteUInt32(DescriptorsSize);
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32(DescriptorsSize);
            foreach (byte[] Descriptor in BuiltInDescriptors)
                Writer.WriteBytes(Descriptor);
            Writer.WriteBytes(Restrictions);

            Writer.AlignTo(4);
            Writer.WriteUInt32(OrOk);
            return Writer.ToArray();
        }

        // The id array is sized by the in parameter that follows two strings and the proxy decode block.
        private static bool TryReadConnectIdCount(ReadOnlySpan<byte> Stub, out uint IdCount)
        {
            IdCount = 0;

            Ndr20Reader Reader = new Ndr20Reader(Stub);
            if (!Reader.TryReadUniqueWideString(out _) || !Reader.TryReadUniqueWideString(out _))
                return false;

            if (!Reader.TryReadUInt32(out uint DecodeInfoReferent))
                return false;

            if (DecodeInfoReferent != 0)
            {
                Reader.Align(8);
                if (!Reader.TrySkip(ProxyDecodeInfoSize))
                    return false;
            }

            if (!Reader.TryReadUInt32(out _) || !Reader.TryReadUInt16(out _))
                return false;

            Reader.Align(4);
            if (!Reader.TryReadUInt32(out IdCount))
                return false;

            return IdCount <= MaximumIds;
        }

        private static bool TryReadIdCount(ReadOnlySpan<byte> Stub, out uint Count)
        {
            Count = 0;

            if (Stub.Length < Ndr20Writer.ContextHandleSize + 4)
                return false;

            Count = BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(Ndr20Writer.ContextHandleSize, 4));
            return Count <= MaximumIds;
        }

        // NT: rpcss keeps the first AppID a process gives (CProcess::SetAppID).
        private static byte[] SetAppId(ReadOnlySpan<byte> Stub)
        {
            Ndr20Reader Reader = new Ndr20Reader(Stub);
            if (!Reader.TryReadContextHandle(out _) || !Reader.TryReadGuid(out Guid AppId))
                return null;

            uint Status = OrOk;
            if (ProcessAppId != Guid.Empty)
                Status = RpcETooLate;
            else
                ProcessAppId = AppId;

            Ndr20Writer Writer = new Ndr20Writer(8);
            Writer.WriteUInt32(Status);
            return Writer.ToArray();
        }

        private static byte[] AllocateReservedIds(ReadOnlySpan<byte> Stub)
        {
            if (!TryReadIdCount(Stub, out uint Count))
                return null;

            return BuildNewIds(Count, Count, OrOk);
        }

        // The resolver keeps no OID state, so the OIDs the apartment gives back are skipped.
        private static byte[] ServerAllocateOIDs(ReadOnlySpan<byte> Stub)
        {
            Ndr20Reader Reader = new Ndr20Reader(Stub);
            if (!Reader.TryReadContextHandle(out _) || !Reader.TryReadUInt64(out ulong Oxid))
                return null;

            if (!Reader.TryReadUInt32(out uint ReturnCount) || ReturnCount > MaximumIds
                || !Reader.TryReadUInt32(out uint Conformance) || Conformance != ReturnCount)
                return null;

            Reader.AlignArray(ReturnCount, 8);
            if (!Reader.TrySkip((int)ReturnCount * sizeof(ulong)) || !Reader.TryReadUInt32(out uint Count) || Count > MaximumIds)
                return null;

            return ServerOxids.ContainsKey(Oxid) ? BuildNewIds(Count, Count, OrOk) : BuildNewIds(Count, 0, OrBadOxid);
        }

        // NT: rpcss is one per machine, so an OXID or OID never names objects of two processes.
        private static ulong NextObjectId() => SessionIds.Next(SessionIdKind.ObjectExporter);

        private static byte[] BuildNewIds(uint Size, uint Allocated, uint Status)
        {
            Ndr20Writer Writer = new Ndr20Writer(32 + (int)Size * 8);
            Writer.WriteUInt32(Size);
            Writer.AlignArray(Size, 8);
            for (uint i = 0; i < Allocated; i++)
                Writer.WriteUInt64(NextObjectId());

            Writer.WriteZeros((int)(Size - Allocated) * sizeof(ulong));
            Writer.WriteUInt32(Allocated);
            Writer.WriteUInt32(Status);
            return Writer.ToArray();
        }

        private static byte[] BulkUpdateOIDs(ReadOnlySpan<byte> Stub)
        {
            if (!TryReadIdCount(Stub, out uint Count))
                return null;

            Ndr20Writer Writer = new Ndr20Writer(16 + (int)Count * 4);
            Writer.WriteUInt32(Count);
            for (uint i = 0; i < Count; i++)
                Writer.WriteUInt32(OrOk);

            Writer.WriteUInt32(OrOk);
            return Writer.ToArray();
        }

        private static byte[] ServerAllocateOXIDAndOIDs(ReadOnlySpan<byte> Stub)
        {
            if (!TryReadIdCount(Stub, out uint Count))
                return null;

            if (!TryReadServerOxid(Stub, out ServerOxid Server))
                Utils.LogError("[-] RPCSS: the OXID_INFO of a server apartment could not be read; its endpoint is unknown.");

            if (PrimaryOxid == 0)
            {
                PrimaryOxid = NextObjectId();
                AddServerOxid(PrimaryOxid, AsPrimary(Server));
            }

            Ndr20Writer Writer = new Ndr20Writer(64 + (int)Count * 8);
            ulong Oxid = NextObjectId();
            AddServerOxid(Oxid, WithPrimaryOxid(Server, PrimaryOxid));
            Writer.WriteUInt64(Oxid);
            Writer.WriteUInt64(PrimaryOxid);

            Writer.WriteUInt32(Count);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(Count);
            Writer.AlignArray(Count, 8);
            for (uint i = 0; i < Count; i++)
                Writer.WriteUInt64(NextObjectId());

            Writer.WriteUInt32(Count);
            Writer.WriteUInt64(0);

            // No new resolver bindings.
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(OrOk);
            return Writer.ToArray();
        }

        private static bool TryReadServerOxid(ReadOnlySpan<byte> Stub, out ServerOxid Server)
        {
            Server = default;

            Ndr20Reader Reader = new Ndr20Reader(Stub);
            if (!Reader.TryReadContextHandle(out _) || !Reader.TryReadUInt32(out _))
                return false;

            Reader.Align(8);
            if (!Reader.TryReadBytes(OxidInfoSize, out ReadOnlySpan<byte> Info))
                return false;

            if (BinaryPrimitives.ReadUInt32LittleEndian(Info.Slice(OxidInfoExtensions)) != 0)
                return false;

            if (BinaryPrimitives.ReadUInt32LittleEndian(Info.Slice(OxidInfoBindings)) != 0 && !TryReadDualStringArray(ref Reader, out _, out _))
                return false;

            string[] Strings = new string[OxidInfoHstringCount];
            for (int i = 0; i < OxidInfoHstringCount; i++)
            {
                if (BinaryPrimitives.ReadUInt32LittleEndian(Info.Slice(OxidInfoHstrings + i * 4)) == 0)
                    continue;

                if (!Orpc.TryReadHstringBody(ref Reader, out ReadOnlySpan<char> Value))
                    return false;
                Strings[i] = new string(Value);
            }

            if (!TryReadDualStringArray(ref Reader, out ReadOnlySpan<byte> Bindings, out ushort SecurityOffset) || SecurityOffset * 2 > Bindings.Length)
                return false;

            string Endpoint = FindLocalEndpoint(MemoryMarshal.Cast<byte, char>(Bindings.Slice(0, SecurityOffset * 2)));
            if (Endpoint == null)
                return false;

            if (!TryReadDualStringArray(ref Reader, out ReadOnlySpan<byte> Security, out SecurityOffset) || SecurityOffset * 2 > Security.Length)
                return false;

            ReadOnlySpan<char> SecurityBindings = MemoryMarshal.Cast<byte, char>(Security.Slice(SecurityOffset * 2));
            if (!IsSecurityBindingList(SecurityBindings))
                return false;

            Server = new ServerOxid(Info.ToArray(), Endpoint, new string(SecurityBindings), Strings[0], Strings[1], Strings[2]);
            return true;
        }

        // rpcss names the process's primary OXID in every OXID_INFO it answers.
        private static ServerOxid WithPrimaryOxid(in ServerOxid Server, ulong Primary)
        {
            if (Server.Info == null)
                return Server;

            byte[] Info = (byte[])Server.Info.Clone();
            BinaryPrimitives.WriteUInt64LittleEndian(Info.AsSpan(OxidInfoPrimaryOxid), Primary);
            return Server with { Info = Info };
        }

        // The primary OXID's RemUnknown is the IPID the apartment gives for it.
        private static ServerOxid AsPrimary(in ServerOxid Server)
        {
            if (Server.Info == null)
                return Server;

            ServerOxid Primary = WithPrimaryOxid(Server, PrimaryOxid);
            Primary.Info.AsSpan(OxidInfoPrimaryRemUnknownIpid, 16).CopyTo(Primary.Info.AsSpan(OxidInfoRemUnknownIpid));
            return Primary;
        }

        private static void AddServerOxid(ulong Oxid, in ServerOxid Server)
        {
            ServerOxids[Oxid] = Server;
            if (Server.Endpoint != null)
                RpcssSessionTable.PublishOxid(Oxid, Server);
        }

        internal static bool TryGetServerOxid(BinaryEmulator Instance, ulong Oxid, out ServerOxid Server)
        {
            if (ServerOxids.TryGetValue(Oxid, out Server))
                return Server.Endpoint != null;

            if (!AlpcMessaging.Supported(Instance))
            {
                Utils.LogError($"[-] RPCSS: OXID 0x{Oxid:X} is not this process's own, and an x86 process resolves no other.");
                return false;
            }

            return RpcssSessionTable.TryFindOxid(Oxid, out Server) && Server.Endpoint.Length != 0 && IsSecurityBindingList(Server.SecurityBindings);
        }

        // Every server of the session is on this machine, so the client's resolver bindings are not read.
        private static byte[] ClientResolveOXID(ReadOnlySpan<byte> Stub, BinaryEmulator Instance)
        {
            Ndr20Reader Reader = new Ndr20Reader(Stub);
            if (!Reader.TryReadContextHandle(out _) || !Reader.TryReadUInt64(out ulong Oxid))
                return null;

            bool Found = TryGetServerOxid(Instance, Oxid, out ServerOxid Server);
            Ndr20Writer Writer = new Ndr20Writer(0x200);
            if (Found)
            {
                WriteOxidInfoFlat(ref Writer, Server);
                WriteOxidInfoPointees(ref Writer, Server);
            }
            else
            {
                Writer.WriteZeros(OxidInfoHstrings);
                for (int i = 0; i < OxidInfoHstringCount; i++)
                    Writer.WriteUInt32(Orpc.UserMarshalMarker);
                Writer.WriteZeros(OxidInfoSize - OxidInfoHstrings - OxidInfoHstringCount * 4);
                for (int i = 0; i < OxidInfoHstringCount; i++)
                    Orpc.WriteHstringBody(ref Writer, default);
            }

            Writer.WriteUInt64(Found ? LocalMachineId : 0);

            // No marshaled target info and no authentication service.
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt16(0);
            Writer.AlignTo(4);
            Writer.WriteUInt32(Found ? OrOk : OrBadOxid);
            return Writer.ToArray();
        }

        private static bool TryReadDualStringArray(ref Ndr20Reader Reader, out ReadOnlySpan<byte> Strings, out ushort SecurityOffset)
        {
            Strings = default;
            SecurityOffset = 0;
            return Reader.TryReadUInt32(out uint Conformance) && Reader.TryReadUInt16(out ushort Entries) && Reader.TryReadUInt16(out SecurityOffset)
                && Conformance == Entries && Reader.TryReadBytes(Entries * 2, out Strings);
        }

        private static string FindLocalEndpoint(ReadOnlySpan<char> Strings)
        {
            while (!Strings.IsEmpty)
            {
                int Terminator = Strings.IndexOf('\0');
                ReadOnlySpan<char> Binding = Terminator < 0 ? Strings : Strings.Slice(0, Terminator);
                Strings = Terminator < 0 ? default : Strings.Slice(Terminator + 1);
                if (!Binding.StartsWith(LocalBindingPrefix, StringComparison.OrdinalIgnoreCase))
                    continue;

                int End = Binding.Slice(LocalBindingPrefix.Length).IndexOfAny(']', ',');
                if (End > 0)
                    return new string(Binding.Slice(LocalBindingPrefix.Length, End));
            }

            return null;
        }

        // The STDOBJREF and OXID_INFO go back as marshalled. They are eight byte aligned both ways.
        private static byte[] RegisterWindowPropInterface(ReadOnlySpan<byte> Stub)
        {
            if (Stub.Length < StdObjRefOffset + 4)
                return null;

            uint Hwnd = BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(HwndOffset, 4));
            WindowProps[Hwnd] = Stub.Slice(StdObjRefOffset, Stub.Length - 4 - StdObjRefOffset).ToArray();

            Ndr20Writer Writer = new Ndr20Writer(24);
            Writer.WriteUInt32(NextCookie++);
            Writer.WriteUInt32(OrOk);
            Writer.WriteUInt32(0);
            return Writer.ToArray();
        }

        private static byte[] GetWindowPropInterface(ReadOnlySpan<byte> Stub)
        {
            if (Stub.Length < RevokeOffset + 4)
                return null;

            uint Hwnd = BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(HwndOffset, 4));
            bool Revoke = BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(RevokeOffset, 4)) != 0;

            if (!WindowProps.TryGetValue(Hwnd, out byte[] Registration))
                return null;

            if (Revoke)
                WindowProps.Remove(Hwnd);

            Ndr20Writer Writer = new Ndr20Writer(Registration.Length + 16);
            Writer.WriteBytes(Registration);
            Writer.AlignTo(4);
            Writer.WriteUInt32(OrOk);
            Writer.WriteUInt32(0);
            return Writer.ToArray();
        }

        // The resolver keeps no state for OIDs, so the array after the OXID is not read.
        private static byte[] ServerFreeOXIDAndOIDs(ReadOnlySpan<byte> Stub)
        {
            if (Stub.Length < FreeOxidOffset + sizeof(ulong))
                return null;

            ulong Oxid = BinaryPrimitives.ReadUInt64LittleEndian(Stub.Slice(FreeOxidOffset, sizeof(ulong)));
            if (!ServerOxids.Remove(Oxid, out ServerOxid Server))
                return BuildStatus(OrBadOxid);

            if (Server.Endpoint != null)
                RpcssSessionTable.WithdrawOxid(Oxid);

            if (Oxid == PrimaryOxid)
                PrimaryOxid = 0;

            return BuildStatus(OrOk);
        }

        // rpcss runs down the process context, which frees every OXID it registered, and returns a NULL handle.
        private static byte[] Disconnect()
        {
            foreach (KeyValuePair<ulong, ServerOxid> Entry in ServerOxids)
            {
                if (Entry.Value.Endpoint != null)
                    RpcssSessionTable.WithdrawOxid(Entry.Key);
            }

            ServerOxids.Clear();
            PrimaryOxid = 0;

            foreach (uint Key in Registrations.Keys)
                RpcssSessionTable.WithdrawRegistration(Key);
            Registrations.Clear();

            Ndr20Writer Writer = new Ndr20Writer(Ndr20Writer.ContextHandleSize + 4);
            Writer.WriteContextHandle(ReadOnlySpan<byte>.Empty);
            Writer.WriteUInt32(OrOk);
            return Writer.ToArray();
        }

        private static byte[] BuildStatus(uint Status)
        {
            Ndr20Writer Writer = new Ndr20Writer(4);
            Writer.WriteUInt32(Status);
            return Writer.ToArray();
        }

        private static byte[] BuildStatusAndResult(uint Status, uint Result)
        {
            Ndr20Writer Writer = new Ndr20Writer(8);
            Writer.WriteUInt32(Status);
            Writer.WriteUInt32(Result);
            return Writer.ToArray();
        }

        // Empty DUALSTRINGARRAY: each list is only its terminator.
        private static void WriteEmptyDualStringArray(ref Ndr20Writer Writer)
        {
            const ushort Entries = 4;
            const ushort SecurityOffset = 2;

            Writer.WriteUInt32(Entries);
            Writer.WriteUInt16(Entries);
            Writer.WriteUInt16(SecurityOffset);
            for (int i = 0; i < Entries; i++)
                Writer.WriteUInt16(0);

            Writer.AlignTo(4);
        }

        // Launch permission, access permission, launch restriction and access restriction, in the order of the Connect
        // reply, as rpcss InitializeSystemSecurityDescriptors builds them for a workstation.
        private static byte[][] BuildBuiltInDescriptors()
        {
            const uint Local = ComRightsExecute | ComRightsExecuteLocal;
            const uint Access = Local | ComRightsExecuteRemote;
            const uint LocalLaunch = Local | ComRightsActivateLocal;
            const uint All = Access | ComRightsActivateLocal | ComRightsActivateRemote;

            byte[] Administrators = NtQueryInformationToken.AdministratorsSid;
            byte[] Everyone = NtQueryInformationToken.EveryoneSid;
            byte[] LocalSystem = NtQueryInformationToken.LocalSystemSid;
            byte[] Packages = NtQueryInformationToken.AllApplicationPackagesSid;
            byte[] DcomUsers = NtQueryInformationToken.BuildSid(5, 32, 562);
            byte[] PerformanceLogUsers = NtQueryInformationToken.BuildSid(5, 32, 559);
            byte[] LpacCom = NtQueryInformationToken.BuildSid(15, 3, 1024, 2405443489, 874036122, 4286035555, 1823921565, 1746547431, 2453885448,
                3625952902, 991631256);

            return
            [
                AdministratorsOwned(Allow(Administrators, All), Allow(NtQueryInformationToken.InteractiveSid, LocalLaunch), Allow(LocalSystem, LocalLaunch)),
                AdministratorsOwned(Allow(NtQueryInformationToken.PrincipalSelfSid, Access), Allow(LocalSystem, Local), Allow(Administrators, Access)),
                AdministratorsOwned(Allow(Administrators, All), Allow(Everyone, LocalLaunch), Allow(DcomUsers, All), Allow(PerformanceLogUsers, All),
                    Allow(Packages, LocalLaunch), Allow(LpacCom, LocalLaunch)),
                AdministratorsOwned(Allow(Everyone, Access), Allow(NtQueryInformationToken.AnonymousLogonSid, Local), Allow(DcomUsers, Access),
                    Allow(PerformanceLogUsers, Access), Allow(Packages, Local), Allow(LpacCom, Local)),
            ];

            static NtAccessCheck.AceEntry Allow(byte[] Sid, uint Mask) => NtAccessCheck.AceEntry.Allow(Sid, Mask);

            static byte[] AdministratorsOwned(params ReadOnlySpan<NtAccessCheck.AceEntry> Entries)
                => NtAccessCheck.BuildSelfRelative(NtQueryInformationToken.AdministratorsSid, NtQueryInformationToken.AdministratorsSid,
                    NtAccessCheck.BuildAcl(Entries), ReadOnlySpan<byte>.Empty);
        }

        // rpcss sends MachineAccessRestriction only when the registry holds a valid COM descriptor, and the client then
        // uses the built-in one.
        private static ReadOnlySpan<byte> ReadMachineAccessRestriction(WinSysHelper Helper)
        {
            if (Helper.TryGetRegistryValue(Helper.ResolveNativeRegistryKey(DcomPolicyKey), MachineAccessRestriction, out _))
                Utils.LogError("[-] RPCSS: the DCOM policy value MachineAccessRestriction is not read; the value under the Ole key applies.");

            if (!Helper.TryGetRegistryValue(Helper.ResolveNativeRegistryKey(OleKey), MachineAccessRestriction, out ValueNode Value)
                || Value.Type != WinSysHelper.RegBinary || Value.Data is not { Length: >= MinimumRegistryDescriptorBytes })
                return default;

            return Value.Data.AsSpan(0, NtAccessCheck.ComDescriptorLength(Value.Data));
        }
    }
}
