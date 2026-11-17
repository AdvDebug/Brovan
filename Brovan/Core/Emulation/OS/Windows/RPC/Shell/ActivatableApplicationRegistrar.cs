using System;
using System.Buffers.Binary;
using Brovan.Core.Emulation.OS.Windows.RPC.Ports;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Shell
{
    // NT: ViewActivator's PendingViewActivationRequest, which lives until the app's view ends.
    internal sealed class PendingViewActivation
    {
        internal ulong ActivationId { get; }
        internal ulong HostId { get; }

        // The window factory carries this GUID to CreateView.
        internal Guid Request { get; } = Guid.NewGuid();

        internal uint ViewId { get; }
        internal string ContractId { get; }
        internal CoreWindowFactoryServer WindowFactory { get; }

        internal PendingViewActivation(ulong ActivationId, ulong HostId, uint ViewId, string ContractId)
        {
            this.ActivationId = ActivationId;
            this.HostId = HostId;
            this.ViewId = ViewId;
            this.ContractId = ContractId;
            WindowFactory = new CoreWindowFactoryServer(this);
        }
    }

    internal sealed class ActivatableApplicationRegistrar : HostObject
    {
        internal static readonly Guid Class = new Guid("dea794e0-1c1d-4363-b171-98d0b1703586");
        private static readonly Guid RegistrarInterface = new Guid("036c57fc-e73d-4f3a-b095-8b813fa2f764");
        private static readonly Guid ActivatableApplicationInterface = new Guid("92696c00-7578-48e1-ac1a-2ca909e2c8cf");
        private static readonly Guid ActivatedEventArgsInterface = new Guid("cf651713-cd08-4fd8-b697-a281b6544e2e");
        private static readonly Guid MarshalByValueClass = new Guid("0000035a-0000-0000-c000-000000000046");
        private const string LaunchContract = "Windows.Launch";
        private const string LaunchActivatedEventArgsClass = "Windows.ApplicationModel.Activation.LaunchActivatedEventArgs";

        private const uint ProcRegisterActivatableApplication = 3;
        private const uint ProcActivate = 6;

        private const uint PropertyTypeInt32 = 4;
        private const uint PropertyTypeUInt32 = 5;
        private const uint PropertyTypeUInt64 = 7;
        private const uint PropertyTypeBoolean = 11;
        private const uint PropertyTypeString = 12;
        private const uint PropertyTypeGuid = 16;
        private const uint ActivationKindLaunch = 0;
        private const uint ExecutionStateNotRunning = 0;

        private sealed class Registration
        {
            public readonly StdObjRef Object;
            public LrpcClient Client;
            public PendingViewActivation View;

            public Registration(StdObjRef Object)
            {
                this.Object = Object;
            }
        }

        private readonly HostApartment Apartment;
        private Registration Current;
        private uint LastViewId;

        internal ActivatableApplicationRegistrar(HostApartment Apartment) => this.Apartment = Apartment;

        internal override bool Permanent => true;

        internal override bool Supports(Guid Interface) => Interface == Orpc.IUnknownId || Interface == RegistrarInterface;

        internal override bool TryCall(HostCall Call, Guid Interface, uint ProcNumber, ReadOnlySpan<byte> Parameters, out byte[] Stub)
        {
            Stub = null;
            if (Interface != RegistrarInterface || ProcNumber != ProcRegisterActivatableApplication)
                return false;

            Stub = RegisterActivatableApplication(Call.Instance, Parameters);
            return true;
        }

        private byte[] RegisterActivatableApplication(BinaryEmulator Instance, ReadOnlySpan<byte> Parameters)
        {
            Ndr20Reader Reader = new Ndr20Reader(Parameters);
            if (!Orpc.TryReadUniqueInterfacePointer(ref Reader, out ReadOnlySpan<byte> ObjRef))
                return null;

            if (!Orpc.TryReadStandardObjRef(ObjRef, out StdObjRef Object))
            {
                Utils.LogError("[-] ActivationManager: the application object is not a standard OBJREF.");
                return null;
            }

            // The new registration goes in first, so the old launch sees it was replaced when its client closes.
            Registration Previous = Current;
            Registration App = new Registration(Object);
            Current = App;
            Previous?.Client?.Close();

            new Launch(Instance, this, App).Start();
            return SuccessResult;
        }

        internal PendingViewActivation FindPendingView(ulong ActivationId, ulong HostId)
            => Current?.View is { } View && View.ActivationId == ActivationId && View.HostId == HostId ? View : null;

        internal PendingViewActivation FindPendingView(Guid Request) => Current?.View is { } View && View.Request == Request ? View : null;

        internal bool IsPending(PendingViewActivation View) => View != null && Current?.View == View;

        // The app sends no message when it exits, so its view activation ends with its view's task.
        internal void EndViewActivation(PendingViewActivation View)
        {
            if (IsPending(View))
                Current.View = null;
        }

        private sealed class Launch
        {
            private readonly BinaryEmulator Instance;
            private readonly ActivatableApplicationRegistrar Registrar;
            private readonly Registration App;
            private AppxApplication Application;
            private Guid AppRemUnknownIpid;
            private Guid AppIpid;
            private readonly ulong ActivationId = Orpc.NewId();
            private string? AppPortName;
            private string Step;

            public Launch(BinaryEmulator Instance, ActivatableApplicationRegistrar Registrar, Registration App)
            {
                this.Instance = Instance;
                this.Registrar = Registrar;
                this.App = App;
            }

            public void Start()
            {
                AppxProcessIdentity Identity = Instance.WindowsGuest?.PackageIdentity;
                Application = Identity?.Application;
                if (Application == null)
                {
                    Utils.LogError("[-] ActivationManager: the registered application has no package identity, so it is not launched.");
                    return;
                }

                if (!RpcssPortHandler.TryGetServerOxid(App.Object.Oxid, out RpcssPortHandler.ServerOxid Server))
                {
                    Utils.LogError("[-] ActivationManager: the resolver knows no endpoint for the apartment of the registered application.");
                    return;
                }

                HostApartment Apartment = Registrar.Apartment;
                App.View = new PendingViewActivation(ActivationId, Identity.HostId, ++Registrar.LastViewId, LaunchContract);

                AppRemUnknownIpid = Server.RemUnknownIpid;
                WinProcess ShellProcess = Instance.WinHelper.ShellProcess;
                AppPortName = LrpcClient.GetPortName(Server.Endpoint);
                Step = "connect";
                Succeeded(LrpcClient.Connect(Instance, AppPortName, ShellProcess.PID, Apartment.ThreadId, ShellProcess.GetPrimaryToken(),
                    SecurityImpersonationLevel.SecurityIdentification, OnConnected, out App.Client));
            }

            private void OnConnected(uint Status)
            {
                if (!Succeeded(Status))
                    return;

                Step = "bind IRundown";
                Succeeded(App.Client.Bind(Orpc.RundownInterface, OnRundownBound));
            }

            private void OnRundownBound(uint Status, ushort Context)
            {
                if (!Succeeded(Status))
                    return;

                Step = "RemQueryInterface";
                Ndr20Writer Query = BuildQuery(App.Object.Ipid);
                Succeeded(App.Client.Call(Context, Orpc.ProcRemQueryInterface, AppRemUnknownIpid, Query.Written, OnQueried));
            }

            private void OnQueried(uint Status, ReadOnlySpan<byte> Response)
            {
                if (!Succeeded(Status))
                    return;

                if (!TryReadQueryResult(Response, out uint Result, out AppIpid))
                {
                    Fail(LrpcPacket.RpcXBadStubData);
                    return;
                }

                if (!Succeeded(Result))
                    return;

                Step = "bind IActivatableApplication";
                Succeeded(App.Client.Bind(ActivatableApplicationInterface, OnApplicationBound));
            }

            private void OnApplicationBound(uint Status, ushort Context)
            {
                if (!Succeeded(Status))
                    return;

                Step = "Activate";
                Ndr20Writer Activate = BuildActivate();
                Succeeded(App.Client.Call(Context, ProcActivate, AppIpid, Activate.Written, OnActivated));
            }

            private void OnActivated(uint Status, ReadOnlySpan<byte> Response)
            {
                if (!Succeeded(Status))
                    return;

                if (!Orpc.TryGetResponseParameters(Response, out int Offset) || Response.Length - Offset < sizeof(uint))
                    Fail(LrpcPacket.RpcXBadStubData);
                else
                    Succeeded(BinaryPrimitives.ReadUInt32LittleEndian(Response.Slice(Offset)));
            }

            private bool Succeeded(uint Status)
            {
                if (Status == LrpcPacket.RpcOk)
                    return true;

                Fail(Status);
                return false;
            }

            // A newer registration closes the client of this one, and the calls that close ends are not failures.
            private void Fail(uint Status)
            {
                if (Registrar.Current != App)
                    return;

                Utils.LogError($"[-] ActivationManager: launching {Application?.Id} through \"{AppPortName}\" failed at {Step} with 0x{Status:X8}.");
                App.View = null;
                App.Client?.Close();
            }

            private static Ndr20Writer BuildQuery(Guid Ipid)
            {
                const ushort InterfaceCount = 1;
                Ndr20Writer Writer = new Ndr20Writer(0xC0);
                Orpc.WriteRequestHeader(ref Writer);
                Writer.WriteGuid(Ipid);
                Writer.WriteUInt32(PublicRefs);
                Writer.WriteUInt16(InterfaceCount);
                Writer.AlignTo(4);
                Writer.WriteUInt32(InterfaceCount);
                Writer.WriteGuid(ActivatableApplicationInterface);
                return Writer;
            }

            private static bool TryReadQueryResult(ReadOnlySpan<byte> Response, out uint Result, out Guid Ipid)
            {
                Result = 0;
                Ipid = Guid.Empty;
                if (!Orpc.TryGetResponseParameters(Response, out int Offset))
                    return false;

                Ndr20Reader Reader = new Ndr20Reader(Response.Slice(Offset));
                if (!Reader.TryReadUniqueUInt32(out bool Present, out uint Count) || !Present || Count != 1)
                    return false;

                Reader.Align(8);
                if (!Reader.TryReadUInt32(out Result))
                    return false;

                Reader.Align(8);
                if (!Reader.TryReadBytes(StdObjRef.Size, out ReadOnlySpan<byte> Std))
                    return false;

                Ipid = StdObjRef.Read(Std).Ipid;
                return true;
            }

            private Ndr20Writer BuildActivate()
            {
                const int FixedSize = 0x140;
                string EntryPoint = Application.EntryPoint ?? string.Empty;
                int Characters = EntryPoint.Length + Application.Id.Length + LaunchContract.Length;
                Ndr20Writer Args = BuildLaunchEventArgs();
                Ndr20Writer Writer = new Ndr20Writer(FixedSize + Characters * sizeof(char) + Args.Written.Length);
                Orpc.WriteRequestHeader(ref Writer);
                Orpc.WriteHstring(ref Writer, EntryPoint);
                Orpc.WriteHstring(ref Writer, Application.Id);
                Orpc.WriteHstring(ref Writer, LaunchContract);
                Orpc.WriteHstring(ref Writer, string.Empty);
                Writer.AlignTo(4);
                Writer.WriteUniqueReferent();

                // combase declares no data size in a marshal-by-value OBJREF.
                Orpc.WriteCustomInterfacePointer(ref Writer, ActivatedEventArgsInterface, MarshalByValueClass, 0, Args.Written);
                Writer.WriteUInt64(ActivationId);
                Writer.WriteUInt64(0);
                return Writer;
            }

            // twinapi's CLaunchActivatedEventArgs reads this property set packed, so no value is aligned.
            private Ndr20Writer BuildLaunchEventArgs()
            {
                Ndr20Writer Writer = new Ndr20Writer(0x600);
                WriteCountedString(ref Writer, LaunchActivatedEventArgsClass);

                const uint PropertyCount = 14;
                Writer.WriteUInt32(PropertyCount);
                WriteProperty(ref Writer, "ActivationKind", PropertyTypeUInt32, ActivationKindLaunch);
                WriteProperty(ref Writer, "PreviousExecutionState", PropertyTypeUInt32, ExecutionStateNotRunning);
                WriteProperty(ref Writer, "UserContext", WinToken.InteractiveUserContext);
                WriteProperty(ref Writer, "IsForeground", true);
                WriteProperty(ref Writer, "IsHolographic", false);
                WriteProperty(ref Writer, "IsInitialized", false);
                WriteProperty(ref Writer, "AamActivationId", ActivationId);
                WriteProperty(ref Writer, "AamActivityId", Guid.NewGuid());
                WriteProperty(ref Writer, "CurrentlyShownApplicationViewId", PropertyTypeInt32, 0u);
                WriteProperty(ref Writer, "MultiView:AamActivationId", 0UL);
                WriteProperty(ref Writer, "IsApplicationMultiviewActivationPolicyEnabled", false);
                WriteProperty(ref Writer, "PrelaunchActivated", false);
                WriteProperty(ref Writer, "Arguments", string.Empty);
                WriteProperty(ref Writer, "TileId", Application.Id);
                return Writer;
            }

            private static void WriteCountedString(ref Ndr20Writer Writer, string Value)
            {
                Writer.WriteUInt32((uint)Value.Length);
                Writer.WriteUtf16(Value);
            }

            private static void WriteKey(ref Ndr20Writer Writer, string Key)
            {
                Writer.WriteUInt32(PropertyTypeString);
                WriteCountedString(ref Writer, Key);
            }

            private static void WriteProperty(ref Ndr20Writer Writer, string Key, uint Type, uint Value)
            {
                WriteKey(ref Writer, Key);
                Writer.WriteUInt32(Type);
                Writer.WriteUInt32(Value);
            }

            private static void WriteProperty(ref Ndr20Writer Writer, string Key, ulong Value)
            {
                WriteKey(ref Writer, Key);
                Writer.WriteUInt32(PropertyTypeUInt64);
                BinaryPrimitives.WriteUInt64LittleEndian(Writer.Take(sizeof(ulong)), Value);
            }

            private static void WriteProperty(ref Ndr20Writer Writer, string Key, Guid Value)
            {
                WriteKey(ref Writer, Key);
                Writer.WriteUInt32(PropertyTypeGuid);
                Value.TryWriteBytes(Writer.Take(16));
            }

            private static void WriteProperty(ref Ndr20Writer Writer, string Key, bool Value)
            {
                WriteKey(ref Writer, Key);
                Writer.WriteUInt32(PropertyTypeBoolean);
                Writer.WriteByte((byte)(Value ? 1 : 0));
            }

            private static void WriteProperty(ref Ndr20Writer Writer, string Key, string Value)
            {
                WriteKey(ref Writer, Key);
                Writer.WriteUInt32(PropertyTypeString);
                WriteCountedString(ref Writer, Value);
            }
        }
    }
}
