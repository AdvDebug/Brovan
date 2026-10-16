using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Ports
{
    internal static class ActivationManagerPortHandler
    {
        public static readonly Guid RegistrarClass = new Guid("dea794e0-1c1d-4363-b171-98d0b1703586");
        private static readonly Guid RegistrarInterface = new Guid("036c57fc-e73d-4f3a-b095-8b813fa2f764");
        private static readonly Guid RemUnknownInterface = new Guid("00000131-0000-0000-c000-000000000046");
        private static readonly Guid RemUnknown2Interface = new Guid("00000143-0000-0000-c000-000000000046");
        private static readonly Guid RundownInterface = new Guid("00000134-0000-0000-c000-000000000046");
        private static readonly Guid[] ServedInterfaces = { RegistrarInterface, RemUnknownInterface, RemUnknown2Interface, RundownInterface };

        private const uint ProcRegisterActivatableApplication = 3;
        private const uint ProcRemQueryInterface = 3;
        private const uint ProcRemAddRef = 4;
        private const uint ProcRemRelease = 5;
        private const uint ProcActivate = 6;

        private static readonly Guid ActivatableApplicationInterface = new Guid("92696c00-7578-48e1-ac1a-2ca909e2c8cf");
        private static readonly Guid ActivatedEventArgsInterface = new Guid("cf651713-cd08-4fd8-b697-a281b6544e2e");
        private static readonly Guid MarshalByValueClass = new Guid("0000035a-0000-0000-c000-000000000046");
        private const string LaunchContract = "Windows.Launch";
        private const string LaunchActivatedEventArgsClass = "Windows.ApplicationModel.Activation.LaunchActivatedEventArgs";

        private const uint PropertyTypeInt32 = 4;
        private const uint PropertyTypeUInt32 = 5;
        private const uint PropertyTypeUInt64 = 7;
        private const uint PropertyTypeBoolean = 11;
        private const uint PropertyTypeString = 12;
        private const uint PropertyTypeGuid = 16;
        private const uint ActivationKindLaunch = 0;
        private const uint ExecutionStateNotRunning = 0;

        // The traits combase gives the shell's registrar, a free-threaded object with agile proxies.
        private const uint ObjectFlags = 0xE80;
        private const uint PublicRefs = 5;
        private const ushort MultithreadedApartment = 0xFFFF;
        private const int RemUnknownIpidSequence = 0x1401;
        private const int RegistrarUnknownIpidSequence = 0x24007;
        private const int RegistrarIpidSequence = 0x24008;
        private const int InterfaceRefSize = 0x18;
        private const int QueryResultSize = 0x30;

        private const uint RpcEInvalidIpid = 0x8001012B;

        public static readonly string Endpoint = "OLE" + Convert.ToHexString(RandomNumberGenerator.GetBytes(14));
        public static readonly string PortName = LrpcClient.GetPortName(Endpoint);
        public static readonly ulong Oxid = Orpc.NewId();
        public static readonly Guid ProcessIdentifier = Guid.NewGuid();
        private static readonly ulong RegistrarOid = Orpc.NewId();

        private static readonly byte[] SuccessReply = BuildSuccessReply();

        private sealed class Registration
        {
            public readonly StdObjRef Object;
            public LrpcClient Client;

            public Registration(StdObjRef Object)
            {
                this.Object = Object;
            }
        }

        private sealed class Shell
        {
            public readonly Guid RemUnknownIpid;
            public readonly Guid RegistrarUnknownIpid;
            public readonly Guid RegistrarIpid;
            public uint ThreadId;
            public Registration App;

            public Shell(uint ProcessId)
            {
                RemUnknownIpid = NewIpid(ProcessId, RemUnknownIpidSequence);
                RegistrarUnknownIpid = NewIpid(ProcessId, RegistrarUnknownIpidSequence);
                RegistrarIpid = NewIpid(ProcessId, RegistrarIpidSequence);
            }
        }

        private static readonly ConditionalWeakTable<BinaryEmulator, Shell> Shells = new();

        private static Shell GetShell(BinaryEmulator Instance)
        {
            return Shells.GetValue(Instance, static Emulator => new Shell(Emulator.WinHelper.ShellProcess.PID));
        }

        // combase puts the server's process id and its apartment in the IPID.
        private static Guid NewIpid(uint ProcessId, int Sequence)
        {
            Span<byte> Ipid = stackalloc byte[16];
            BinaryPrimitives.WriteInt32LittleEndian(Ipid, Sequence);
            BinaryPrimitives.WriteUInt16LittleEndian(Ipid.Slice(4), unchecked((ushort)ProcessId));
            BinaryPrimitives.WriteUInt16LittleEndian(Ipid.Slice(6), MultithreadedApartment);
            RandomNumberGenerator.Fill(Ipid.Slice(8));
            return new Guid(Ipid);
        }

        private static byte[] BuildSuccessReply()
        {
            Ndr20Writer Writer = new Ndr20Writer(0x40);
            Orpc.WriteResponseHeader(ref Writer);
            Writer.WriteUInt32(Orpc.SOk);
            return Writer.ToArray();
        }

        public static Guid GetRemUnknownIpid(BinaryEmulator Instance)
        {
            return GetShell(Instance).RemUnknownIpid;
        }

        public static bool IsRegistrarInterface(Guid Interface) => Interface == Orpc.IUnknownId || Interface == RegistrarInterface;

        public static StdObjRef GetRegistrar(BinaryEmulator Instance, Guid Interface)
        {
            return RegistrarObject(GetShell(Instance), Interface, PublicRefs);
        }

        private static StdObjRef RegistrarObject(Shell Current, Guid Interface, uint Refs)
        {
            return new StdObjRef(ObjectFlags, Refs, Oxid, RegistrarOid, Interface == RegistrarInterface ? Current.RegistrarIpid : Current.RegistrarUnknownIpid);
        }

        public static string GetPrincipal(BinaryEmulator Instance)
        {
            return LsaLookupPortHandler.ReadComputerName(Instance) + "\\" + WinSysHelper.CurrentUserName;
        }

        public static NTSTATUS Handle(WinPort Port, byte[] SendData, PortReply Reply, BinaryEmulator Instance)
        {
            if (!LrpcPacket.TryParse(SendData, out LrpcMessage Message))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Message.Type == LrpcMessageType.Bind)
            {
                if (!LrpcBindings.TryAccept(Reply.Client, Message, ServedInterfaces, out Guid Interface, out Reply.Data))
                {
                    if ((Instance.Settings.Flags & LogFlags.General) != 0)
                        Instance.TriggerEventMessage($"[!] ActivationManager: no interface {Interface}; refusing the bind.", LogFlags.General);
                    Reply.Data = LrpcPacket.BuildFault(Message, LrpcPacket.RpcSUnknownIf);
                }
            }
            else if (Message.Type == LrpcMessageType.Request)
            {
                Reply.Data = HandleRequest(Message, Reply.Client, Instance);
            }

            Reply.Data ??= LrpcPacket.EchoHeader(SendData);

            return NTSTATUS.STATUS_SUCCESS;
        }

        // The handlers below return the whole reply, or null for a request they cannot read.
        private static byte[] HandleRequest(in LrpcMessage Message, ServedClient Client, BinaryEmulator Instance)
        {
            if (!LrpcBindings.TryResolve(Client, Message, out Guid Interface, out Guid Ipid))
                return LrpcPacket.BuildFault(Message, LrpcPacket.RpcSUnknownIf);

            ReadOnlySpan<byte> Stub = Message.StubData;
            if (!Orpc.TryGetRequestParameters(Stub, out int Offset))
                return LrpcPacket.BuildFault(Message, LrpcPacket.RpcXBadStubData);

            Shell Current = GetShell(Instance);
            ReadOnlySpan<byte> Parameters = Stub.Slice(Offset);
            byte[] Reply;
            if (Ipid == Current.RemUnknownIpid && Interface != RegistrarInterface)
            {
                Reply = HandleRemUnknown(Message, Parameters, Current);
            }
            else if (Ipid == Current.RegistrarIpid && Interface == RegistrarInterface && Message.ProcNumber == ProcRegisterActivatableApplication)
            {
                Reply = RegisterActivatableApplication(Message, Parameters, Instance, Current);
            }
            else
            {
                Utils.LogError($"[-] ActivationManager: no method {Message.ProcNumber} of {Interface} on IPID {Ipid}.");
                return LrpcPacket.BuildFault(Message, RpcEInvalidIpid);
            }

            return Reply ?? LrpcPacket.BuildFault(Message, LrpcPacket.RpcXBadStubData);
        }

        private static byte[] RegisterActivatableApplication(in LrpcMessage Message, ReadOnlySpan<byte> Parameters, BinaryEmulator Instance, Shell Current)
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
            Registration Previous = Current.App;
            Registration App = new Registration(Object);
            Current.App = App;
            Previous?.Client?.Close();

            new Launch(Instance, Current, App).Start();
            return LrpcPacket.BuildResponse(Message, SuccessReply);
        }

        private sealed class Launch
        {
            private readonly BinaryEmulator Instance;
            private readonly Shell Current;
            private readonly Registration App;
            private AppxApplication Application;
            private Guid AppRemUnknownIpid;
            private Guid AppIpid;
            private readonly ulong ActivationId = Orpc.NewId();
            private string? AppPortName;
            private string Step;

            public Launch(BinaryEmulator Instance, Shell Current, Registration App)
            {
                this.Instance = Instance;
                this.Current = Current;
                this.App = App;
            }

            public void Start()
            {
                Application = Instance.WindowsGuest?.PackageIdentity?.Application;
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

                AppRemUnknownIpid = Server.RemUnknownIpid;
                WinSysHelper Helper = Instance.WinHelper;
                WinProcess ShellProcess = Helper.ShellProcess;
                if (Current.ThreadId == 0)
                    Current.ThreadId = Helper.GenerateRandomPID();

                AppPortName = LrpcClient.GetPortName(Server.Endpoint);
                Step = "connect";
                Succeeded(LrpcClient.Connect(Instance, AppPortName, ShellProcess.PID, Current.ThreadId, ShellProcess.GetPrimaryToken(),
                    SecurityImpersonationLevel.SecurityIdentification, OnConnected, out App.Client));
            }

            private void OnConnected(uint Status)
            {
                if (!Succeeded(Status))
                    return;

                Step = "bind IRundown";
                Succeeded(App.Client.Bind(RundownInterface, OnRundownBound));
            }

            private void OnRundownBound(uint Status, ushort Context)
            {
                if (!Succeeded(Status))
                    return;

                Step = "RemQueryInterface";
                Ndr20Writer Query = BuildQuery(App.Object.Ipid);
                Succeeded(App.Client.Call(Context, ProcRemQueryInterface, AppRemUnknownIpid, Query.Written, OnQueried));
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
                if (Current.App != App)
                    return;

                Utils.LogError($"[-] ActivationManager: launching {Application?.Id} through \"{AppPortName}\" failed at {Step} with 0x{Status:X8}.");
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
                WriteProperty(ref Writer, "UserContext", 0UL);
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

        private static byte[] HandleRemUnknown(in LrpcMessage Message, ReadOnlySpan<byte> Parameters, Shell Current)
        {
            switch (Message.ProcNumber)
            {
                case ProcRemQueryInterface:
                    return RemQueryInterface(Message, Parameters, Current);

                case ProcRemAddRef:
                    return RemAddRef(Message, Parameters);

                case ProcRemRelease:
                    return TryReadInterfaceRefs(Parameters, out _) ? LrpcPacket.BuildResponse(Message, SuccessReply) : null;
            }

            Utils.LogError($"[-] ActivationManager: IRemUnknown method {Message.ProcNumber} is not supported.");
            return null;
        }

        private static byte[] RefuseViewReply(in LrpcMessage Message, int Count)
        {
            Utils.LogError($"[-] ActivationManager: a reply for {Count} interfaces needs a view, which is not supported.");
            return LrpcPacket.BuildFault(Message, LrpcPacket.RpcSCannotSupport);
        }

        private static byte[] RemQueryInterface(in LrpcMessage Message, ReadOnlySpan<byte> Parameters, Shell Current)
        {
            Ndr20Reader Reader = new Ndr20Reader(Parameters);
            if (!Reader.TryReadGuid(out Guid Ipid) || !Reader.TryReadUInt32(out uint Refs) || !Reader.TryReadUInt16(out ushort Count)
                || !Reader.TryReadUInt32(out uint Conformance) || Conformance != Count || Count == 0 || Count > Orpc.MaxRequestedInterfaces
                || !Reader.TryReadBytes(Count * Orpc.InterfaceIdSize, out ReadOnlySpan<byte> Interfaces))
                return null;

            if (Ipid != Current.RegistrarIpid && Ipid != Current.RegistrarUnknownIpid)
                return null;

            if (Count > LrpcPacket.MaxResponseStubLength / QueryResultSize)
                return RefuseViewReply(Message, Count);

            Ndr20Writer Writer = new Ndr20Writer(0x40 + Count * QueryResultSize);
            Orpc.WriteResponseHeader(ref Writer);
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32(Count);
            for (int i = 0; i < Count; i++)
            {
                Guid Interface = new Guid(Interfaces.Slice(i * Orpc.InterfaceIdSize, Orpc.InterfaceIdSize));
                bool Supported = IsRegistrarInterface(Interface);
                StdObjRef Object = Supported ? RegistrarObject(Current, Interface, Refs) : default;

                Writer.AlignTo(8);
                Writer.WriteUInt32(Supported ? Orpc.SOk : Orpc.ENoInterface);
                Writer.AlignTo(8);
                Object.Write(Writer.Take(StdObjRef.Size));
            }

            Writer.WriteUInt32(Orpc.SOk);
            return LrpcPacket.BuildResponse(Message, Writer.Written);
        }

        // The objects of this apartment live as long as the emulator, so references are not counted.
        private static bool TryReadInterfaceRefs(ReadOnlySpan<byte> Parameters, out ushort Count)
        {
            Ndr20Reader Reader = new Ndr20Reader(Parameters);
            return Reader.TryReadUInt16(out Count) && Reader.TryReadUInt32(out uint Conformance) && Conformance == Count
                && Reader.TrySkip(Count * InterfaceRefSize);
        }

        private static byte[] RemAddRef(in LrpcMessage Message, ReadOnlySpan<byte> Parameters)
        {
            if (!TryReadInterfaceRefs(Parameters, out ushort Count))
                return null;

            if (Count > LrpcPacket.MaxResponseStubLength / sizeof(uint))
                return RefuseViewReply(Message, Count);

            Ndr20Writer Writer = new Ndr20Writer(0x40 + Count * sizeof(uint));
            Orpc.WriteResponseHeader(ref Writer);
            Writer.WriteUInt32(Count);
            for (int i = 0; i < Count; i++)
                Writer.WriteUInt32(Orpc.SOk);

            Writer.WriteUInt32(Orpc.SOk);
            return LrpcPacket.BuildResponse(Message, Writer.Written);
        }
    }
}
