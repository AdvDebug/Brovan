using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using Brovan.Core.Emulation.OS.Windows.RPC.Ports;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows.RPC.CoreUI
{
    internal static class CoreUIMessage
    {
        private const int HeaderSize = 8;

        internal const byte KindMethod = 1;
        internal const byte KindObjectSystem = 2;
        internal const byte KindProxySystem = 3;
        internal const byte KindEvent = 4;
        internal const byte KindProperty = 5;

        internal const ushort ReceiveRequestConnectProxy = 0;
        internal const ushort ReceiveRequestDisposeProxy = 1;
        internal const ushort ReceiveNotifyProxyMaterialized = 2;

        internal const ushort NotifyImplementationConnected = 0;
        internal const ushort NotifyImplementationDisconnected = 1;

        internal const ushort NotifyMaterializePushedProxy = 0;

        internal static bool TryRead(ReadOnlySpan<byte> Payload, out byte Kind, out ushort Index, out CoreMessagingReader Parameters)
        {
            Kind = 0;
            Index = 0;
            Parameters = default;
            if (Payload.Length < HeaderSize)
                return false;

            uint Size = BinaryPrimitives.ReadUInt32LittleEndian(Payload);
            if (Size < HeaderSize || Size > (uint)Payload.Length)
                return false;

            Kind = Payload[4];
            Index = BinaryPrimitives.ReadUInt16LittleEndian(Payload.Slice(6));
            Parameters = new CoreMessagingReader(Payload.Slice(HeaderSize, (int)Size - HeaderSize));
            return true;
        }

        internal static void Send(HostMessagingCall Call, ulong Target, byte Kind, ushort Index, CoreMessagingWriter Parameters)
        {
            ReadOnlySpan<byte> Written = Parameters != null ? Parameters.Written : ReadOnlySpan<byte>.Empty;
            Span<byte> Header = stackalloc byte[HeaderSize];
            BinaryPrimitives.WriteUInt32LittleEndian(Header, (uint)(HeaderSize + Written.Length));
            Header[4] = Kind;
            Header[5] = 0;
            BinaryPrimitives.WriteUInt16LittleEndian(Header.Slice(6), Index);
            Call.Send(Target, Header, Written);
        }

        // NT drops the connection with a protocol error here, and Brovan only logs.
        internal static void Refuse(string What)
        {
            Utils.LogError($"[-] CoreUI: Brovan's server refused {What}.");
        }

        // Module numbers and type indices are values of this build of CoreUIComponents.dll.
        internal const int MessagingModule = 2;
        internal const int RemoteInterfacesModule = 3;

        internal static uint TypeId(int Module, ushort TypeIndex) => (uint)(0x100 + Module - 1) << 16 | TypeIndex;

        internal static void WriteRoutingInfo(CoreMessagingWriter Parameters, HostMessagingServer Server, ulong Identity)
        {
            Span<byte> Routing = stackalloc byte[CoreMessagingRouting.Size];
            Server.WriteRoutingInfo(Routing, Identity);
            Parameters.Bytes(Routing);
        }

        internal static bool TryReadProxy(ref CoreMessagingReader Parameters, HostMessagingCall Call, out CoreUIProxy Proxy)
        {
            Proxy = null;
            if (!Parameters.TryReadUInt64(out ulong Identity))
                return false;

            if (Identity == 0)
                return true;

            if (!Call.Connection.TryGetEndpoint(Identity, out HostMessagingEndpoint Endpoint) || Endpoint is not CoreUIProxy Found)
                return false;

            Found.Carried(Call);
            Proxy = Found;
            return true;
        }

        internal static HostMessagingServer CreateServer(WinSysHelper Helper, CoreMessagingRegistrarPort Registrar, uint ProcessId, uint ThreadId)
            => HostMessagingServer.Create(Helper, Registrar, ProcessId, ThreadId, new CoreUISession());
    }

    internal ref struct CoreUIPropertyWriter
    {
        internal readonly HostMessagingCall Call;
        internal readonly ReadOnlySpan<byte> ClientRouting;
        internal readonly CoreMessagingWriter Value;
        internal bool Failed;

        internal CoreUIPropertyWriter(HostMessagingCall Call, ReadOnlySpan<byte> ClientRouting, CoreMessagingWriter Value)
        {
            this.Call = Call;
            this.ClientRouting = ClientRouting;
            this.Value = Value;
            Failed = false;
        }

        // Each writer returns whether the value is not zero.
        internal bool UInt32(uint Data)
        {
            Value.UInt32(Data);
            return Data != 0;
        }

        internal bool UInt64(ulong Data)
        {
            Value.UInt64(Data);
            return Data != 0;
        }

        internal bool Bool(bool Data)
        {
            Value.Bool(Data);
            return Data;
        }

        internal bool Bytes(scoped ReadOnlySpan<byte> Data)
        {
            Value.Bytes(Data);
            return Data.ContainsAnyExcept((byte)0);
        }

        internal bool WriteObject(CoreUIObject Object)
        {
            if (Object == null)
            {
                Value.UInt64(0);
                return false;
            }

            if (!Object.TryPush(Call, ClientRouting, out ulong Proxy))
            {
                Failed = true;
                return false;
            }

            Value.UInt64(Proxy);
            return true;
        }
    }

    internal abstract class CoreUIObject : HostMessagingEndpoint
    {
        protected abstract uint TypeId { get; }

        protected virtual int PropertyCount => 0;

        // False when the value is zero, which a snapshot leaves out.
        protected virtual bool WriteProperty(ref CoreUIPropertyWriter Writer, ushort Index) => false;

        protected abstract void Invoke(HostMessagingCall Call, ushort Method, ref CoreMessagingReader Parameters);

        protected virtual void ProxyCreated(HostMessagingCall Call, ulong Proxy)
        {
        }

        protected static void SendEvent(HostMessagingCall Call, ulong Proxy, ushort Index, CoreMessagingWriter Parameters)
            => CoreUIMessage.Send(Call, Proxy, CoreUIMessage.KindEvent, Index, Parameters);

        // A run-time object has its stubs on its own connection only.
        protected void NotifyPropertyChanged(HostMessagingCall Call, ushort Index)
        {
            HostMessagingConnection Owner = Connection;
            if (Owner == null)
            {
                CoreUIMessage.Refuse($"to change property {Index} of a named object");
                return;
            }

            HostMessagingCall Target = Call.Connection == Owner ? Call : new HostMessagingCall(Call.Instance, Owner);
            CoreMessagingWriter Value = new CoreMessagingWriter();
            foreach (HostMessagingConnection.Stub Stub in Owner.StubsOf(this))
                SendProperty(Target, Stub.Proxy, Stub.Routing, Index, Value, SkipZero: false);

            if (Target != Call)
                Target.Flush();
        }

        private void SendProperty(HostMessagingCall Call, ulong Proxy, ReadOnlySpan<byte> ProxyRouting, ushort Index, CoreMessagingWriter Value, bool SkipZero)
        {
            Value.Clear();
            CoreUIPropertyWriter Writer = new CoreUIPropertyWriter(Call, ProxyRouting, Value);
            bool NotZero = WriteProperty(ref Writer, Index);
            if ((NotZero || !SkipZero) && !Writer.Failed)
                CoreUIMessage.Send(Call, Proxy, CoreUIMessage.KindProperty, Index, Value);
        }

        internal sealed override void Receive(HostMessagingCall Call, ReadOnlySpan<byte> Payload)
        {
            if (!CoreUIMessage.TryRead(Payload, out byte Kind, out ushort Index, out CoreMessagingReader Parameters))
            {
                CoreUIMessage.Refuse($"a message of {Payload.Length} bytes to an object");
                return;
            }

            if (Kind == CoreUIMessage.KindMethod)
                Invoke(Call, Index, ref Parameters);
            else if (Kind == CoreUIMessage.KindObjectSystem)
                ReceiveSystem(Call, Index, ref Parameters);
            else
                CoreUIMessage.Refuse($"a message of kind {Kind} to an object");
        }

        private void ReceiveSystem(HostMessagingCall Call, ushort Method, ref CoreMessagingReader Parameters)
        {
            uint Type = 0;
            if ((Method == CoreUIMessage.ReceiveRequestConnectProxy && !Parameters.TryReadUInt32(out Type))
                || !Parameters.TryReadFixed(CoreMessagingRouting.Size, out ReadOnlySpan<byte> Routing) || !Parameters.AtEnd)
            {
                CoreUIMessage.Refuse($"object system method {Method} with parameters that do not match it");
                return;
            }

            ulong Proxy = CoreMessagingRouting.Identity(Routing);
            switch (Method)
            {
                case CoreUIMessage.ReceiveRequestConnectProxy:
                    ConnectProxy(Call, Type, Routing);
                    break;
                case CoreUIMessage.ReceiveRequestDisposeProxy:
                    if (Call.Connection.TryRemoveStub(this, Proxy))
                        CoreUIMessage.Send(Call, Proxy, CoreUIMessage.KindProxySystem, CoreUIMessage.NotifyImplementationDisconnected, null);
                    break;
                case CoreUIMessage.ReceiveNotifyProxyMaterialized:
                    Call.Connection.Materialized(this, Proxy);
                    break;
                default:
                    CoreUIMessage.Refuse($"object system method {Method}");
                    break;
            }
        }

        private void ConnectProxy(HostMessagingCall Call, uint Type, ReadOnlySpan<byte> ProxyRouting)
        {
            if (Type != TypeId)
            {
                CoreUIMessage.Refuse($"a proxy of type 0x{Type:X8} for an object of type 0x{TypeId:X8}");
                return;
            }

            ulong Proxy = CoreMessagingRouting.Identity(ProxyRouting);
            if (!Call.Connection.TryAddStub(this, Proxy, ProxyRouting))
            {
                CoreUIMessage.Refuse("a second proxy at one identity, or one past the limit of objects");
                return;
            }

            InitializeProxy(Call, Proxy, ProxyRouting);
            ProxyCreated(Call, Proxy);
        }

        private void InitializeProxy(HostMessagingCall Call, ulong Proxy, ReadOnlySpan<byte> ProxyRouting)
        {
            CoreMessagingWriter Value = new CoreMessagingWriter();
            for (int Index = 0; Index < PropertyCount; Index++)
                SendProperty(Call, Proxy, ProxyRouting, (ushort)Index, Value, SkipZero: true);

            CoreUIMessage.Send(Call, Proxy, CoreUIMessage.KindProxySystem, CoreUIMessage.NotifyImplementationConnected, null);
        }

        internal bool TryPush(HostMessagingCall Call, ReadOnlySpan<byte> ClientRouting, out ulong Proxy)
        {
            Proxy = 0;
            HostMessagingConnection Connection = Call.Connection;
            if (this.Connection != null && this.Connection != Connection)
            {
                CoreUIMessage.Refuse("to push an object of one connection to another");
                return false;
            }

            if (Connection.TryCountPush(this, out Proxy))
                return true;

            uint ClientGroup = Connection.Client.Group;
            Span<byte> ProxyRouting = stackalloc byte[CoreMessagingRouting.Size];
            if (ClientGroup == 0 || !Call.TryAllocateRemoteEndpoint(this, ClientRouting, ProxyRouting, out Proxy))
            {
                CoreUIMessage.Refuse("to push an object to a client with no identity left");
                return false;
            }

            Connection.CountPush(this, Proxy);

            CoreMessagingWriter Parameters = new CoreMessagingWriter();
            CoreUIMessage.WriteRoutingInfo(Parameters, Call.Server, Identity);
            Parameters.Bytes(ProxyRouting);
            Parameters.UInt32(TypeId);
            CoreUIMessage.Send(Call, HIdentityAllocator.SessionIdentity(ClientGroup, 1), CoreUIMessage.KindMethod, CoreUIMessage.NotifyMaterializePushedProxy, Parameters);
            InitializeProxy(Call, Proxy, ProxyRouting);
            ProxyCreated(Call, Proxy);
            return true;
        }
    }

    // Brovan's maps have no entries, so a new proxy gets OnInitialized and no OnInsert.
    internal sealed class CoreUIMessageMap : CoreUIObject
    {
        private const ushort MessageMapType = 0x0053;
        private const ushort OnInitialized = 0;

        protected override uint TypeId => CoreUIMessage.TypeId(CoreUIMessage.MessagingModule, MessageMapType);

        protected override void Invoke(HostMessagingCall Call, ushort Method, ref CoreMessagingReader Parameters)
            => CoreUIMessage.Refuse($"IRemoteMessageMap method {Method}");

        protected override void ProxyCreated(HostMessagingCall Call, ulong Proxy) => SendEvent(Call, Proxy, OnInitialized, null);
    }

    internal sealed class CoreUIProxy : HostMessagingEndpoint
    {
        private readonly byte[] Routing;
        private readonly Dictionary<ushort, byte[]> Properties = new Dictionary<ushort, byte[]>();
        private int PropertyBytes;
        private bool Materialized;

        internal CoreUIProxy(ReadOnlySpan<byte> ObjectRouting, uint TypeId)
        {
            Routing = ObjectRouting.ToArray();
            this.TypeId = TypeId;
        }

        internal uint TypeId { get; }

        // Called once when the proxy leaves its server, with a null call when its connection ended.
        internal Action<HostMessagingCall> Disconnected { get; set; }

        internal ReadOnlySpan<byte> ObjectRouting => Routing;

        internal ulong ObjectIdentity => CoreMessagingRouting.Identity(Routing);

        internal ReadOnlySpan<byte> Property(ushort Index) => Properties.TryGetValue(Index, out byte[] Value) ? Value : ReadOnlySpan<byte>.Empty;

        internal void Invoke(HostMessagingCall Call, ushort Method, CoreMessagingWriter Parameters)
            => CoreUIMessage.Send(Call, ObjectIdentity, CoreUIMessage.KindMethod, Method, Parameters);

        internal void InvokeWithObject(HostMessagingCall Call, ushort Method, CoreUIObject Argument)
        {
            CoreMessagingWriter Parameters = new CoreMessagingWriter();
            CoreUIPropertyWriter Writer = new CoreUIPropertyWriter(Call, Routing, Parameters);
            Writer.WriteObject(Argument);
            if (!Writer.Failed)
                Invoke(Call, Method, Parameters);
        }

        // NT tells the object once, at the first call that carries the pushed proxy, that the proxy materialized.
        internal void Carried(HostMessagingCall Call)
        {
            if (Materialized)
                return;

            Materialized = true;
            CoreMessagingWriter Parameters = new CoreMessagingWriter();
            CoreUIMessage.WriteRoutingInfo(Parameters, Call.Server, Identity);
            CoreUIMessage.Send(Call, ObjectIdentity, CoreUIMessage.KindObjectSystem, CoreUIMessage.ReceiveNotifyProxyMaterialized, Parameters);
        }

        internal override void Receive(HostMessagingCall Call, ReadOnlySpan<byte> Payload)
        {
            if (!CoreUIMessage.TryRead(Payload, out byte Kind, out ushort Index, out CoreMessagingReader Parameters))
            {
                CoreUIMessage.Refuse($"a message of {Payload.Length} bytes to a proxy");
                return;
            }

            if (Kind == CoreUIMessage.KindProperty)
            {
                SetProperty(Call.Server, Index, ref Parameters);
                return;
            }

            if (Kind != CoreUIMessage.KindProxySystem || !Parameters.AtEnd)
            {
                CoreUIMessage.Refuse($"a message of kind {Kind} to a proxy");
                return;
            }

            if (Index == CoreUIMessage.NotifyImplementationDisconnected)
            {
                Gone(Call);
                Call.Server.Remove(this);
            }
            else if (Index != CoreUIMessage.NotifyImplementationConnected)
                CoreUIMessage.Refuse($"proxy system method {Index}");
        }

        internal override void Released()
        {
            Connection.Server.ReleaseBytes(PropertyBytes);
            PropertyBytes = 0;
            Properties.Clear();
            Gone(null);
        }

        private void Gone(HostMessagingCall Call)
        {
            Action<HostMessagingCall> Listener = Disconnected;
            Disconnected = null;
            Listener?.Invoke(Call);
        }

        private void SetProperty(HostMessagingServer Server, ushort Index, ref CoreMessagingReader Parameters)
        {
            if (!Parameters.TryReadNext(out ReadOnlySpan<byte> Value) || !Parameters.AtEnd)
            {
                CoreUIMessage.Refuse($"property {Index} with parameters that do not match it");
                return;
            }

            int OldBytes = Properties.TryGetValue(Index, out byte[] Old) ? HostMessagingServer.HeldEntryBytes + Old.Length : 0;
            int NewBytes = HostMessagingServer.HeldEntryBytes + Value.Length;
            if (NewBytes > OldBytes && !Server.TryHoldBytes(NewBytes - OldBytes))
            {
                CoreUIMessage.Refuse($"property {Index} past the limit of bytes the server holds");
                return;
            }

            if (NewBytes < OldBytes)
                Server.ReleaseBytes(OldBytes - NewBytes);

            PropertyBytes += NewBytes - OldBytes;
            if (Old != null && Old.Length == Value.Length)
                Value.CopyTo(Old);
            else
                Properties[Index] = Value.ToArray();
        }
    }

    internal sealed class CoreUISession : HostMessagingEndpoint
    {
        internal override void Receive(HostMessagingCall Call, ReadOnlySpan<byte> Payload)
        {
            if (!CoreUIMessage.TryRead(Payload, out byte Kind, out ushort Index, out CoreMessagingReader Parameters)
                || Kind != CoreUIMessage.KindMethod || Index != CoreUIMessage.NotifyMaterializePushedProxy
                || !Parameters.TryReadFixed(CoreMessagingRouting.Size, out ReadOnlySpan<byte> ObjectRouting)
                || !Parameters.TryReadFixed(CoreMessagingRouting.Size, out ReadOnlySpan<byte> ProxyRouting)
                || !Parameters.TryReadUInt32(out uint TypeId) || !Parameters.AtEnd)
            {
                CoreUIMessage.Refuse($"a message of {Payload.Length} bytes to the session endpoint");
                return;
            }

            if (!Call.Connection.Client.IsNamedBy(ObjectRouting))
            {
                CoreUIMessage.Refuse("a pushed object that is not the sender's");
                return;
            }

            if (!Call.Server.TryAdd(Call.Connection, CoreMessagingRouting.Identity(ProxyRouting), new CoreUIProxy(ObjectRouting, TypeId)))
                CoreUIMessage.Refuse("a pushed object at an identity outside its connection's group");
        }
    }
}
