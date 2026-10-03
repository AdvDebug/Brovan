using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Ports
{
    // dnsrslvr, interface 45776b01-5956-4485-9f80-f428f7d60129 v2.0.
    public static class DnsResolverPortHandler
    {
        public const string PortName = "\\RPC Control\\DNSResolver";

        private const uint ProcResolverQuery = 4;

        private const ushort TypeA = 1;
        private const ushort TypeCname = 5;
        private const ushort TypeAaaa = 28;

        private const uint FlagsAnswerUnicode = 0x0009;
        private const uint FlagNamePresent = 0x2000;
        private const uint FlagNestedData = 0x1000;

        // As the x64 service writes them. The client recomputes them for its own width.
        private const ushort DataLengthA = 4;
        private const ushort DataLengthAaaa = 16;
        private const ushort DataLengthCname = 8;

        private const uint RecordTtl = 0;

        private const uint ErrorInvalidParameter = 87;
        private const uint ErrorInvalidName = 123;
        private const uint ErrorNotSupported = 50;
        private const uint DnsErrorRcodeServerFailure = 9002;
        private const uint DnsErrorRcodeNameError = 9003;
        private const uint DnsErrorRcodeNotImplemented = 9004;
        private const uint DnsInfoNoRecords = 9501;
        private const uint DnsErrorNoDnsServers = 9852;

        private const uint RpcSCallFailed = 1726;
        private const uint RpcSProcnumOutOfRange = 1745;
        private const uint RpcXBadStubData = 1783;

        // DNS_QUERY_DUAL_ADDR: AAAA records first, then the A records mapped into IPv6.
        private const ulong QueryDualAddr = 0x4000;

        private const int MaxNameLength = 255;

        private sealed class HostAnswer
        {
            public string Name;
            public ushort Type;
            public bool Dual;
            public uint Status;
            public string CanonicalName;
            public List<byte[]> Addresses;

            public bool Answers(string QueryName, ushort QueryType, bool QueryDual) =>
                QueryType == Type && QueryDual == Dual && string.Equals(QueryName, Name, StringComparison.Ordinal);
        }

        public static NTSTATUS Handle(WinPort Port, byte[] SendData, PortReply Reply, BinaryEmulator Instance)
        {
            if (!LrpcPacket.TryParse(SendData, out LrpcMessage Message))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            switch (Message.Type)
            {
                case LrpcMessageType.Bind:
                    Reply.Data = LrpcPacket.BuildBindAccept(Message, out _);
                    break;

                case LrpcMessageType.Request:
                    Reply.Data = Message.ProcNumber == ProcResolverQuery
                        ? ResolverQuery(Message, Reply, Instance)
                        : Unimplemented(Message, Instance);
                    break;
            }

            if (Reply.Data == null)
            {
                Reply.Data = new byte[LrpcPacket.HeaderSize];
                Array.Copy(SendData, Reply.Data, Math.Min(LrpcPacket.HeaderSize, SendData.Length));
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static byte[] Unimplemented(in LrpcMessage Message, BinaryEmulator Instance)
        {
            if ((Instance.Settings.Flags & LogFlags.General) != 0)
                Instance.TriggerEventMessage($"[!] No server for proc {Message.ProcNumber} on \"{PortName}\"; faulting.", LogFlags.General);

            return LrpcPacket.BuildFault(Message, RpcSProcnumOutOfRange);
        }

        // R_ResolverQuery(name, type, 3 ULONGs, server count, servers, 2-byte struct, [in, out] options,
        // [out] records, handle, ULONG64, message)
        private static byte[] ResolverQuery(in LrpcMessage Message, PortReply Reply, BinaryEmulator Instance)
        {
            ReadOnlySpan<byte> Stub = Message.StubData;
            if (Stub.Length < sizeof(ulong) || (Stub.Length & 7) != 0)
                return LrpcPacket.BuildFault(Message, RpcXBadStubData);

            Ndr20Reader Reader = new Ndr20Reader(Stub);
            if (!Reader.TryReadUniqueWideString(out string Name))
                return LrpcPacket.BuildFault(Message, RpcXBadStubData);

            if (!Reader.TryReadUInt16(out ushort Type))
                return LrpcPacket.BuildFault(Message, RpcXBadStubData);

            if (!Reader.TryReadUInt32(out _) || !Reader.TrySkip(2 * sizeof(uint)) || !Reader.TryReadUInt32(out uint ServerCount) || !Reader.TryReadUInt32(out uint ServersReferent))
                return LrpcPacket.BuildFault(Message, RpcXBadStubData);

            ulong QueryOptions = BinaryPrimitives.ReadUInt64LittleEndian(Stub.Slice(Stub.Length - sizeof(ulong)));

            if (ServerCount != 0 || ServersReferent != 0)
            {
                if ((Instance.Settings.Flags & LogFlags.General) != 0)
                    Log(Instance, $"query for \"{Name}\" names its own DNS servers; the host resolver cannot use them.");
                return BuildReply(Message, QueryOptions, null, ErrorNotSupported);
            }

            if (!Reader.TryReadUInt16(out _) || !Reader.TryReadUInt64(out ulong InlineOptions) || InlineOptions != QueryOptions)
                return LrpcPacket.BuildFault(Message, RpcXBadStubData);

            if (Name == null)
                return BuildReply(Message, QueryOptions, null, ErrorInvalidParameter);

            if (Instance.Settings.GetNetworkPolicy().Mode != NetworkAccessMode.Full)
                return BuildReply(Message, QueryOptions, null, DnsErrorNoDnsServers);

            if (Type != TypeA && Type != TypeAaaa)
            {
                if ((Instance.Settings.Flags & LogFlags.General) != 0)
                    Log(Instance, $"query for \"{Name}\" asks for record type {Type}; the host resolver answers A and AAAA only.");
                return BuildReply(Message, QueryOptions, null, DnsErrorRcodeNotImplemented);
            }

            bool Dual = Type == TypeAaaa && (QueryOptions & QueryDualAddr) != 0;
            EmulatedThread Thread = Instance.CurrentThread;
            WindowsThreadState State = Thread == null ? null : WinEmulatedThread.GetState(Thread);
            if (State?.HostWork is Task<HostAnswer> Done && Done.IsCompleted && Done.Result.Answers(Name, Type, Dual))
            {
                State.HostWork = null;
                return BuildReply(Message, QueryOptions, Done.Result, Done.Result.Status);
            }

            Task<HostAnswer> Lookup = StartLookup(Name, Type, Dual, Instance.WakeSignal);
            if (Lookup.IsCompleted)
                return BuildReply(Message, QueryOptions, Lookup.Result, Lookup.Result.Status);

            Reply.HostWork = Lookup;
            return LrpcPacket.BuildFault(Message, RpcSCallFailed);
        }

        private static Task<HostAnswer> StartLookup(string Name, ushort Type, bool Dual, WakeSignal Wake)
        {
            if (Name.Length == 0 || Name.Length > MaxNameLength)
                return Task.FromResult(Failed(Name, Type, Dual, ErrorInvalidName));

            AddressFamily Family = Dual ? AddressFamily.Unspecified : Type == TypeA ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;

            // The host resolver would turn a literal into a reverse lookup.
            if (IPAddress.TryParse(Name, out IPAddress Literal))
                return Task.FromResult(FromAddresses(Name, Type, Dual, null, new[] { Literal }));

            Task<HostAnswer> Lookup = LookUpOnHost(Name, Type, Dual, Family);
            Lookup.ContinueWith(static (_, Signal) => ((WakeSignal)Signal).Bump(), Wake, CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            return Lookup;
        }

        private static async Task<HostAnswer> LookUpOnHost(string Name, ushort Type, bool Dual, AddressFamily Family)
        {
            try
            {
                IPHostEntry Entry = await Dns.GetHostEntryAsync(Name, Family).ConfigureAwait(false);
                return FromAddresses(Name, Type, Dual, Entry.HostName, Entry.AddressList);
            }
            catch (SocketException Ex)
            {
                uint Status = Ex.SocketErrorCode switch
                {
                    SocketError.HostNotFound => DnsErrorRcodeNameError,
                    SocketError.NoData => DnsInfoNoRecords,
                    _ => DnsErrorRcodeServerFailure
                };
                return Failed(Name, Type, Dual, Status);
            }
            catch (ArgumentException)
            {
                return Failed(Name, Type, Dual, ErrorInvalidName);
            }
            catch (Exception Ex)
            {
                Utils.LogError($"DNS lookup of \"{Name}\" failed on the host: {Ex.Message}");
                return Failed(Name, Type, Dual, DnsErrorRcodeServerFailure);
            }
        }

        private static HostAnswer FromAddresses(string Name, ushort Type, bool Dual, string HostName, IPAddress[] Found)
        {
            List<byte[]> Addresses = new List<byte[]>(Found.Length);
            AddressFamily Family = Type == TypeA ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
            foreach (IPAddress Address in Found)
            {
                if (Address.AddressFamily == Family)
                    Addresses.Add(Address.GetAddressBytes());
            }

            if (Dual)
            {
                foreach (IPAddress Address in Found)
                {
                    if (Address.AddressFamily == AddressFamily.InterNetwork)
                        Addresses.Add(Address.MapToIPv6().GetAddressBytes());
                }
            }

            if (Addresses.Count == 0)
                return Failed(Name, Type, Dual, DnsInfoNoRecords);

            string Canonical = string.IsNullOrEmpty(HostName) || string.Equals(HostName.TrimEnd('.'), Name.TrimEnd('.'), StringComparison.OrdinalIgnoreCase)
                ? null
                : HostName.TrimEnd('.');

            return new HostAnswer { Name = Name, Type = Type, Dual = Dual, Status = 0, CanonicalName = Canonical, Addresses = Addresses };
        }

        private static HostAnswer Failed(string Name, ushort Type, bool Dual, uint Status) =>
            new HostAnswer { Name = Name, Type = Type, Dual = Dual, Status = Status };

        private readonly struct WireRecord
        {
            public readonly ushort Type;
            public readonly string Owner;
            public readonly bool NamePresent;
            public readonly byte[] Address;
            public readonly string Target;

            public WireRecord(ushort Type, string Owner, bool NamePresent, byte[] Address, string Target)
            {
                this.Type = Type;
                this.Owner = Owner;
                this.NamePresent = NamePresent;
                this.Address = Address;
                this.Target = Target;
            }
        }

        private static byte[] BuildReply(in LrpcMessage Message, ulong QueryOptions, HostAnswer Answer, uint Status)
        {
            List<WireRecord> Records = new List<WireRecord>();
            if (Answer != null && Answer.Status == 0)
            {
                string Owner = Answer.Name;
                if (Answer.CanonicalName != null)
                {
                    Records.Add(new WireRecord(TypeCname, Owner, true, null, Answer.CanonicalName));
                    Owner = Answer.CanonicalName;
                }

                for (int i = 0; i < Answer.Addresses.Count; i++)
                    Records.Add(new WireRecord(Answer.Type, Owner, i == 0, Answer.Addresses[i], null));
            }

            Ndr20Writer Writer = new Ndr20Writer(256);
            Writer.WriteUInt64(QueryOptions);

            if (Records.Count == 0)
            {
                Writer.WriteUInt32(0);
            }
            else
            {
                Writer.WriteUniqueReferent();
                for (int i = 0; i < Records.Count; i++)
                    WriteRecordFlat(ref Writer, Records[i], i + 1 < Records.Count);

                // Each record's strings follow the records chained behind it.
                for (int i = Records.Count - 1; i >= 0; i--)
                {
                    if (Records[i].NamePresent)
                        Writer.WriteConformantWideString(Records[i].Owner);
                    if (Records[i].Target != null)
                        Writer.WriteConformantWideString(Records[i].Target);
                }
            }

            Writer.WriteSystemHandle(-1);
            Writer.WriteUInt64(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(Status);
            return LrpcPacket.BuildResponse(Message, Writer.ToArray());
        }

        // DNS_RECORDW
        private static void WriteRecordFlat(ref Ndr20Writer Writer, in WireRecord Record, bool HasNext)
        {
            Writer.AlignTo(8);
            if (HasNext)
                Writer.WriteUniqueReferent();
            else
                Writer.WriteUInt32(0);

            if (Record.NamePresent)
                Writer.WriteUniqueReferent();
            else
                Writer.WriteUInt32(0);

            uint Flags = FlagsAnswerUnicode | (Record.NamePresent ? FlagNamePresent : 0);
            ushort DataLength = Record.Type switch
            {
                TypeA => DataLengthA,
                TypeAaaa => DataLengthAaaa,
                _ => DataLengthCname
            };
            if (Record.Type == TypeCname)
                Flags |= FlagNestedData;

            Writer.WriteUInt16(Record.Type);
            Writer.WriteUInt16(DataLength);
            Writer.WriteUInt32(Flags);
            Writer.WriteUInt32(RecordTtl);
            Writer.WriteUInt32(0);

            Writer.WriteUInt16(Record.Type);
            switch (Record.Type)
            {
                case TypeA:
                    Writer.AlignTo(4);
                    Writer.WriteBytes(Record.Address);
                    break;

                case TypeAaaa:
                    Writer.AlignTo(8);
                    Writer.WriteBytes(Record.Address);
                    break;

                default:
                    Writer.AlignTo(4);
                    Writer.WriteUniqueReferent();
                    break;
            }
        }

        private static void Log(BinaryEmulator Instance, string Text) =>
            Instance.TriggerEventMessage($"[DnsResolver] {Text}", LogFlags.General);
    }
}
