using System;
using System.Collections.Generic;
using System.Text;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Ports
{
    public static class CsrssPortHandler
    {
        private const int OffPmDataLength = 0x00;
        private const int OffPmTotalLength = 0x02;
        private const int OffPmType = 0x04;
        private const int OffPmDataInfoOffset = 0x06;
        private const int PmHeaderSize = 0x28; // x64 PORT_MESSAGE size
        private const ushort LPC_REPLY = 2;

        private const int OffCsrApiNumber = PmHeaderSize + 0x08;
        private const int OffCsrReturnValue = PmHeaderSize + 0x0C;
        private const int OffCsrDataStart = PmHeaderSize + 0x18;
        private const int OffClientConnectServerId = OffCsrDataStart + 0x00;
        private const int OffClientConnectConnectionInfo = OffCsrDataStart + 0x08;
        private const int OffClientConnectConnectionInfoSize = OffCsrDataStart + 0x10;
        private const int BaseSrvCreateActivationContextMessageSize = 0x1F8;
        private const int OffBaseSrvActCtxOutputPointer = OffCsrDataStart + 0xB8;
        private const int OffBaseSrvActCtxDataPointer = OffCsrDataStart + 0xC0;
        private const int MinimalActivationContextDataSize = 0x300;

        private const uint CSRSRV_INDEX = 0;
        private const uint BASESRV_INDEX = 1;
        private const uint CONSRV_INDEX = 2;
        private const uint USERSRV_INDEX = 3;

        private const byte DceRpcVersion = 5;
        private const byte DceRpcRequest = 0;
        private const byte DceRpcResponse = 2;
        private const byte DceRpcFault = 3;
        private const byte DceRpcBind = 11;
        private const byte DceRpcBindAck = 12;
        private const byte DceRpcLittleEndianFlag = 0x10;
        private const byte DceRpcFirstFrag = 0x01;
        private const byte DceRpcLastFrag = 0x02;
        private const uint DceRpcDataRepresentation = 0x00000010;

        private static readonly byte[] NdrTransferSyntax =
        {
            0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
            0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
            0x02, 0x00, 0x00, 0x00
        };

        private static readonly byte[] EventLogInterfaceSyntax =
        {
            0xDC, 0x3F, 0x27, 0x82, 0x2A, 0xE3, 0xC3, 0x18,
            0x3F, 0x78, 0x82, 0x79, 0x29, 0xDC, 0x23, 0xEA,
            0x00, 0x00, 0x00, 0x00
        };

        private static readonly HashSet<string> EventLogRpcPorts = new(StringComparer.OrdinalIgnoreCase);

        private static readonly uint[] ActivationContextSectionIds =
        {
            2u,  // ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION.
            3u,  // ACTIVATION_CONTEXT_SECTION_WINDOW_CLASS_REDIRECTION.
            4u,  // ACTIVATION_CONTEXT_SECTION_COM_SERVER_REDIRECTION.
            5u,  // ACTIVATION_CONTEXT_SECTION_COM_INTERFACE_REDIRECTION.
            6u,  // ACTIVATION_CONTEXT_SECTION_COM_TYPE_LIBRARY_REDIRECTION.
            7u,  // ACTIVATION_CONTEXT_SECTION_COM_PROGID_REDIRECTION.
            9u,  // ACTIVATION_CONTEXT_SECTION_CLR_SURROGATES.
            10u, // ACTIVATION_CONTEXT_SECTION_APPLICATION_SETTINGS.
            12u  // ACTIVATION_CONTEXT_SECTION_WINRT_ACTIVATABLE_CLASSES.
        };

        private static ulong _fakeServerInfo = 0;
        private static ulong _fakeActivationContextData = 0;
        private static uint _tempFileCounter = 1;
        private static readonly Dictionary<Guid, string> EventLogContexts = new();

        private enum EventLogOpnum : ushort
        {
            ElfrCloseEL = 2,
            ElfrDeregisterEventSource = 3,
            ElfrOpenELW = 7,
            ElfrRegisterEventSourceW = 8,
            ElfrReportEventW = 11,
            ElfrOpenELA = 14,
            ElfrRegisterEventSourceA = 15,
            ElfrReportEventA = 18,
            ElfrReportEventExW = 25,
            ElfrReportEventExA = 26
        }

        public static NTSTATUS Handle(WinPort Port, byte[] SendData, out byte[] ReplyData, BinaryEmulator Instance)
        {
            if (SendData == null || SendData.Length < PmHeaderSize)
            {
                ReplyData = BuildMinimalReply();
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (IsCsrApiPort(Port?.Name))
            {
                ReplyData = HandleCsrPort(Port, SendData, Instance);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ReplyData = HandleGenericRpcPort(Port, SendData, Instance);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static byte[] HandleCsrPort(WinPort Port, byte[] SendData, BinaryEmulator Instance)
        {
            byte[] Reply = (byte[])SendData.Clone();
            PreparePortReply(Reply);

            if (Reply.Length < OffCsrApiNumber + 4)
                return Reply;

            uint ApiNumber = ReadU32(Reply, OffCsrApiNumber);
            uint DllIndex = ApiNumber >> 16;
            uint ApiIndex = ApiNumber & 0xFFFF;

            if (ApiNumber != 0)
            {
                Instance.TriggerEventMessage($"CsrssPortHandler: Port=\"{Port?.Name}\", Api=0x{ApiNumber:X8}, Dll={DllIndex}, Index={ApiIndex}.", LogFlags.Syscall);
            }

            if (ApiIndex == 0)
            {
                switch (DllIndex)
                {
                    case CSRSRV_INDEX:
                        HandleCsrSrvConnect(Reply, Instance);
                        break;
                    case BASESRV_INDEX:
                        HandleBaseSrvConnect(Reply, Instance);
                        break;
                    case CONSRV_INDEX:
                        HandleConSrvConnect(Reply, Instance);
                        break;
                    case USERSRV_INDEX:
                        HandleUserSrvConnect(Reply, Instance);
                        break;
                    default:
                        WriteCsrStatus(Reply, NTSTATUS.STATUS_SUCCESS);
                        break;
                }

                return Reply;
            }

            switch (DllIndex)
            {
                case CSRSRV_INDEX:
                    HandleCsrSrvApi(Reply, ApiIndex, Instance);
                    break;
                case BASESRV_INDEX:
                    HandleBaseSrvApi(Reply, ApiIndex, Instance);
                    break;
                case CONSRV_INDEX:
                    HandleConSrvApi(Reply, ApiIndex, Instance);
                    break;
                case USERSRV_INDEX:
                    HandleUserSrvApi(Reply, ApiIndex, Instance);
                    break;
                default:
                    WriteCsrStatus(Reply, NTSTATUS.STATUS_SUCCESS);
                    break;
            }

            return Reply;
        }

        private static byte[] HandleGenericRpcPort(WinPort Port, byte[] SendData, BinaryEmulator Instance)
        {
            if (TryBuildDceRpcReply(Port, SendData, out byte[] RpcReply, Instance))
            {
                Instance.TriggerEventMessage($"GenericRpcPort: Port=\"{Port?.Name}\", ReplyLength=0x{RpcReply.Length:X}.", LogFlags.Syscall);
                return RpcReply;
            }

            byte[] Reply = (byte[])SendData.Clone();
            PreparePortReply(Reply);
            return Reply;
        }

        private static void HandleCsrSrvConnect(byte[] Reply, BinaryEmulator Instance)
        {
            if (Reply.Length < OffCsrDataStart + 0x18)
                return;

            TryReadClientConnectData(Reply, out uint ServerId, out ulong ConnectionInfo, out uint ConnectionInfoSize);

            ulong Base = GetSharedSectionBase(Instance);
            if (Base == 0)
                return;

            EnsureSharedSectionInitialized(Instance, Base);

            Span<byte> Data = stackalloc byte[0x18];
            WriteU64(Data, 0x00, Base);
            WriteU64(Data, 0x08, Base + 0x1000);
            WriteU32(Data, 0x10, 4u);

            WriteU64(Reply, OffCsrDataStart + 0x00, Base);
            WriteU64(Reply, OffCsrDataStart + 0x08, Base + 0x1000);
            WriteU32(Reply, OffCsrDataStart + 0x10, 4u);
            TryWriteClientConnectData(Reply, Instance, Data, ServerId, ConnectionInfo, ConnectionInfoSize);
        }

        private static void HandleBaseSrvConnect(byte[] Reply, BinaryEmulator Instance)
        {
            if (Reply.Length < OffCsrDataStart + 0x10)
                return;

            TryReadClientConnectData(Reply, out uint ServerId, out ulong ConnectionInfo, out uint ConnectionInfoSize);

            Span<byte> Data = stackalloc byte[0x10];
            WriteU64(Reply, OffCsrDataStart + 0x00, 0UL);
            WriteU64(Reply, OffCsrDataStart + 0x08, 0UL);
            TryWriteClientConnectData(Reply, Instance, Data, ServerId, ConnectionInfo, ConnectionInfoSize);
        }

        private static void HandleConSrvConnect(byte[] Reply, BinaryEmulator Instance)
        {
            if (Reply.Length < OffCsrDataStart + 0x20)
                return;

            TryReadClientConnectData(Reply, out uint ServerId, out ulong ConnectionInfo, out uint ConnectionInfoSize);

            Span<byte> Data = stackalloc byte[0x20];
            WriteU64(Data, 0x00, (ulong)(Instance.WinHelper.ConsoleHandle?.Handle ?? 0));
            WriteU64(Data, 0x08, (ulong)(Instance.WinHelper.ConsoleHandle?.Handle ?? 0));
            WriteU32(Data, 0x10, 65001u);
            WriteU32(Data, 0x14, 65001u);

            WriteU64(Reply, OffCsrDataStart + 0x00, (ulong)(Instance.WinHelper.ConsoleHandle?.Handle ?? 0));
            WriteU64(Reply, OffCsrDataStart + 0x08, (ulong)(Instance.WinHelper.ConsoleHandle?.Handle ?? 0));
            WriteU32(Reply, OffCsrDataStart + 0x10, 65001u);
            WriteU32(Reply, OffCsrDataStart + 0x14, 65001u);
            TryWriteClientConnectData(Reply, Instance, Data, ServerId, ConnectionInfo, ConnectionInfoSize);
        }

        private static void HandleUserSrvConnect(byte[] Reply, BinaryEmulator Instance)
        {
            if (Reply.Length < OffCsrDataStart + 8)
                return;

            TryReadClientConnectData(Reply, out uint ServerId, out ulong ConnectionInfo, out uint ConnectionInfoSize);

            if (!Instance.WinHelper.EnsureUserSharedInfo(out ulong psi, out ulong aheList, out uint handleEntrySize))
                return;

            const int UserConnectSharedInfoOffset = 0x08;

            Span<byte> Data = stackalloc byte[0x28];
            Data.Clear();
            WriteU64(Data, UserConnectSharedInfoOffset + 0x00, psi);
            WriteU64(Data, UserConnectSharedInfoOffset + 0x08, aheList);
            WriteU32(Data, UserConnectSharedInfoOffset + 0x10, handleEntrySize);
            WriteU32(Data, UserConnectSharedInfoOffset + 0x14, 0u);
            WriteU64(Data, UserConnectSharedInfoOffset + 0x18, 0UL);

            WriteU64(Reply, OffCsrDataStart + 0x000, psi);
            WriteU64(Reply, OffCsrDataStart + 0x008, aheList);
            WriteU32(Reply, OffCsrDataStart + 0x010, handleEntrySize);
            WriteU32(Reply, OffCsrDataStart + 0x014, 0u);
            WriteU64(Reply, OffCsrDataStart + 0x018, 0UL);

            uint UserConnectWriteSize = Math.Max(ConnectionInfoSize, (uint)Data.Length);
            TryWriteClientConnectData(Reply, Instance, Data, ServerId, ConnectionInfo, UserConnectWriteSize);
            Instance.WinHelper.InitializeUser32SharedInfoGlobals(psi, aheList, handleEntrySize);
        }

        private static void HandleCsrSrvApi(byte[] Reply, uint ApiIndex, BinaryEmulator Instance)
        {
            WriteCsrStatus(Reply, NTSTATUS.STATUS_SUCCESS);

            switch (ApiIndex)
            {
                case 1: // CsrIdentifyAlertableThread-style notification.
                    ZeroCsrData(Reply, 0x10);
                    break;
                case 2: // CsrSetPriorityClass-style request.
                case 3:
                    break;
                default:
                    break;
            }
        }

        private static void HandleBaseSrvApi(byte[] Reply, uint ApiIndex, BinaryEmulator Instance)
        {
            WriteCsrStatus(Reply, NTSTATUS.STATUS_SUCCESS);

            switch (ApiIndex)
            {
                case 2: // BaseSrvGetTempFile.
                    WriteU32(Reply, OffCsrDataStart + 0x00, _tempFileCounter++);
                    break;
                case 12: // BaseSrvSetProcessShutdownParam.
                    StoreShutdownParameters(Reply, Instance);
                    break;
                case 13: // BaseSrvGetProcessShutdownParam.
                    WriteShutdownParameters(Reply, Instance);
                    break;
                case 14: // BaseSrvNlsSetUserInfo.
                case 15: // BaseSrvNlsSetMultipleUserInfo.
                case 17: // BaseSrvSetVDMCurDirs.
                case 18: // BaseSrvGetVDMCurDirs.
                case 19: // BaseSrvBatNotification.
                case 20: // BaseSrvRegisterWowExec.
                case 21: // BaseSrvSoundSentryNotification.
                case 22: // BaseSrvRefreshIniFileMapping.
                case 24: // BaseSrvSetTermsrvAppInstallMode.
                case 25: // BaseSrvNlsUpdateCacheCount.
                case 26: // BaseSrvSetTermsrvClientTimeZone.
                case 29: // BaseSrvRegisterThread.
                    break;
                case 30: // BaseSrvCreateActivationContext.
                    if (!HandleBaseSrvCreateActivationContext(Reply, Instance))
                        TryZeroCapturedBuffer(Reply, Instance, 0x00, 0x08);
                    break;
                default:
                    break;
            }
        }

        private static void HandleConSrvApi(byte[] Reply, uint ApiIndex, BinaryEmulator Instance)
        {
            WriteCsrStatus(Reply, NTSTATUS.STATUS_SUCCESS);

            switch (ApiIndex)
            {
                case 0:
                    HandleConSrvConnect(Reply, Instance);
                    break;
                default:
                    NormalizeConsoleReply(Reply, Instance);
                    break;
            }
        }

        private static void HandleUserSrvApi(byte[] Reply, uint ApiIndex, BinaryEmulator Instance)
        {
            WriteCsrStatus(Reply, NTSTATUS.STATUS_SUCCESS);

            switch (ApiIndex)
            {
                case 4: // SrvActivateDebugger.
                case 5: // SrvGetThreadConsoleDesktop.
                case 8: // SrvCreateSystemThreads.
                    ZeroCsrData(Reply, 0x20);
                    break;
                default:
                    break;
            }
        }

        private static void StoreShutdownParameters(byte[] Reply, BinaryEmulator Instance)
        {
            if (Reply.Length < OffCsrDataStart + 8 || Instance.WinHelper.WinProcesses.FirstOrDefault(Proc => Proc.PID == Instance.WinHelper.PID) == null)
                return;

            Instance.WinHelper.WinProcesses.FirstOrDefault(Proc => Proc.PID == Instance.WinHelper.PID).ShutdownLevel = ReadU32(Reply, OffCsrDataStart + 0x00);
            Instance.WinHelper.WinProcesses.FirstOrDefault(Proc => Proc.PID == Instance.WinHelper.PID).ShutdownFlags = ReadU32(Reply, OffCsrDataStart + 0x04);
        }

        private static void WriteShutdownParameters(byte[] Reply, BinaryEmulator Instance)
        {
            if (Reply.Length < OffCsrDataStart + 8)
                return;

            uint Level = Instance.WinHelper.WinProcesses.FirstOrDefault(Proc => Proc.PID == Instance.WinHelper.PID)?.ShutdownLevel ?? 0x280;
            if (Level == 0)
                Level = 0x280;

            WriteU32(Reply, OffCsrDataStart + 0x00, Level);
            WriteU32(Reply, OffCsrDataStart + 0x04, Instance.WinHelper.WinProcesses.FirstOrDefault(Proc => Proc.PID == Instance.WinHelper.PID)?.ShutdownFlags ?? 0);
        }

        private static bool HandleBaseSrvCreateActivationContext(byte[] Reply, BinaryEmulator Instance)
        {
            if (Reply.Length < OffCsrDataStart + BaseSrvCreateActivationContextMessageSize)
                return false;

            ulong OutputPointer = ReadU64(Reply, OffBaseSrvActCtxOutputPointer);
            if (OutputPointer == 0 || !Instance.IsRegionMapped(OutputPointer, 8))
                return false;

            ulong ActivationContextData = GetOrAllocActivationContextData(Instance);
            if (ActivationContextData == 0)
                return false;

            Instance._emulator.WriteMemory(OutputPointer, ActivationContextData, 8);
            WriteU64(Reply, OffBaseSrvActCtxDataPointer, ActivationContextData);
            Instance.TriggerEventMessage($"CsrssPortHandler: BaseSrvCreateActivationContext -> Data=0x{ActivationContextData:X}, Out=0x{OutputPointer:X}.", LogFlags.Syscall);
            return true;
        }

        private static void NormalizeConsoleReply(byte[] Reply, BinaryEmulator Instance)
        {
            if (Reply.Length < OffCsrDataStart + 0x18)
                return;

            ulong First = ReadU64(Reply, OffCsrDataStart + 0x00);
            if (First == 0 || First == 1 || First == 2 || First == 3 || First == 4)
                WriteU64(Reply, OffCsrDataStart + 0x00, (ulong)(Instance.WinHelper.ConsoleHandle?.Handle ?? 0));

            WriteU32(Reply, OffCsrDataStart + 0x08, 65001u);
            WriteU32(Reply, OffCsrDataStart + 0x0C, 65001u);
            WriteU32(Reply, OffCsrDataStart + 0x10, 0x0003u);
        }

        private static bool TryReadClientConnectData(byte[] Reply, out uint ServerId, out ulong ConnectionInfo, out uint ConnectionInfoSize)
        {
            ServerId = 0;
            ConnectionInfo = 0;
            ConnectionInfoSize = 0;

            if (Reply.Length < OffClientConnectConnectionInfoSize + 4)
                return false;

            ServerId = ReadU32(Reply, OffClientConnectServerId);
            ConnectionInfo = ReadU64(Reply, OffClientConnectConnectionInfo);
            ConnectionInfoSize = ReadU32(Reply, OffClientConnectConnectionInfoSize);
            return true;
        }

        private static void TryWriteClientConnectData(byte[] Reply, BinaryEmulator Instance, ReadOnlySpan<byte> Data, uint ServerId, ulong ConnectionInfo, uint ConnectionInfoSize)
        {
            if (ConnectionInfo == 0 || ConnectionInfoSize == 0)
                return;

            int WriteLength = (int)Math.Min(ConnectionInfoSize, (uint)Data.Length);
            if (WriteLength <= 0 || !Instance.IsRegionMapped(ConnectionInfo, (ulong)WriteLength))
                return;

            Instance._emulator.WriteMemory(ConnectionInfo, Data.Slice(0, WriteLength));
            WriteU32(Reply, OffClientConnectConnectionInfoSize, (uint)WriteLength);

            Instance.TriggerEventMessage($"CsrssPortHandler: Connected server {ServerId}, ConnectionInfo=0x{ConnectionInfo:X}, Size=0x{WriteLength:X}.", LogFlags.Syscall);
        }

        private static void TryZeroCapturedBuffer(byte[] Reply, BinaryEmulator Instance, int PointerOffset, int SizeOffset)
        {
            if (Reply.Length < OffCsrDataStart + Math.Max(PointerOffset + 8, SizeOffset + 4))
                return;

            ulong Buffer = ReadU64(Reply, OffCsrDataStart + PointerOffset);
            uint Size = ReadU32(Reply, OffCsrDataStart + SizeOffset);
            if (Buffer == 0 || Size == 0 || Size > 0x10000)
                return;

            if (!Instance.IsRegionMapped(Buffer, Size))
                return;

            Instance.WinHelper.WriteZeroMemory(Buffer, Size);
        }

        private static bool TryBuildDceRpcReply(WinPort Port, byte[] SendData, out byte[] Reply, BinaryEmulator Instance)
        {
            Reply = null;

            if (SendData.Length < PmHeaderSize + 16)
                return false;

            int RpcOffset = PmHeaderSize;
            if (SendData[RpcOffset] != DceRpcVersion)
                return false;

            byte PacketType = SendData[RpcOffset + 2];
            switch (PacketType)
            {
                case DceRpcBind:
                    if (IsEventLogBind(SendData, RpcOffset) && !string.IsNullOrEmpty(Port?.Name))
                        EventLogRpcPorts.Add(Port.Name);

                    Reply = BuildDceRpcBindAck(SendData, RpcOffset);
                    return true;
                case DceRpcRequest:
                    Reply = BuildDceRpcRequestReply(Port, SendData, RpcOffset, Instance);
                    return true;
                default:
                    Reply = BuildDceRpcFault(SendData, RpcOffset, 0x000006BBu);
                    return true;
            }
        }

        private static byte[] BuildDceRpcRequestReply(WinPort Port, byte[] SendData, int RpcOffset, BinaryEmulator Instance)
        {
            if (SendData.Length < RpcOffset + 0x18)
                return BuildDceRpcFault(SendData, RpcOffset, 0x000006BAu);

            ushort Opnum = ReadU16(SendData, RpcOffset + 0x16);
            if (!IsEventLogPort(Port) || !TryBuildEventLogStub(Opnum, out byte[] Stub))
                return BuildDceRpcFault(SendData, RpcOffset, 0x000006BAu);

            Instance.TriggerEventMessage($"EventLogRpc: Opnum=0x{Opnum:X}, StubLength=0x{Stub.Length:X}.", LogFlags.Syscall);
            return BuildDceRpcResponse(SendData, RpcOffset, Stub);
        }

        private static bool TryBuildEventLogStub(ushort Opnum, out byte[] Stub)
        {
            Stub = null;

            switch ((EventLogOpnum)Opnum)
            {
                case EventLogOpnum.ElfrOpenELW:
                case EventLogOpnum.ElfrRegisterEventSourceW:
                case EventLogOpnum.ElfrOpenELA:
                case EventLogOpnum.ElfrRegisterEventSourceA:
                    Stub = BuildEventLogOpenStub();
                    return true;
                case EventLogOpnum.ElfrCloseEL:
                case EventLogOpnum.ElfrDeregisterEventSource:
                    Stub = BuildEventLogCloseStub();
                    return true;
                case EventLogOpnum.ElfrReportEventW:
                case EventLogOpnum.ElfrReportEventA:
                    Stub = BuildEventLogReportStub(false);
                    return true;
                case EventLogOpnum.ElfrReportEventExW:
                case EventLogOpnum.ElfrReportEventExA:
                    Stub = BuildEventLogReportStub(true);
                    return true;
                default:
                    return false;
            }
        }

        private static byte[] BuildEventLogOpenStub()
        {
            byte[] Stub = new byte[0x18];
            Guid ContextId = Guid.NewGuid();
            EventLogContexts[ContextId] = "Application";
            WriteContextHandle(Stub, 0x00, ContextId);
            WriteU32(Stub, 0x14, (uint)NTSTATUS.STATUS_SUCCESS);
            return Stub;
        }

        private static byte[] BuildEventLogCloseStub()
        {
            byte[] Stub = new byte[0x18];
            WriteContextHandle(Stub, 0x00, Guid.Empty);
            WriteU32(Stub, 0x14, (uint)NTSTATUS.STATUS_SUCCESS);
            return Stub;
        }

        private static byte[] BuildEventLogReportStub(bool ExVariant)
        {
            byte[] Stub = new byte[ExVariant ? 0x08 : 0x0C];
            WriteU32(Stub, 0x00, 0);
            if (!ExVariant)
                WriteU32(Stub, 0x04, 0);
            WriteU32(Stub, ExVariant ? 0x04 : 0x08, (uint)NTSTATUS.STATUS_SUCCESS);
            return Stub;
        }

        private static byte[] BuildDceRpcResponse(byte[] SendData, int RpcOffset, byte[] Stub)
        {
            ushort RpcLength = checked((ushort)(0x18 + Stub.Length));
            byte[] Reply = new byte[PmHeaderSize + RpcLength];
            CopyPortHeader(SendData, Reply);
            PreparePortReply(Reply);

            int o = PmHeaderSize;
            Reply[o + 0x00] = DceRpcVersion;
            Reply[o + 0x01] = 0;
            Reply[o + 0x02] = DceRpcResponse;
            Reply[o + 0x03] = DceRpcFirstFrag | DceRpcLastFrag | DceRpcLittleEndianFlag;
            WriteU32(Reply, o + 0x04, DceRpcDataRepresentation);
            WriteU16(Reply, o + 0x08, RpcLength);
            WriteU16(Reply, o + 0x0A, 0);
            WriteU32(Reply, o + 0x0C, ReadU32(SendData, RpcOffset + 0x0C));
            WriteU32(Reply, o + 0x10, (uint)Stub.Length);
            WriteU16(Reply, o + 0x14, ReadU16(SendData, RpcOffset + 0x14));
            Reply[o + 0x16] = 0;
            Reply[o + 0x17] = 0;
            WriteBytes(Reply, o + 0x18, Stub);
            SetPortMessageLengths(Reply, RpcLength);
            return Reply;
        }

        private static void WriteContextHandle(byte[] b, int o, Guid ContextId)
        {
            WriteU32(b, o + 0x00, 0);
            if (o + 0x14 <= b.Length)
                ContextId.TryWriteBytes(b.AsSpan(o + 0x04, 0x10));
        }

        private static byte[] BuildDceRpcBindAck(byte[] SendData, int RpcOffset)
        {
            const ushort RpcLength = 0x38;
            byte[] Reply = new byte[PmHeaderSize + RpcLength];
            CopyPortHeader(SendData, Reply);
            PreparePortReply(Reply);

            int o = PmHeaderSize;
            Reply[o + 0x00] = DceRpcVersion;
            Reply[o + 0x01] = 0;
            Reply[o + 0x02] = DceRpcBindAck;
            Reply[o + 0x03] = DceRpcFirstFrag | DceRpcLastFrag;
            WriteU32(Reply, o + 0x04, DceRpcDataRepresentation);
            WriteU16(Reply, o + 0x08, RpcLength);
            WriteU16(Reply, o + 0x0A, 0);
            WriteU32(Reply, o + 0x0C, ReadU32(SendData, RpcOffset + 0x0C));
            WriteU16(Reply, o + 0x10, 0x16D0);
            WriteU16(Reply, o + 0x12, 0x16D0);
            WriteU32(Reply, o + 0x14, 1);
            WriteU16(Reply, o + 0x18, 0);
            WriteU16(Reply, o + 0x1A, 0);
            Reply[o + 0x1C] = 1;
            Reply[o + 0x1D] = 0;
            WriteU16(Reply, o + 0x1E, 0);
            WriteU16(Reply, o + 0x20, 0);
            WriteU16(Reply, o + 0x22, 0);
            WriteBytes(Reply, o + 0x24, SelectAcceptedTransferSyntax(SendData, RpcOffset));
            SetPortMessageLengths(Reply, RpcLength);
            return Reply;
        }

        private static bool IsEventLogPort(WinPort Port)
        {
            if (string.IsNullOrEmpty(Port?.Name))
                return false;

            return EventLogRpcPorts.Contains(Port.Name) ||
                   Port.Name.IndexOf("eventlog", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool IsEventLogBind(byte[] SendData, int RpcOffset)
        {
            const int ContextListOffset = 0x18;
            const int ContextElementHeaderSize = 0x04;
            const int AbstractSyntaxSize = 0x14;
            const int TransferSyntaxSize = 0x14;

            int ContextList = RpcOffset + ContextListOffset;
            if (ContextList + 4 > SendData.Length)
                return false;

            int ContextCount = SendData[ContextList];
            int Element = ContextList + 4;

            for (int i = 0; i < ContextCount; i++)
            {
                if (Element + ContextElementHeaderSize + AbstractSyntaxSize > SendData.Length)
                    return false;

                if (BytesAtEqual(SendData, Element + ContextElementHeaderSize, EventLogInterfaceSyntax))
                    return true;

                int TransferSyntaxCount = SendData[Element + 2];
                Element += ContextElementHeaderSize + AbstractSyntaxSize + TransferSyntaxCount * TransferSyntaxSize;
            }

            return false;
        }

        private static ReadOnlySpan<byte> SelectAcceptedTransferSyntax(byte[] SendData, int RpcOffset)
        {
            const int ContextListOffset = 0x18;
            const int ContextElementHeaderSize = 0x04;
            const int AbstractSyntaxSize = 0x14;
            const int TransferSyntaxSize = 0x14;

            int ContextList = RpcOffset + ContextListOffset;
            if (ContextList + 4 > SendData.Length)
                return NdrTransferSyntax;

            int ContextCount = SendData[ContextList];
            int Element = ContextList + 4;
            int FirstOfferedSyntax = -1;

            for (int i = 0; i < ContextCount; i++)
            {
                if (Element + ContextElementHeaderSize + AbstractSyntaxSize > SendData.Length)
                    break;

                int TransferSyntaxCount = SendData[Element + 2];
                int TransferSyntax = Element + ContextElementHeaderSize + AbstractSyntaxSize;
                for (int j = 0; j < TransferSyntaxCount; j++)
                {
                    if (TransferSyntax + TransferSyntaxSize > SendData.Length)
                        break;

                    ReadOnlySpan<byte> Syntax = SendData.AsSpan(TransferSyntax, TransferSyntaxSize);

                    if (FirstOfferedSyntax < 0)
                        FirstOfferedSyntax = TransferSyntax;

                    if (Syntax.SequenceEqual(NdrTransferSyntax))
                        return Syntax;

                    TransferSyntax += TransferSyntaxSize;
                }

                Element = TransferSyntax;
            }

            return FirstOfferedSyntax >= 0 ? SendData.AsSpan(FirstOfferedSyntax, TransferSyntaxSize) : NdrTransferSyntax;
        }

        private static bool BytesAtEqual(byte[] Data, int Offset, byte[] Expected)
        {
            if (Data == null || Expected == null || Offset < 0 || Offset + Expected.Length > Data.Length)
                return false;

            return Data.AsSpan(Offset, Expected.Length).SequenceEqual(Expected);
        }

        private static byte[] BuildDceRpcFault(byte[] SendData, int RpcOffset, uint Status)
        {
            const ushort RpcLength = 0x20;
            byte[] Reply = new byte[PmHeaderSize + RpcLength];
            CopyPortHeader(SendData, Reply);
            PreparePortReply(Reply);

            int o = PmHeaderSize;
            Reply[o + 0x00] = DceRpcVersion;
            Reply[o + 0x01] = 0;
            Reply[o + 0x02] = DceRpcFault;
            Reply[o + 0x03] = DceRpcFirstFrag | DceRpcLastFrag | DceRpcLittleEndianFlag;
            WriteU32(Reply, o + 0x04, DceRpcDataRepresentation);
            WriteU16(Reply, o + 0x08, RpcLength);
            WriteU16(Reply, o + 0x0A, 0);
            WriteU32(Reply, o + 0x0C, ReadU32(SendData, RpcOffset + 0x0C));
            WriteU32(Reply, o + 0x10, 0);
            WriteU16(Reply, o + 0x14, 0);
            WriteU16(Reply, o + 0x16, 0);
            WriteU32(Reply, o + 0x18, Status);
            WriteU32(Reply, o + 0x1C, 0);
            SetPortMessageLengths(Reply, RpcLength);
            return Reply;
        }

        private static ulong GetOrAllocServerInfo(BinaryEmulator Instance)
        {
            if (_fakeServerInfo != 0 && Instance.IsRegionMapped(_fakeServerInfo, 1))
                return _fakeServerInfo;

            const ulong Size = 0x2000;
            ulong addr = Instance.MapUniqueAddress(Size, MemoryProtection.ReadWrite);
            if (addr == 0) return 0;

            Instance.WinHelper.WriteZeroMemory(addr, (uint)Size);

            Instance._emulator.WriteMemory(addr + 0x04, (uint)0x200, 4); // cHandleEntries, prevents divide-by-zero

            _fakeServerInfo = addr;
            return addr;
        }

        private static ulong GetOrAllocActivationContextData(BinaryEmulator Instance)
        {
            if (_fakeActivationContextData != 0 && Instance.IsRegionMapped(_fakeActivationContextData, MinimalActivationContextDataSize))
                return _fakeActivationContextData;

            const ulong Size = 0x1000;
            ulong Address = Instance.MapUniqueAddress(Size, MemoryProtection.ReadWrite);
            if (Address == 0)
                return 0;

            Instance.WinHelper.WriteZeroMemory(Address, (uint)Size);
            Span<byte> Data = Instance.WinHelper.Shared.GetSpan(MinimalActivationContextDataSize);
            Data.Clear();
            BuildMinimalActivationContextData(Data);
            Instance._emulator.WriteMemory(Address, Data.Slice(0, MinimalActivationContextDataSize));
            _fakeActivationContextData = Address;
            return Address;
        }

        private static void BuildMinimalActivationContextData(Span<byte> Data)
        {
            const uint ActCtxMagic = 0x78746341u;
            const uint StringSectionMagic = 0x64487353u;
            const uint GuidSectionMagic = 0x64487347u;
            const uint TocOffset = 0x20u;
            const uint TocEntriesOffset = 0x30u;
            const uint AssemblyRosterOffset = 0xC0u;
            const uint StringSectionLength = 0x2Cu;
            const uint GuidSectionLength = 0x28u;

            WriteU32(Data, 0x00, ActCtxMagic);
            WriteU32(Data, 0x04, 0x20u);
            WriteU32(Data, 0x08, 1u);
            WriteU32(Data, 0x0C, (uint)Data.Length);
            WriteU32(Data, 0x10, TocOffset);
            WriteU32(Data, 0x18, AssemblyRosterOffset);

            WriteU32(Data, (int)TocOffset + 0x00, 0x10u);
            WriteU32(Data, (int)TocOffset + 0x04, (uint)ActivationContextSectionIds.Length);
            WriteU32(Data, (int)TocOffset + 0x08, TocEntriesOffset);

            uint SectionOffset = 0xD8u;
            for (int i = 0; i < ActivationContextSectionIds.Length; i++)
            {
                uint SectionId = ActivationContextSectionIds[i];
                bool GuidSection = SectionId == 4u || SectionId == 5u || SectionId == 6u || SectionId == 9u;
                uint SectionLength = GuidSection ? GuidSectionLength : StringSectionLength;
                int TocEntry = (int)(TocEntriesOffset + (uint)(i * 0x10));

                WriteU32(Data, TocEntry + 0x00, SectionId);
                WriteU32(Data, TocEntry + 0x04, SectionOffset);
                WriteU32(Data, TocEntry + 0x08, SectionLength);

                WriteU32(Data, (int)SectionOffset, GuidSection ? GuidSectionMagic : StringSectionMagic);
                WriteU32(Data, (int)SectionOffset + 0x14, 0u);

                SectionOffset += (SectionLength + 3u) & ~3u;
            }

            WriteU32(Data, (int)AssemblyRosterOffset + 0x00, 0x14u);
            WriteU32(Data, (int)AssemblyRosterOffset + 0x08, 1u);

        }

        private static ulong GetSharedSectionBase(BinaryEmulator Instance)
        {
            foreach (WinSection s in Instance.WinHelper.WinSections)
            {
                if (s == null) continue;
                if (string.Equals(s.Name, "\\Windows\\SharedSection", StringComparison.OrdinalIgnoreCase) || (!string.IsNullOrEmpty(s.Name) && s.Name.EndsWith("\\Windows\\SharedSection", StringComparison.OrdinalIgnoreCase)))
                    return s.BackingAddress;
            }
            return 0;
        }

        internal static void EnsureSharedSectionInitialized(BinaryEmulator Instance, ulong Base)
        {
            foreach (WinSection s in Instance.WinHelper.WinSections)
            {
                if (s == null || s.BackingAddress != Base) continue;
                bool ok = string.Equals(s.Name, "\\Windows\\SharedSection", StringComparison.OrdinalIgnoreCase) || (!string.IsNullOrEmpty(s.Name) && s.Name.EndsWith("\\Windows\\SharedSection", StringComparison.OrdinalIgnoreCase));
                if (!ok) continue;

                if (s.Initialized)
                    return;

                ulong Static = Base + 0x1000;
                Instance._emulator.WriteMemory(Base + 0x08, 0x10UL, 8);
                Instance.WinHelper.WriteZeroMemory(Static, 0xC00);

                WriteUStr(Instance, Static + 0x000, "C:\\Windows");
                WriteUStr(Instance, Static + 0x010, "C:\\Windows\\System32");
                WriteUStr(Instance, Static + 0x020, "\\Sessions\\1\\BaseNamedObjects");
                WriteUStr(Instance, Static + 0x960, "C:\\Windows\\SysWOW64");
                WriteUStr(Instance, Static + 0xB40, "\\AppContainerNamedObjects");
                WriteUStr(Instance, Static + 0xB58, "\\Sessions\\1\\Windows\\WindowStations");

                ulong ReadOnlyStaticServerData = Base + 0x3000;
                Instance.WinHelper.WriteZeroMemory(ReadOnlyStaticServerData, 0x400);
                WindowsVersionInfo.WriteSharedDataVersionInformation(Instance, ReadOnlyStaticServerData);
                const string WindowsDirectory = "C:\\Windows";
                int WindowsDirectoryByteCount = Encoding.Unicode.GetByteCount(WindowsDirectory) + 2;
                Span<byte> WindowsDirectoryBytes = Instance.WinHelper.Shared.GetSpan((uint)WindowsDirectoryByteCount);
                Encoding.Unicode.GetBytes(WindowsDirectory.AsSpan(), WindowsDirectoryBytes);
                WindowsDirectoryBytes[WindowsDirectoryByteCount - 2] = 0;
                WindowsDirectoryBytes[WindowsDirectoryByteCount - 1] = 0;
                Instance._emulator.WriteMemory(ReadOnlyStaticServerData + 0x1E, WindowsDirectoryBytes.Slice(0, WindowsDirectoryByteCount));

                Instance._emulator.WriteMemory(Static + 0x959, (byte)1, 1);
                Instance._emulator.WriteMemory(Static + 0x9E8, Static, 8);
                Instance._emulator.WriteMemory(Static + 0xB50, Static, 8);

                s.Initialized = true;
                return;
            }
        }

        private static bool IsCsrApiPort(string Name)
        {
            return string.Equals(Name, "\\Windows\\ApiPort", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(Name, "\\Windows\\SbApiPort", StringComparison.OrdinalIgnoreCase);
        }

        private static void WriteUStr(BinaryEmulator Instance, ulong addr, string val)
        {
            int ByteCount = Encoding.Unicode.GetByteCount(val) + 2;
            Span<byte> Encoded = Instance.WinHelper.Shared.GetSpan((uint)ByteCount);
            Encoding.Unicode.GetBytes(val.AsSpan(), Encoded);
            Encoded[ByteCount - 2] = 0;
            Encoded[ByteCount - 1] = 0;

            ulong buf = Instance.MapUniqueAddress((ulong)ByteCount, MemoryProtection.ReadWrite);
            if (buf == 0) return;

            Instance._emulator.WriteMemory(buf, Encoded.Slice(0, ByteCount));
            Instance._emulator.WriteMemory(addr + 0, (ushort)(ByteCount - 2), 2);
            Instance._emulator.WriteMemory(addr + 2, (ushort)ByteCount, 2);
            Instance._emulator.WriteMemory(addr + 4, 0u, 4);
            Instance._emulator.WriteMemory(addr + 8, buf, 8);
        }

        private static void PreparePortReply(byte[] Reply)
        {
            WriteU16(Reply, OffPmType, LPC_REPLY);
            WriteU16(Reply, OffPmDataInfoOffset, 0);
        }

        private static void CopyPortHeader(byte[] SendData, byte[] Reply)
        {
            int Length = Math.Min(PmHeaderSize, Math.Min(SendData.Length, Reply.Length));
            Buffer.BlockCopy(SendData, 0, Reply, 0, Length);
        }

        private static void SetPortMessageLengths(byte[] Reply, ushort DataLength)
        {
            WriteU16(Reply, OffPmDataLength, DataLength);
            WriteU16(Reply, OffPmTotalLength, (ushort)(PmHeaderSize + DataLength));
        }

        private static void WriteCsrStatus(byte[] Reply, NTSTATUS Status)
        {
            WriteU32(Reply, OffCsrReturnValue, (uint)Status);
        }

        private static void ZeroCsrData(byte[] Reply, int Length)
        {
            if (Length <= 0 || Reply.Length <= OffCsrDataStart)
                return;

            int Count = Math.Min(Length, Reply.Length - OffCsrDataStart);
            Array.Clear(Reply, OffCsrDataStart, Count);
        }

        private static byte[] BuildMinimalReply()
        {
            byte[] b = new byte[PmHeaderSize + 0x10];
            WriteU16(b, OffPmType, LPC_REPLY);
            WriteU16(b, OffPmDataLength, 0x10);
            WriteU16(b, OffPmTotalLength, (ushort)(PmHeaderSize + 0x10));
            return b;
        }


        private static void WriteU16(Span<byte> b, int o, ushort v)
        { if (o < 0 || o + 2 > b.Length) return; b[o] = (byte)v; b[o + 1] = (byte)(v >> 8); }

        private static void WriteU32(Span<byte> b, int o, uint v)
        { if (o < 0 || o + 4 > b.Length) return; for (int i = 0; i < 4; i++) b[o + i] = (byte)(v >> (i * 8)); }

        private static void WriteU64(Span<byte> b, int o, ulong v)
        { if (o < 0 || o + 8 > b.Length) return; for (int i = 0; i < 8; i++) b[o + i] = (byte)(v >> (i * 8)); }

        private static void WriteU16(byte[] b, int o, ushort v)
        { if (o < 0 || o + 2 > b.Length) return; b[o] = (byte)v; b[o + 1] = (byte)(v >> 8); }

        private static void WriteU32(byte[] b, int o, uint v)
        { if (o < 0 || o + 4 > b.Length) return; for (int i = 0; i < 4; i++) b[o + i] = (byte)(v >> (i * 8)); }

        private static void WriteU64(byte[] b, int o, ulong v)
        { if (o < 0 || o + 8 > b.Length) return; for (int i = 0; i < 8; i++) b[o + i] = (byte)(v >> (i * 8)); }

        private static void WriteBytes(byte[] b, int o, ReadOnlySpan<byte> v)
        { if (o < 0 || v.Length > b.Length - o) return; v.CopyTo(b.AsSpan(o, v.Length)); }

        private static ushort ReadU16(byte[] b, int o)
        { if (o < 0 || o + 2 > b.Length) return 0; return (ushort)(b[o] | (b[o + 1] << 8)); }

        private static uint ReadU32(byte[] b, int o)
        { if (o < 0 || o + 4 > b.Length) return 0; return (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)); }

        private static ulong ReadU64(byte[] b, int o)
        {
            if (o < 0 || o + 8 > b.Length) return 0;
            return (ulong)b[o] | ((ulong)b[o + 1] << 8) | ((ulong)b[o + 2] << 16) | ((ulong)b[o + 3] << 24) | ((ulong)b[o + 4] << 32) | ((ulong)b[o + 5] << 40) | ((ulong)b[o + 6] << 48) | ((ulong)b[o + 7] << 56);
        }
    }
}
