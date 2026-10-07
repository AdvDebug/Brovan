using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;
using Brovan.Core.Helpers;

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
        private const int OffBaseSrvCreateProcessHandle = OffCsrDataStart + 0x00;
        private const int OffBaseSrvCreateProcessSxsFlags = OffCsrDataStart + 0x38;
        private const int OffBaseSrvCreateProcessSupportedOs = OffCsrDataStart + 0xDC;
        private const int OffBaseSrvCreateProcessMaxVersionTested = OffCsrDataStart + 0xF0;

        // NT: BASE_SXS_CREATEPROCESS_MSG flags that sxssrv tests.
        private const uint SxsFromManifestPaths = 0x01;
        private const uint SxsNoActivationContext = 0x20;
        private const uint SxsFromImageFile = 0x40;
        private const int OffBaseSrvDefineDosDeviceFlags = OffCsrDataStart + 0x00;
        private const int OffBaseSrvDefineDosDeviceName = OffCsrDataStart + 0x08;
        private const int OffBaseSrvDefineDosDeviceTarget = OffCsrDataStart + 0x18;

        private const uint DddRemoveDefinition = 0x2;
        private const uint DddExactMatchOnRemove = 0x4;
        private const uint DddNoBroadcastSystem = 0x8;
        private const uint DddLuidBroadcastDrive = 0x10;
        private const int DefineDosDeviceBufferChars = 0x1000;

        private const uint CSRSRV_INDEX = 0;
        private const uint BASESRV_INDEX = 1;
        private const uint CONSRV_INDEX = 2;
        private const uint USERSRV_INDEX = 3;

        internal static readonly string SessionWindowsDirectory = WinToken.InteractiveSessionDirectory + "\\Windows";
        internal static readonly string SessionApiPortName = SessionWindowsDirectory + "\\ApiPort";

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

        public static NTSTATUS Handle(WinPort Port, byte[] SendData, PortReply Reply, BinaryEmulator Instance)
        {
            if (SendData == null || SendData.Length < PmHeaderSize)
            {
                Reply.Data = BuildMinimalReply();
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (IsCsrApiPort(Port?.Name))
            {
                Reply.Data = HandleCsrPort(Port, SendData, Instance);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (DwmApiPortHandler.TryHandle(Port?.Name, SendData, Reply, Instance))
                return NTSTATUS.STATUS_SUCCESS;

            Reply.Data = HandleGenericRpcPort(Port, SendData, Reply.Connection, Instance);
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
                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"CsrssPortHandler: Port=\"{Port?.Name}\", Api=0x{ApiNumber:X8}, Dll={DllIndex}, Index={ApiIndex}.", LogFlags.Syscall);
            }

            if (ApiIndex == 0)
            {
                if (TryReadClientConnectData(Reply, out uint ServerId, out _, out _))
                {
                    switch (ServerId)
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

        private static byte[] HandleGenericRpcPort(WinPort Port, byte[] SendData, ulong Connection, BinaryEmulator Instance)
        {
            if (TryBuildDceRpcReply(Port, SendData, out byte[] RpcReply, Instance))
            {
                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"GenericRpcPort: Port=\"{Port?.Name}\", ReplyLength=0x{RpcReply.Length:X}.", LogFlags.Syscall);
                return RpcReply;
            }

            if (LrpcPacket.TryParse(SendData, out LrpcMessage Message))
            {
                if (RpcssPortHandler.TryHandle(Port?.Name, Connection, Message, Instance.WinHelper.PID, out byte[] RpcssReply))
                    return RpcssReply;

                if (Message.Type == LrpcMessageType.Bind)
                    return LrpcPacket.BuildBindAccept(Message, out _);

                if (Message.Type == LrpcMessageType.Request)
                {
                    if (ScmPortHandler.TryHandle(Port?.Name, Message.ProcNumber, Message.StubData, out byte[] ScmReply))
                        return LrpcPacket.BuildResponse(Message, ScmReply);

                    if (LsaLookupPortHandler.TryHandle(Port?.Name, Message.ProcNumber, Message.StubData, Instance, out byte[] LsaReply))
                        return LrpcPacket.BuildResponse(Message, LsaReply);

                    if ((Instance.Settings.Flags & LogFlags.General) != 0)
                        Instance.TriggerEventMessage($"[!] No server for proc {Message.ProcNumber} on \"{Port?.Name}\"; faulting.", LogFlags.General);

                    return LrpcPacket.BuildFault(Message, RpcSProcnumOutOfRange);
                }
            }

            byte[] Reply = (byte[])SendData.Clone();
            PreparePortReply(Reply);
            return Reply;
        }

        private const uint RpcSProcnumOutOfRange = 1745;

        private static void HandleCsrSrvConnect(byte[] Reply, BinaryEmulator Instance)
        {
            if (Reply.Length < OffCsrDataStart + 0x18)
                return;

            TryReadClientConnectData(Reply, out uint ServerId, out ulong ConnectionInfo, out uint ConnectionInfoSize);

            WinSection Section = NtMapViewOfSection.FindSharedSection(Instance);
            if (Section == null)
                return;

            NtMapViewOfSection.EnsureSharedSectionInitialized(Instance, Section);
            ulong Base = Section.BackingAddress;

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

            Span<byte> Data = stackalloc byte[UserConnectTotalSize];
            if (!TryBuildUserConnect(Instance, ConnectionInfo, ConnectionInfoSize, Data))
                return;

            uint UserConnectWriteSize = Math.Max(ConnectionInfoSize, (uint)Data.Length);
            TryWriteClientConnectData(Reply, Instance, Data, ServerId, ConnectionInfo, UserConnectWriteSize);
        }

        private const int UserConnectHeaderSize = 0x08;
        private const int UserConnectSharedInfoSize = 0x238;
        public const int UserConnectTotalSize = UserConnectHeaderSize + UserConnectSharedInfoSize;

        /// <summary>
        /// Fills a USERCONNECT reply for the user server
        /// </summary>
        public static bool TryBuildUserConnect(BinaryEmulator Instance, ulong ConnectionInfo, uint ConnectionInfoSize, Span<byte> Data)
        {
            if (Data.Length < UserConnectTotalSize)
                return false;

            if (!Instance.WinHelper.EnsureUserSharedInfo(out ulong psi, out ulong aheList, out uint entrySize))
                return false;

            Instance.WinHelper.PublishDpiServerInfo();

            ulong DisplayInfo = Instance.WinHelper.EnsureUserDesktopInfo();
            if (DisplayInfo == 0)
                return false;

            if (!Instance.WinHelper.EnsureUserMessageBitmask(out ulong Bitmask)
                || !Instance.WinHelper.EnsureUserDefWindowMessageBitmask(out ulong DefWindowBitmask))
                return false;

            Data.Clear();

            if (ConnectionInfo != 0 && ConnectionInfoSize >= (uint)UserConnectHeaderSize && Instance.IsRegionMapped(ConnectionInfo, (ulong)UserConnectHeaderSize))
            {
                Span<byte> ExistingHeader = stackalloc byte[UserConnectHeaderSize];
                if (Instance.ReadMemory(ConnectionInfo, ExistingHeader, (uint)UserConnectHeaderSize))
                    ExistingHeader.CopyTo(Data);
            }

            WriteU64(Data, UserConnectHeaderSize + 0x00, psi);
            WriteU64(Data, UserConnectHeaderSize + 0x08, aheList);
            WriteU32(Data, UserConnectHeaderSize + 0x10, entrySize);
            WriteU64(Data, UserConnectHeaderSize + 0x18, DisplayInfo);

            for (int Index = 0; Index < WinSysHelper.UserSharedInfoMessageTableCount; Index++)
            {
                int Offset = UserConnectHeaderSize + WinSysHelper.UserSharedInfoMessageTableOffset(Index);
                WriteU32(Data, Offset, WinSysHelper.UserMessageBitmaskLastMessage);
                WriteU64(Data, Offset + 8, Index == WinSysHelper.UserDefWindowMessageTableIndex ? DefWindowBitmask : Bitmask);
            }

            return true;
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
                case 14: // BaseSrvSetVDMCurDirs.
                case 15: // BaseSrvGetVDMCurDirs.
                case 17: // BaseSrvRegisterWowExec.
                case 18: // BaseSrvSoundSentryNotification.
                case 19: // BaseSrvRefreshIniFileMapping.
                case 21: // BaseSrvSetTermsrvAppInstallMode.
                case 22: // BaseSrvSetTermsrvClientTimeZone.
                case 24: // BaseSrvDeadEntry.
                case 25: // BaseSrvRegisterThread.
                case 26: // BaseSrvDeferredCreateProcess.
                    break;
                case 29: // BaseSrvCreateProcess2.
                    HandleBaseSrvCreateProcess2(Reply, Instance);
                    break;
                case 20: // BaseSrvDefineDosDevice.
                    WriteCsrStatus(Reply, HandleBaseSrvDefineDosDevice(Reply, Instance));
                    break;
                case 27: // BaseSrvNlsGetUserInfo.
                    WriteCsrStatus(Reply, HandleBaseSrvNlsGetUserInfo(Reply, Instance));
                    break;
                case 28: // BaseSrvNlsUpdateCacheCount.
                    Instance.WinHelper.NlsUserInfo?.UpdateCacheCount(Instance);
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

        private static NTSTATUS HandleBaseSrvNlsGetUserInfo(byte[] Reply, BinaryEmulator Instance)
        {
            BaseSrvNlsUserInfo Server = Instance.WinHelper.NlsUserInfo;
            if (Reply.Length < OffCsrDataStart + 0x0C || Server == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            ulong Buffer = ReadU64(Reply, OffCsrDataStart + 0x00);
            uint Size = ReadU32(Reply, OffCsrDataStart + 0x08);

            // NT: CsrValidateMessageBuffer.
            if (Buffer == 0 || !Instance.IsRegionMapped(Buffer, BaseSrvNlsUserInfo.Size))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Status = Server.GetUserInfo(Instance, Size);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            return Instance.WriteMemory(Buffer, Server.UserInfo) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;
        }

        private static NTSTATUS HandleBaseSrvDefineDosDevice(byte[] Reply, BinaryEmulator Instance)
        {
            if (Reply.Length < OffBaseSrvDefineDosDeviceTarget + 0x10)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!TryReadCapturedString(Reply, OffBaseSrvDefineDosDeviceName, Instance, out string DeviceName) ||
                !TryReadCapturedString(Reply, OffBaseSrvDefineDosDeviceTarget, Instance, out string TargetPath))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return DefineDosDevice(Instance, ReadU32(Reply, OffBaseSrvDefineDosDeviceFlags), DeviceName, TargetPath);
        }

        // NT: CsrValidateMessageBuffer.
        private static bool TryReadCapturedString(byte[] Reply, int Offset, BinaryEmulator Instance, out string Value)
        {
            UNICODE_STRING64 Captured = new UNICODE_STRING64
            {
                Length = ReadU16(Reply, Offset),
                MaximumLength = ReadU16(Reply, Offset + 2),
                Buffer = ReadU64(Reply, Offset + 8)
            };

            Value = string.Empty;
            if ((Captured.MaximumLength & 1) != 0 || (Captured.MaximumLength != 0 && !Instance.IsRegionMapped(Captured.Buffer, Captured.MaximumLength)))
                return false;

            return Instance.WinHelper.TryReadUnicodeString64(Captured, out Value, out _);
        }

        // basesrv BaseSrvDefineDosDevice with LUID device maps. Earlier targets stack behind the new one in the link buffer.
        internal static NTSTATUS DefineDosDevice(BinaryEmulator Instance, uint Flags, string DeviceName, string TargetPath)
        {
            bool Remove = (Flags & DddRemoveDefinition) != 0;
            bool IsDriveLetter = (Flags & DddNoBroadcastSystem) == 0 && WinSysHelper.TryGetDriveLetter(DeviceName, out _);
            if ((Flags & DddLuidBroadcastDrive) != 0 && !IsDriveLetter)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            // basesrv: \??\<name> and the targets share one 4096 character buffer.
            string LinkName = "\\??\\" + DeviceName;
            if (LinkName.Length > DefineDosDeviceBufferChars - 1)
                LinkName = LinkName.Substring(0, DefineDosDeviceBufferChars - 1);
            int Room = DefineDosDeviceBufferChars - 1 - LinkName.Length;

            WinSysHelper.DosDeviceLookup Lookup = Instance.WinHelper.LookupDosDeviceName(ref LinkName, true, out IHandleObject Found, out WinObjectDirectory Directory, out string Leaf, out NTSTATUS Status);
            if (Lookup == WinSysHelper.DosDeviceLookup.Outside)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            WinSymbolicLink Existing = null;
            if (Lookup == WinSysHelper.DosDeviceLookup.Found)
            {
                Existing = Found as WinSymbolicLink;
                if (Existing == null || Directory == null)
                    Status = NTSTATUS.STATUS_OBJECT_TYPE_MISMATCH;
                else if (!WinSysHelper.TryGrantObjectAccess(AccessMask.SymbolicLinkQuery | AccessMask.Delete, false, Directory.EntryUserAccess, out _))
                    Status = NTSTATUS.STATUS_ACCESS_DENIED;
            }

            if ((Flags & DddLuidBroadcastDrive) != 0)
                return Remove && Status == NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND ? NTSTATUS.STATUS_SUCCESS : Status;

            if (Status == NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND)
            {
                if (Remove)
                    return TargetPath.Length == 0 ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;
            }
            else if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            int TargetEnd = TargetPath.IndexOf('\0');
            string NewTarget = TargetEnd < 0 ? TargetPath : TargetPath.Substring(0, TargetEnd);
            if (NewTarget.Length + 1 >= Room)
                return NTSTATUS.STATUS_TOO_MANY_NAMES;

            int ListRoom = Room - 1 - NewTarget.Length;
            string List = string.Empty;
            if (Existing != null)
            {
                string Old = Existing.TargetBuffer;
                if (Old.Length == ListRoom)
                    return NTSTATUS.STATUS_BUFFER_OVERFLOW;
                if (Old.Length > ListRoom)
                    return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                if (Old.Length >= 2 && Old[^1] == '\0' && Old[^2] == '\0')
                    List = Old;
                else if (Old.Length == 0 || Old[^1] != '\0')
                {
                    if (Old.Length + 1 >= ListRoom)
                        return NTSTATUS.STATUS_BUFFER_OVERFLOW;
                    List = Old + "\0\0";
                }
                else
                    List = Old + "\0";
            }

            if (!WinSysHelper.TryGrantObjectAccess(AccessMask.DirectoryCreateObject, true, Directory.UserAccess, out _))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            if (Existing != null)
                Directory.Remove(Existing);

            string Buffer;
            bool Matched = false;
            if (!Remove)
                Buffer = Existing == null ? NewTarget + "\0" : NewTarget + "\0" + List;
            else
            {
                StringBuilder Kept = new StringBuilder(List.Length);
                int Position = 0;
                while (Position < List.Length && List[Position] != '\0')
                {
                    int End = List.IndexOf('\0', Position);
                    string Entry = List.Substring(Position, End - Position);
                    Position = End + 1;

                    if (!Matched && ((Flags & DddExactMatchOnRemove) != 0
                        ? string.Equals(Entry, NewTarget, StringComparison.OrdinalIgnoreCase)
                        : Entry.StartsWith(NewTarget, StringComparison.OrdinalIgnoreCase)))
                    {
                        Matched = true;
                        continue;
                    }

                    Kept.Append(Entry).Append('\0');
                }

                Buffer = Kept.Append('\0').ToString();
            }

            int TargetLength = Buffer.IndexOf('\0');
            if (TargetLength == 0)
                return NTSTATUS.STATUS_SUCCESS;

            Directory.AddLink(Leaf, Buffer.Substring(0, TargetLength), Buffer.Substring(TargetLength));
            return Remove && !Matched ? NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND : NTSTATUS.STATUS_SUCCESS;
        }

        // NT: kernel32 builds the child's SwitchBack context from the manifest compatibility in this reply.
        private static void HandleBaseSrvCreateProcess2(byte[] Reply, BinaryEmulator Instance)
        {
            if (Reply.Length < OffBaseSrvCreateProcessMaxVersionTested + 8)
                return;

            ulong ProcessHandle = ReadU64(Reply, OffBaseSrvCreateProcessHandle);
            uint SxsFlags = ReadU32(Reply, OffBaseSrvCreateProcessSxsFlags);
            if (!TryReadChildCompatibility(Instance, ProcessHandle, SxsFlags, out uint SupportedOs, out ulong MaxVersionTested))
                return;

            WriteU32(Reply, OffBaseSrvCreateProcessSupportedOs, SupportedOs);
            WriteU64(Reply, OffBaseSrvCreateProcessMaxVersionTested, MaxVersionTested);
        }

        internal static bool TryReadChildCompatibility(BinaryEmulator Instance, ulong ProcessHandle, uint SxsFlags, out uint SupportedOs, out ulong MaxVersionTested)
        {
            SupportedOs = 0;
            MaxVersionTested = 0;

            if ((SxsFlags & SxsNoActivationContext) != 0 || (SxsFlags & (SxsFromManifestPaths | SxsFromImageFile)) == 0)
                return false;

            WinProcess Process = Instance.WinHelper.HandleManager.GetObjectByHandle<WinProcess>(ProcessHandle);
            if (string.IsNullOrEmpty(Process?.HostImagePath))
                return false;

            byte[] Manifest;
            BinaryFile Image = null;
            try
            {
                Image = Instance.LoadBinary(Process.HostImagePath);
                Manifest = Win32k.Win32kDpi.ReadImageManifest(Image, Process.HostImagePath);
            }
            catch (Exception Ex) when (Ex is IOException || Ex is UnauthorizedAccessException)
            {
                Utils.LogError($"[CsrssPortHandler] Manifest of {Process.HostImagePath} not read: {Ex.Message}");
                return false;
            }
            finally
            {
                Image?.Dispose();
            }

            if (Manifest == null)
                return false;

            WinSxS.ReadCompatibility(Manifest, out SupportedOs, out MaxVersionTested);
            return true;
        }

        private static bool HandleBaseSrvCreateActivationContext(byte[] Reply, BinaryEmulator Instance)
        {
            if (Reply.Length < OffCsrDataStart + BaseSrvCreateActivationContextMessageSize)
                return false;

            ulong OutputPointer = ReadU64(Reply, OffBaseSrvActCtxOutputPointer);
            if (OutputPointer == 0 || !Instance.IsRegionMapped(OutputPointer, 8))
                return false;

            ulong ActivationContextData = AllocActivationContextData(Instance);
            if (ActivationContextData == 0)
                return false;

            Instance._emulator.WriteMemory(OutputPointer, ActivationContextData, 8);
            WriteU64(Reply, OffBaseSrvActCtxDataPointer, ActivationContextData);
            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
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

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
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

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
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
            Guid ContextId = Guid.NewGuid();
            EventLogContexts[ContextId] = "Application";
            return Ndr20Writer.BuildContextHandleReply(ContextId);
        }

        private static byte[] BuildEventLogCloseStub()
        {
            return Ndr20Writer.BuildContextHandleReply(Guid.Empty);
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

        /// <summary>
        /// Builds one ACTIVATION_CONTEXT_DATA block.
        /// </summary>
        /// <remarks>
        /// Every created context owns its own block. ntdll unmaps
        /// the block when it releases the context, and a shared one leaves the other contexts pointing at
        /// freed address space.
        /// </remarks>
        public static ulong AllocActivationContextData(BinaryEmulator Instance)
        {
            const ulong Size = 0x1000;
            ulong Address = Instance.MapUniqueAddress(Size, MemoryProtection.ReadWrite);
            if (Address == 0)
                return 0;

            Instance.WinHelper.WriteZeroMemory(Address, (uint)Size);
            Span<byte> Data = Instance.WinHelper.Shared.GetSpan(MinimalActivationContextDataSize);
            Data.Clear();
            BuildMinimalActivationContextData(Data);
            Instance._emulator.WriteMemory(Address, Data.Slice(0, MinimalActivationContextDataSize));
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

        private static bool IsCsrApiPort(string Name)
        {
            return string.Equals(Name, "\\Windows\\ApiPort", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(Name, "\\Windows\\SbApiPort", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(Name, SessionApiPortName, StringComparison.OrdinalIgnoreCase);
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

    // basesrv NLS_USER_INFO. kernelbase copies it again when the update count changes.
    internal sealed class BaseSrvNlsUserInfo
    {
        internal const uint Size = 0x67C;

        private const ulong StaticServerDataOffset = 0x178;
        private const int LogonIdOffset = 0x62C;
        private const int UserSidOffset = 0x634;
        private const int UpdateCountOffset = 0x678;
        private const int CalendarTypeOffset = 0x4D8;

        // REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET.
        private const uint ChangeFilter = 0x5;

        private const uint DbgMultiSessionSku = 0x100;
        private const uint DbgMultiUsersInSessionSku = 0x200;

        private const int MultipleQueryCount = 30;
        private const uint MultipleQueryBufferLength = 0x3AC;
        private const int PartialQueryDataLimit = 0xB6 - 12;

        private const string CommonGlobUserSettingsKey = @"\Registry\Machine\System\CurrentControlSet\Control\CommonGlobUserSettings";
        private const string ExplicitSettingsKey = "\U0001F30E\U0001F30F\U0001F30D";

        // basesrv OverrideDetails. Size is in WCHARs, 0 for a number.
        private static readonly (string Name, int Offset, int Size)[] Fields =
        {
            ("LocaleName", 0x000, 86), ("sList", 0x0AC, 5), ("sDecimal", 0x0B6, 5), ("sThousand", 0x0C0, 5),
            ("sGrouping", 0x0CA, 11), ("sNativeDigits", 0x0E0, 12), ("sMonDecimalSep", 0x0F8, 5),
            ("sMonThousandSep", 0x102, 5), ("sMonGrouping", 0x10C, 11), ("sPositiveSign", 0x122, 6),
            ("sNegativeSign", 0x12E, 6), ("sTimeFormat", 0x13A, 81), ("sShortTime", 0x1DC, 81), ("s1159", 0x27E, 16),
            ("s2359", 0x29E, 16), ("sShortDate", 0x2BE, 81), ("sYearMonth", 0x360, 81), ("sLongDate", 0x402, 81),
            ("iCountry", 0x4A4, 0), ("iMeasure", 0x4A6, 0), ("iPaperSize", 0x4A8, 0), ("iDigits", 0x4AA, 0),
            ("iLZero", 0x4AC, 0), ("iNegNumber", 0x4AE, 0), ("NumShape", 0x4B0, 0), ("iCurrDigits", 0x4B2, 0),
            ("iCurrency", 0x4B4, 0), ("iNegCurr", 0x4B6, 0), ("iFirstDayOfWeek", 0x4B8, 0),
            ("iFirstWeekOfYear", 0x4BA, 0), ("sCurrency", 0x4BC, 14), ("iCalendarType", CalendarTypeOffset, 0),
        };

        // basesrv CalendarNames.
        private static readonly string[] CalendarNames =
        {
            "", "Gregorian", "", "Japanese", "Taiwan", "Korean", "Hijri", "Thai", "Hebrew", "", "", "", "",
            "", "", "", "", "", "", "", "", "", "Persian", "UmAlQura",
        };

        private readonly byte[] Info = new byte[Size];
        private readonly ulong Address;
        private readonly string InternationalKeyPath;
        private bool CacheDirty = true;

        private BaseSrvNlsUserInfo(ulong Address, string InternationalKeyPath)
        {
            this.Address = Address;
            this.InternationalKeyPath = InternationalKeyPath;
        }

        internal ReadOnlySpan<byte> UserInfo => Info;

        private uint UpdateCount
        {
            get => BinaryPrimitives.ReadUInt32LittleEndian(Info.AsSpan(UpdateCountOffset, 4));
            set => BinaryPrimitives.WriteUInt32LittleEndian(Info.AsSpan(UpdateCountOffset, 4), value);
        }

        // basesrv BaseSrvNlsLogon and the first BaseSrvNlsUpdateRegistryCache.
        internal static void Logon(BinaryEmulator Instance, ulong StaticServerData)
        {
            ulong Address = StaticServerData + StaticServerDataOffset;
            uint SkuFlags = Instance.WinHelper.KuserSharedData?.SharedDataFlags ?? 0;

            // basesrv GetGlobalizationUserModelType.
            bool MultiSession = (SkuFlags & DbgMultiSessionSku) != 0;

            // This model keeps its settings in the state store, which is not emulated. Clients read the registry.
            if (!MultiSession && (SkuFlags & DbgMultiUsersInSessionSku) != 0)
            {
                BaseSrvNlsUserInfo Unattached = new BaseSrvNlsUserInfo(Address, null);
                Unattached.Publish(Instance);
                Instance.WinHelper.NlsUserInfo = Unattached;
                return;
            }

            string Root = MultiSession
                ? @"\Registry\User\" + Instance.WinHelper.CurrentUserSid
                : SingleUserModelRoot(Instance);
            if (Root != null && Instance.WinHelper.ResolveRegistryKey(Root) == null)
                Root = null;

            BaseSrvNlsUserInfo Server = new BaseSrvNlsUserInfo(Address, Root == null ? null : Instance.WinHelper.NormalizeNtRegistryPath(Root + @"\Control Panel\International"));

            BinaryPrimitives.WriteUInt64LittleEndian(Server.Info.AsSpan(LogonIdOffset, 8), WinToken.InteractiveLogonId);
            byte[] Sid = NtQueryInformationToken.InteractiveUserSid();
            Sid.CopyTo(Server.Info.AsSpan(UserSidOffset, Sid.Length));

            if (Server.InternationalKeyPath != null)
                Server.UpdateCount = 1;

            Server.Publish(Instance);
            Instance.WinHelper.NlsUserInfo = Server;
        }

        // OpenGlobalizationUserSettingsKey_ForSingleUserModel.
        private static string SingleUserModelRoot(BinaryEmulator Instance)
        {
            WinRegKey Common = Instance.WinHelper.ResolveRegistryKey(CommonGlobUserSettingsKey);
            if (Common == null)
                return null;

            if (!Instance.WinHelper.TryGetRegistryValue(Common, "RedirectedKey", out ValueNode Redirected) || Redirected.Type != WinSysHelper.RegSz)
                return CommonGlobUserSettingsKey;

            ReadOnlySpan<byte> Data = Redirected.Data;
            int End = SimdStringHelpers.IndexOfUtf16Nul(Data);
            string Target = SimdStringHelpers.TryDecodeUtf16LeString(Data.Slice(0, End >= 0 ? End : Data.Length & ~1));
            return string.IsNullOrEmpty(Target) ? null : Target;
        }

        internal NTSTATUS GetUserInfo(BinaryEmulator Instance, uint RequestedSize)
        {
            if (RequestedSize != Size)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (CacheDirty)
            {
                CacheDirty = false;
                if (InternationalKeyPath == null)
                    return NTSTATUS.STATUS_UNSUCCESSFUL;

                UpdateCount++;
                ReadUserSettings(Instance);
                Publish(Instance);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        internal void UpdateCacheCount(BinaryEmulator Instance)
        {
            CacheDirty = true;
            UpdateCount++;
            if (!Instance._emulator.WriteMemory(Address + UpdateCountOffset, UpdateCount))
                Utils.LogError($"[BaseSrv] Failed to publish the NLS update count at 0x{Address + UpdateCountOffset:X}.");
        }

        // basesrv BaseSrvNlsUpdateRegistryCache.
        internal void RegistryChanged(BinaryEmulator Instance, string ChangedPath, uint ChangedFilter)
        {
            if (InternationalKeyPath == null || ChangedPath == null || (ChangedFilter & ChangeFilter) == 0)
                return;

            if (!ChangedPath.StartsWith(InternationalKeyPath, StringComparison.OrdinalIgnoreCase)
                || (ChangedPath.Length != InternationalKeyPath.Length && ChangedPath[InternationalKeyPath.Length] != '\\'))
                return;

            UpdateCacheCount(Instance);
        }

        private void Publish(BinaryEmulator Instance)
        {
            if (!Instance.WriteMemory(Address, Info))
                Utils.LogError($"[BaseSrv] Failed to publish NLS_USER_INFO at 0x{Address:X}.");
        }

        // basesrv NlsUpdateCacheInfo. A shorter string leaves the tail of the old one.
        private void ReadUserSettings(BinaryEmulator Instance)
        {
            Span<byte> Data = Info;
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x628, 4), 1);
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x4DA, 4), 0xFFFF);
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x4E4, 4), 0xFFFF);
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x586, 4), 0xFFFF);

            WinRegKey Key = Instance.WinHelper.ResolveRegistryKey(InternationalKeyPath);
            ValueNode[] Values = new ValueNode[Fields.Length];
            if (Key != null)
            {
                for (int i = 0; i < Fields.Length; i++)
                    Instance.WinHelper.TryGetRegistryValue(Key, Fields[i].Name, out Values[i]);
            }

            // One NtQueryMultipleValueKey for the first 30 names. If it fails, a 0xB6-byte NtQueryValueKey per name.
            bool MultipleQuery = Key != null;
            uint Packed = 0;
            for (int i = 0; i < MultipleQueryCount && MultipleQuery; i++)
            {
                uint Length = (uint)(Values[i]?.Data?.Length ?? 0);
                MultipleQuery = Values[i] != null && Packed + Length <= MultipleQueryBufferLength;
                Packed = (Packed + Length + 3) & ~3u;
            }

            for (int i = 0; i < Fields.Length; i++)
            {
                ValueNode Value = Values[i];
                byte[] Bytes = Value?.Data ?? Array.Empty<byte>();
                bool Present = Value != null && ((MultipleQuery && i < MultipleQueryCount) || Bytes.Length <= PartialQueryDataLimit);
                StoreField(Data.Slice(Fields[i].Offset), Fields[i].Size, Present ? Value.Type : 0, Bytes);
            }

            if (Key != null)
                ReadExplicitSettings(Instance, Data);
        }

        private static void StoreField(Span<byte> Field, int FieldSize, int Type, ReadOnlySpan<byte> Bytes)
        {
            if (Type != WinSysHelper.RegSz || Bytes.Length == 0 || (Bytes.Length & 1) != 0 || BinaryPrimitives.ReadUInt16LittleEndian(Bytes.Slice(Bytes.Length - 2)) != 0)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(Field, 0xFFFF);
                if (FieldSize != 0)
                    BinaryPrimitives.WriteUInt16LittleEndian(Field.Slice(2), 0);
                return;
            }

            int Count = Bytes.Length / 2 - 1;
            if (FieldSize == 0)
                BinaryPrimitives.WriteUInt16LittleEndian(Field, ParseNumber(Bytes, Count));
            else if (!StoreCounted(Field, FieldSize - 1, Bytes, Count))
                BinaryPrimitives.WriteUInt32LittleEndian(Field, 0xFFFF);
        }

        private static ushort ParseNumber(ReadOnlySpan<byte> Bytes, int Count)
        {
            if ((uint)(Count - 1) > 2)
                return 0xFFFF;

            ushort Number = 0;
            for (int i = 0; i < Count; i++)
            {
                ushort Digit = (ushort)(BinaryPrimitives.ReadUInt16LittleEndian(Bytes.Slice(i * 2, 2)) - '0');
                if (Digit > 9)
                    return 0xFFFF;
                Number = (ushort)(Number * 10 + Digit);
            }

            return Number;
        }

        private static bool StoreCounted(Span<byte> Field, int Chars, ReadOnlySpan<byte> Text, int Count)
        {
            if (!CopyString(Field.Slice(2, Chars * 2), Chars, Text, Count))
                return false;

            BinaryPrimitives.WriteUInt16LittleEndian(Field, (ushort)Count);
            return true;
        }

        // basesrv ReadSettingsCache.
        private void ReadExplicitSettings(BinaryEmulator Instance, Span<byte> Data)
        {
            WinRegKey Explicit = Instance.WinHelper.ResolveRegistryKey(InternationalKeyPath + @"\" + ExplicitSettingsKey);
            if (Explicit == null)
                return;

            if (TryQueryString(Instance, Explicit, "Currencies", out ReadOnlySpan<byte> Text, out int Length) && Length >= 3)
                StoreCounted(Data.Slice(0x4DA), 4, Text, 3);

            if (TryQueryString(Instance, Explicit, "Calendar", out Text, out Length) && Length >= 4)
            {
                ushort CalendarId = CalendarIdFromString(Text);
                if (CalendarId != 0)
                    BinaryPrimitives.WriteUInt16LittleEndian(Data.Slice(CalendarTypeOffset, 2), CalendarId);
            }

            ReadDateFormats(Instance, Data, Explicit.FullPath + @"\Gregorian", 0x4E4, 0x586);

            ushort Calendar = BinaryPrimitives.ReadUInt16LittleEndian(Data.Slice(CalendarTypeOffset, 2));
            if (Calendar < CalendarNames.Length && CalendarNames[Calendar].Length != 0)
                ReadDateFormats(Instance, Data, Explicit.FullPath + @"\" + CalendarNames[Calendar], 0x2BE, 0x402);
        }

        private static void ReadDateFormats(BinaryEmulator Instance, Span<byte> Data, string KeyPath, int ShortDateOffset, int LongDateOffset)
        {
            WinRegKey Key = Instance.WinHelper.ResolveRegistryKey(KeyPath);
            if (Key == null)
                return;

            if (TryQueryString(Instance, Key, "Short Date", out ReadOnlySpan<byte> Text, out int Length) && (uint)(Length - 2) <= 0x4D)
                StoreCounted(Data.Slice(ShortDateOffset), 0x50, Text, Length);

            if (TryQueryString(Instance, Key, "Long Date", out Text, out Length) && (uint)(Length - 3) <= 0x4C)
                StoreCounted(Data.Slice(LongDateOffset), 0x50, Text, Length);
        }

        // basesrv QueryStringValue.
        private static bool TryQueryString(BinaryEmulator Instance, WinRegKey Key, string Name, out ReadOnlySpan<byte> Text, out int Length)
        {
            Text = default;
            Length = 0;

            if (!Instance.WinHelper.TryGetRegistryValue(Key, Name, out ValueNode Value) || Value.Type != WinSysHelper.RegSz)
                return false;

            byte[] Bytes = Value.Data ?? Array.Empty<byte>();
            if (Bytes.Length > PartialQueryDataLimit || (Bytes.Length & 1) != 0 || Bytes.Length <= 2)
                return false;

            Length = Bytes.Length / 2 - 1;
            Text = Bytes;
            return BinaryPrimitives.ReadUInt16LittleEndian(Text.Slice(Length * 2, 2)) == 0;
        }

        // ntdll wcsncpy_s.
        private static bool CopyString(Span<byte> Destination, int DestinationChars, ReadOnlySpan<byte> Source, int Count)
        {
            if (Count == 0)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(Destination, 0);
                return true;
            }

            int Available = DestinationChars;
            int Remaining = Count;
            int Index = 0;
            while (true)
            {
                ushort c = BinaryPrimitives.ReadUInt16LittleEndian(Source.Slice(Index * 2, 2));
                BinaryPrimitives.WriteUInt16LittleEndian(Destination.Slice(Index * 2, 2), c);
                Index++;
                if (c == 0)
                    return true;
                if (--Available == 0)
                    break;
                if (--Remaining == 0)
                {
                    BinaryPrimitives.WriteUInt16LittleEndian(Destination.Slice(Index * 2, 2), 0);
                    return true;
                }
            }

            BinaryPrimitives.WriteUInt16LittleEndian(Destination, 0);
            return false;
        }

        // basesrv CalendarIdFromString. ntdll _wcsicmp folds A to Z only.
        private static ushort CalendarIdFromString(ReadOnlySpan<byte> Text)
        {
            for (ushort Id = 0; Id < CalendarNames.Length; Id++)
            {
                string Name = CalendarNames[Id];
                int i = 0;
                while (true)
                {
                    char Left = i < Name.Length ? Name[i] : '\0';
                    char Right = (char)BinaryPrimitives.ReadUInt16LittleEndian(Text.Slice(i * 2, 2));
                    if (Left >= 'A' && Left <= 'Z')
                        Left = (char)(Left + 32);
                    if (Right >= 'A' && Right <= 'Z')
                        Right = (char)(Right + 32);
                    if (Left != Right)
                        break;
                    if (Left == '\0')
                        return Id;
                    i++;
                }
            }

            return 0;
        }
    }
}
