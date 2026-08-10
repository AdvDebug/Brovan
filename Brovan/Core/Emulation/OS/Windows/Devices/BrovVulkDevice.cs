using System;
using System.Buffers.Binary;
using Brovan.Core.Emulation.OS.SharedHelpers;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class BrovVulkDevice : IWinDevice
    {
        private const uint IOCTL_BROVVULK_GEN = 0x80002004;
        private const uint MaxGenPayload = 1u << 20;
        private const uint BatchId = 0xFFFFFFFE;
        private const uint MaxBatchCommands = 1u << 20;
        private const int VK_ERROR_INITIALIZATION_FAILED = -3;

        private readonly object Lock = new object();
        private readonly GenState GenState = new GenState();
        private readonly GenReader Reader = new GenReader();
        private readonly GenBuf Writer = new GenBuf();

        public string DeviceName => "\\Device\\BrovVulk";

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            InternalPath = DevicePath;
            Handler = HandleIoctl;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS HandleIoctl(uint Ioctl, ref DeviceData Data, BinaryEmulator Instance)
        {
            if (Ioctl == IOCTL_BROVVULK_GEN)
                return HandleGenIoctl(ref Data, Instance);

            if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                Instance.TriggerEventMessage($"[BrovVulk] unknown IOCTL 0x{Ioctl:X}.", LogFlags.Issues);

            return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
        }

        private NTSTATUS HandleGenIoctl(ref DeviceData Data, BinaryEmulator Instance)
        {
            byte[] Input = Data.InputBuffer;
            if (Input == null || Input.Length < 8)
            {
                if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage($"[BrovVulk] rejected IOCTL with a {(Input == null ? -1 : Input.Length)} byte input buffer.", LogFlags.Issues);

                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            uint Id = BinaryPrimitives.ReadUInt32LittleEndian(Input.AsSpan(0, 4));
            uint PayloadLen = BinaryPrimitives.ReadUInt32LittleEndian(Input.AsSpan(4, 4));
            if (PayloadLen > (uint)(Input.Length - 8) || PayloadLen > MaxGenPayload)
            {
                if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage($"[BrovVulk] rejected command {Id} with payload length {PayloadLen} in a {Input.Length} byte input buffer.", LogFlags.Issues);

                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            byte[] OutBytes;
            lock (Lock)
            {
                Reader.Reset(Input, 8, (int)PayloadLen);
                Writer.Reset();
                int Result;
                IntPtr PreviousDpiContext = HostDisplayMetrics.EnterWindowDpiContext(Win32k.Win32kDpi.GetHostAwareness(Instance));
                try
                {
                    if (Id == BatchId)
                    {
                        uint Count = Reader.ReadU32();
                        if (Count > MaxBatchCommands)
                            throw new InvalidOperationException($"BrovVulk generic: batch count {Count} exceeds cap.");

                        Result = 0;
                        for (uint k = 0; k < Count; k++)
                        {
                            uint SubId = Reader.ReadU32();
                            try { Result = BrovVulkGenDispatch.Dispatch(SubId, Reader, Writer, GenState, Instance); }
                            finally { GenState.FreeCallAllocs(); }
                        }
                    }
                    else
                    {
                        try { Result = BrovVulkGenDispatch.Dispatch(Id, Reader, Writer, GenState, Instance); }
                        finally { GenState.FreeCallAllocs(); }
                    }
                }
                catch (Exception Ex)
                {
                    if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                        Instance.TriggerEventMessage($"[!] BrovVulk(gen): {Ex.Message}", LogFlags.Issues);
                    Writer.Reset();
                    Result = VK_ERROR_INITIALIZATION_FAILED;
                }
                finally
                {
                    HostDisplayMetrics.LeaveWindowDpiContext(PreviousDpiContext);
                }

                OutBytes = Writer.Finish(Result);
            }

            Data.OutputBuffer = OutBytes;
            Data.Information = (ulong)OutBytes.Length;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
