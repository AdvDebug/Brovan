using System;
using System.Buffers.Binary;
using System.Text;
using System.Threading.Tasks;
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
        internal readonly GenState GenState = new GenState();
        private readonly GenReader Reader = new GenReader();
        private readonly GenReader PostedReader = new GenReader();
        private readonly GenBuf Writer = new GenBuf();
        private readonly bool[] MissingReported = new bool[BrovVulkApi.CommandCount];

        public string DeviceName => "\\Device\\BrovVulk";

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            InternalPath = DevicePath;
            Handler = HandleIoctl;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS HandleIoctl(uint Ioctl, ref DeviceData Data, BinaryEmulator Instance)
        {
            if (Ioctl != IOCTL_BROVVULK_GEN)
                return HandleIoctl(Ioctl, ref Data, (IGuestMemory)Instance);

            Task Rerun = Instance.WinHelper.TakeRetriedHostWork<Task<BrovVulkWaits.Call>>();
            bool CanPark = Instance.CurrentThread != null && Data.File != null && Data.File.Synchronous && !BrovVulkWaits.Disabled;

            NTSTATUS Status = HandleGenIoctl(ref Data, Instance, CanPark, Rerun, out BrovVulkWaits.Call Parked);
            if (Parked == null)
                return Status;

            WinPendingIo Io = Instance.WinHelper.SynchronousIo(Data.File, Data.EventHandle, Data.ApcRoutine, Data.ApcContext, Data.IoStatusBlock);
            if (!Instance.WinHelper.TryRetrySyscallWhenDone(Parked.Done.Task, Io))
            {
                GenState.Waits.Release(Parked);
                return Status;
            }

            GenState.Waits.Start(Parked, Instance.WakeSignal);
            Data.OutputBuffer = null;
            Data.Information = 0;
            return NTSTATUS.STATUS_PENDING;
        }

        internal NTSTATUS HandleIoctl(uint Ioctl, ref DeviceData Data, IGuestMemory Instance)
        {
            if (Ioctl == IOCTL_BROVVULK_GEN)
                return HandleGenIoctl(ref Data, Instance, false, null, out _);

            if ((Instance.GuestLogFlags & LogFlags.Issues) != 0)
                Instance.TriggerEventMessage($"[BrovVulk] unknown IOCTL 0x{Ioctl:X}.", LogFlags.Issues);

            return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
        }

        private NTSTATUS HandleGenIoctl(ref DeviceData Data, IGuestMemory Instance, bool CanPark, Task Rerun, out BrovVulkWaits.Call Parked)
        {
            Parked = null;
            byte[] Input = Data.InputBuffer;
            // InputBuffer can be pooled, so only InputLength bounds the guest data.
            uint InputLength = Input == null ? 0 : Math.Min(Data.InputLength, (uint)Input.Length);
            if (Input == null || InputLength < 8)
            {
                if ((Instance.GuestLogFlags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage($"[BrovVulk] rejected IOCTL with a {(Input == null ? -1 : (int)InputLength)} byte input buffer.", LogFlags.Issues);

                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            uint Id = BinaryPrimitives.ReadUInt32LittleEndian(Input.AsSpan(0, 4));
            uint PayloadLen = BinaryPrimitives.ReadUInt32LittleEndian(Input.AsSpan(4, 4));
            if (PayloadLen > InputLength - 8 || PayloadLen > MaxGenPayload)
            {
                if ((Instance.GuestLogFlags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage($"[BrovVulk] rejected command {Id} with payload length {PayloadLen} in a {InputLength} byte input buffer.", LogFlags.Issues);

                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            byte[] OutBytes;
            lock (Lock)
            {
                Reader.Reset(Input, 8, (int)PayloadLen);
                Writer.Reset();
                int Result;
                uint Failing = Id;
                IntPtr PreviousDpiContext = HostDisplayMetrics.EnterWindowDpiContext(Instance.GuestDpiAwareness);
                try
                {
                    if (Id == BatchId || Id == BrovVulkGenDispatch.PostedBatchId)
                    {
                        Result = RunBatch(Input, Id == BrovVulkGenDispatch.PostedBatchId, Instance, ref Failing);
                    }
                    else if (GenState.HasLostDevice && BrovVulkGenDispatch.MayLoseDevice.Contains(Id) && PayloadLen >= 4
                             && GenState.IsDeviceLost(BinaryPrimitives.ReadUInt32LittleEndian(Input.AsSpan(8, 4))))
                    {
                        Result = BrovVulkConstants.VK_ERROR_DEVICE_LOST;
                    }
                    else
                    {
                        if (BrovVulkGenDispatch.CreatesGuestIds.Contains(Id))
                            PostStats.SentNow();
                        GenState.Waits.BeginCommand(CanPark, Rerun);
                        try { Result = BrovVulkGenDispatch.Dispatch(Id, Reader, Writer, GenState, Instance); }
                        finally { GenState.FreeCallAllocs(); }
                        Parked = GenState.Waits.TakeParked();
                    }
                }
                catch (Exception Ex)
                {
                    LogFailure(Failing, Ex.Message, Instance);
                    Writer.Reset();
                    Result = VK_ERROR_INITIALIZATION_FAILED;
                }
                finally
                {
                    GenState.Waits.EndCommand();
                    HostDisplayMetrics.LeaveWindowDpiContext(PreviousDpiContext);
                }

                // A park that fails answers as a poll does, so the guest keeps polling.
                if (Parked != null)
                {
                    Writer.Reset();
                    Result = BrovVulkConstants.VK_NOT_READY;
                }

                OutBytes = Writer.Finish(Result);
            }

            Data.OutputBuffer = OutBytes;
            Data.Information = (ulong)OutBytes.Length;
            return NTSTATUS.STATUS_SUCCESS;
        }

        // The guest took success for a posted creation, so one that fails here loses its device. Vulkan still allows
        // the commands that end a handle on a lost device, so only those of its posted commands run.
        private int RunBatch(byte[] Input, bool Posted, IGuestMemory Instance, ref uint Failing)
        {
            uint Count = Reader.ReadU32();
            if (Count > MaxBatchCommands)
                throw new InvalidOperationException($"BrovVulk generic: batch count {Count} exceeds cap.");

            int Result = 0;
            for (uint k = 0; k < Count; k++)
            {
                uint SubId = Reader.ReadU32();
                Failing = SubId;
                GenReader SubReader = Reader;
                uint Handle = 0;
                if (Posted)
                {
                    uint SubLen = Reader.ReadU32();
                    if (SubLen > (uint)Reader.Remaining)
                        throw new InvalidOperationException($"BrovVulk posted: sub-command length {SubLen} exceeds the batch.");

                    int Start = Reader.Offset;
                    Reader.Skip((int)SubLen);
                    if (SubLen >= 4)
                        Handle = BinaryPrimitives.ReadUInt32LittleEndian(Input.AsSpan(Start, 4));
                    if (GenState.HasLostDevice && !BrovVulkGenDispatch.ReleasesHandles.Contains(SubId) && GenState.IsDeviceLost(Handle))
                    {
                        PostStats.Dropped();
                        continue;
                    }

                    PostedReader.Reset(Input, Start, (int)SubLen);
                    SubReader = PostedReader;
                }

                try
                {
                    Result = BrovVulkGenDispatch.Dispatch(SubId, SubReader, Writer, GenState, Instance);
                }
                catch (EntryPointNotFoundException Ex)
                {
                    ReportMissingEntryPoint(SubId, Ex, Instance);
                    if (Posted)
                        Result = VK_ERROR_INITIALIZATION_FAILED;
                }
                catch (Exception Ex) when (Posted)
                {
                    LogFailure(SubId, Ex.Message, Instance);
                    Result = VK_ERROR_INITIALIZATION_FAILED;
                }
                finally
                {
                    GenState.FreeCallAllocs();
                    if (Posted)
                        Writer.Reset();
                }

                if (!Posted)
                    continue;

                PostStats.Posted(Result < 0);
                if (Result < 0 && BrovVulkGenDispatch.CreatesGuestIds.Contains(SubId))
                {
                    GenState.MarkDeviceLost(Handle);
                    PostStats.DeviceLost();
                    Utils.LogError($"[!] BrovVulk(gen): posted {CommandName(SubId)} failed with {Result}, so its device is lost.");
                }
            }

            return Posted ? 0 : Result;
        }

        private static string CommandName(uint Id) => Id < (uint)BrovVulkApi.CommandNames.Length ? BrovVulkApi.CommandNames[Id] : Id.ToString();

        private static void LogFailure(uint Id, string Message, IGuestMemory Instance)
        {
            Utils.LogError($"[!] BrovVulk(gen): {CommandName(Id)}: {Message}");
            if ((Instance.GuestLogFlags & LogFlags.Issues) != 0)
                Instance.TriggerEventMessage($"[!] BrovVulk(gen): {CommandName(Id)}: {Message}", LogFlags.Issues);
        }

        private static class PostStats
        {
            private static readonly BrovVulkStats Log = new BrovVulkStats("BROVVULK_POST_STATS", "BrovVulk post stats:", Describe);

            private static long _posted;
            private static long _failed;
            private static long _sentNow;
            private static long _lost;
            private static long _dropped;

            internal static void Posted(bool failed)
            {
                if (!Log.Enabled)
                    return;

                _posted++;
                if (failed)
                    _failed++;
                Log.Tick();
            }

            internal static void SentNow()
            {
                if (!Log.Enabled)
                    return;

                _sentNow++;
                Log.Tick();
            }

            internal static void DeviceLost()
            {
                if (!Log.Enabled)
                    return;

                _lost++;
                Log.Tick();
            }

            internal static void Dropped()
            {
                if (!Log.Enabled)
                    return;

                _dropped++;
                Log.Tick();
            }

            private static void Describe(StringBuilder sb) =>
                sb.Append(" posted=").Append(_posted).Append(" failed=").Append(_failed).Append(" guestIdsSentNow=").Append(_sentNow)
                  .Append(" devicesLost=").Append(_lost).Append(" droppedOnLostDevice=").Append(_dropped);
        }

        // Raised at the call, after the sub-command's input was read, so the next sub-command still parses.
        private void ReportMissingEntryPoint(uint Id, EntryPointNotFoundException Ex, IGuestMemory Instance)
        {
            if (Id >= (uint)MissingReported.Length || MissingReported[Id])
                return;

            MissingReported[Id] = true;
            if ((Instance.GuestLogFlags & LogFlags.Issues) != 0)
                Instance.TriggerEventMessage($"[!] BrovVulk(gen): batch skipped {BrovVulkApi.CommandNames[Id]}. {Ex.Message}", LogFlags.Issues);
        }
    }
}
