using System;
using System.Buffers;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtDeviceIoControlFile : IWinSyscall
    {
        private const uint LargeObjectThreshold = 85000;
        // The shared pool keeps rented arrays for the process lifetime.
        private static uint MaxPooledIoBytes => MemoryBudget.PooledIoBytes;


        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong FileHandle = Instance.WinHelper.GetArg(0);
            ulong EventHandle = Instance.WinHelper.GetArg(1);
            ulong ApcRoutine = Instance.WinHelper.GetArg(2);
            ulong ApcContext = Instance.WinHelper.GetArg(3);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg(4);
            uint IoControlCode = (uint)Instance.WinHelper.GetArg(5);
            ulong InputBufferPtr = Instance.WinHelper.GetArg(6);
            uint InputBufferLength = (uint)Instance.WinHelper.GetArg(7);
            ulong OutputBufferPtr = Instance.WinHelper.GetArg(8);
            uint OutputBufferLength = (uint)Instance.WinHelper.GetArg(9);

            NTSTATUS Status = CheckRequest(Instance, FileHandle, IoStatusBlockPtr, ApcRoutine, IoControlCode, InputBufferPtr, InputBufferLength, OutputBufferPtr, OutputBufferLength, out WinFile File);
            if (Status == NTSTATUS.STATUS_SUCCESS)
                Status = Instance.WinHelper.ReferenceIoEvent(EventHandle);

            if (Status != NTSTATUS.STATUS_SUCCESS)
            {
                Instance.WinHelper.ClearPipeWait();
                return Status;
            }

            if (!File.Device || File.Handler == null)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_DEVICE_REQUEST, 0);
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
            }

            Status = CheckControlBuffers(Instance, IoControlCode, InputBufferPtr, InputBufferLength, OutputBufferPtr, OutputBufferLength);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            DeviceData Data = new DeviceData();
            Data.File = File;
            Data.FileHandle = FileHandle;
            Data.EventHandle = EventHandle;
            Data.ApcRoutine = ApcRoutine;
            Data.ApcContext = ApcContext;
            Data.IoStatusBlock = IoStatusBlockPtr;
            Data.UserBuffer = OutputBufferPtr;
            Data.InputPointer = InputBufferPtr;

            byte[] RentedInput = null;
            byte[] RentedOutput = null;
            try
            {
                Status = CaptureControlBuffers(Instance, IoControlCode, InputBufferPtr, InputBufferLength, OutputBufferPtr, OutputBufferLength, ref Data, out RentedInput, out RentedOutput);
                Data.OutputLength = OutputBufferLength;

                if (Status == NTSTATUS.STATUS_SUCCESS)
                {
                    try
                    {
                        Status = File.Handler(IoControlCode, ref Data, Instance);
                    }
                    catch (Exception Ex)
                    {
                        Utils.LogError($"[NtDeviceIoControlFile] 0x{IoControlCode:X} on {File.Path}: {Ex.Message}");
                        Status = NTSTATUS.STATUS_UNSUCCESSFUL;
                    }
                }

                if (!WriteBackControlOutput(Instance, Status, OutputBufferPtr, OutputBufferLength, in Data))
                    Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
            }
            finally
            {
                ReleaseControlBuffers(RentedInput, RentedOutput);
            }

            ulong Information = Data.Information;
            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, Status, Information);
            Instance.WinHelper.SignalIoEvent(EventHandle, Status);
            Instance.WinHelper.QueueImmediateCompletion(File, ApcRoutine, ApcContext, IoStatusBlockPtr, Status, Information);
            return Status;
        }

        internal const uint METHOD_BUFFERED = 0;
        internal const uint METHOD_NEITHER = 3;

        // NT checks in this order and writes no IO_STATUS_BLOCK for a failure here.
        internal static NTSTATUS CheckRequest(BinaryEmulator Instance, ulong FileHandle, ulong IoStatusBlockPtr, ulong ApcRoutine, uint ControlCode, ulong InputBufferPtr, uint InputBufferLength, ulong OutputBufferPtr, uint OutputBufferLength, out WinFile File)
        {
            File = null;
            if (!Instance.WinHelper.TryProbeIoStatusBlock(IoStatusBlockPtr, out NTSTATUS ProbeStatus))
                return ProbeStatus;

            if (!ProbeControlBuffers(Instance, ControlCode, InputBufferPtr, InputBufferLength, OutputBufferPtr, OutputBufferLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = Instance.WinHelper.ReferenceObjectByHandle(FileHandle, AccessMask.GiveTemp, out File, out AccessMask Granted);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (File.RefusesApcRoutine(ApcRoutine))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!HasControlAccess(Granted, ControlCode))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT touches each page of a buffered output buffer but checks only the range of an input buffer.
        private static bool ProbeControlBuffers(BinaryEmulator Instance, uint ControlCode, ulong InputBufferPtr, uint InputBufferLength, ulong OutputBufferPtr, uint OutputBufferLength)
        {
            uint Method = ControlCode & 3;
            if (Method == METHOD_BUFFERED && OutputBufferPtr != 0 && OutputBufferLength != 0 && !Instance.IsAccessible(OutputBufferPtr, OutputBufferLength, true))
                return false;

            if (Method == METHOD_NEITHER || InputBufferPtr == 0 || InputBufferLength == 0)
                return true;

            return NtWow64GetNativeSystemInformation.IsUserRange(InputBufferPtr, InputBufferLength);
        }

        // NT: checked after the event reset. A failure leaves the IO_STATUS_BLOCK alone.
        internal static NTSTATUS CheckControlBuffers(BinaryEmulator Instance, uint ControlCode, ulong InputBufferPtr, uint InputBufferLength, ulong OutputBufferPtr, uint OutputBufferLength)
        {
            // NT: system buffer allocation failure.
            if ((InputBufferPtr != 0 && InputBufferLength > MaxPooledIoBytes) || (OutputBufferPtr != 0 && OutputBufferLength > MaxPooledIoBytes))
                return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

            uint Method = ControlCode & 3;
            if (Method == METHOD_NEITHER)
                return NTSTATUS.STATUS_SUCCESS;

            if (InputBufferPtr != 0 && !Instance.IsMemoryRangeMapped(InputBufferPtr, InputBufferLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            // NT: direct methods lock the output pages.
            if (Method != METHOD_BUFFERED && OutputBufferPtr != 0 && !Instance.IsMemoryRangeMapped(OutputBufferPtr, OutputBufferLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: a METHOD_NEITHER driver fails a bad buffer as a normal request.
        internal static NTSTATUS CaptureControlBuffers(BinaryEmulator Instance, uint ControlCode, ulong InputBufferPtr, uint InputBufferLength, ulong OutputBufferPtr, uint OutputBufferLength, ref DeviceData Data, out byte[] RentedInput, out byte[] RentedOutput)
        {
            RentedInput = null;
            RentedOutput = null;

            uint Method = ControlCode & 3;
            bool OutputLocked = Method != METHOD_BUFFERED && Method != METHOD_NEITHER;
            if (OutputBufferPtr != 0 && !OutputLocked && !Instance.IsMemoryRangeMapped(OutputBufferPtr, OutputBufferLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (InputBufferPtr != 0 && InputBufferLength != 0)
            {
                byte[] InputBuffer;
                if (InputBufferLength >= LargeObjectThreshold)
                {
                    RentedInput = ArrayPool<byte>.Shared.Rent((int)InputBufferLength);
                    InputBuffer = RentedInput;
                }
                else
                {
                    InputBuffer = new byte[InputBufferLength];
                }

                if (!Instance.ReadMemory(InputBufferPtr, InputBuffer.AsSpan(0, (int)InputBufferLength)))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Data.InputBuffer = InputBuffer;
                Data.InputLength = InputBufferLength;
            }

            if (OutputBufferPtr != 0 && OutputBufferLength != 0)
            {
                RentedOutput = ArrayPool<byte>.Shared.Rent((int)OutputBufferLength);
                Array.Clear(RentedOutput, 0, (int)OutputBufferLength);
                Data.OutputBuffer = RentedOutput;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT copies back unless NT_ERROR(Status).
        internal static bool WriteBackControlOutput(BinaryEmulator Instance, NTSTATUS Status, ulong OutputBufferPtr, uint OutputBufferLength, in DeviceData Data)
        {
            if (((uint)Status >> 30) == 3 || OutputBufferPtr == 0 || OutputBufferLength == 0 || Data.OutputBuffer == null)
                return true;

            uint ToWrite = (uint)Math.Min(Data.Information, Math.Min(OutputBufferLength, (uint)Data.OutputBuffer.Length));
            return ToWrite == 0 || Instance.WriteMemory(OutputBufferPtr, Data.OutputBuffer.AsSpan(0, (int)ToWrite));
        }

        internal static void ReleaseControlBuffers(byte[] RentedInput, byte[] RentedOutput)
        {
            if (RentedOutput != null)
                ArrayPool<byte>.Shared.Return(RentedOutput);

            if (RentedInput != null)
                ArrayPool<byte>.Shared.Return(RentedInput);
        }

        private static bool HasControlAccess(AccessMask Granted, uint ControlCode)
        {
            uint RequiredAccess = (ControlCode >> 14) & 0x3;
            return ((RequiredAccess & 0x1) == 0 || (Granted & WinFile.ReadDataAccess) != 0)
                && ((RequiredAccess & 0x2) == 0 || (Granted & WinFile.WriteDataAccess) != 0);
        }

    }
}
