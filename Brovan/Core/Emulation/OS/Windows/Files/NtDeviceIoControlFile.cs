using System;
using System.Buffers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtDeviceIoControlFile : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong FileHandle = Instance.WinHelper.GetArg(0);
            ulong EventHandle = Instance.WinHelper.GetArg(1);

            // ulong ApcRoutine = Instance.WinHelper.GetArg(2); // not used for now
            // ulong ApcContext = Instance.WinHelper.GetArg(3); // not used for now
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg(4);
            uint IoControlCode = (uint)Instance.WinHelper.GetArg(5);
            ulong InputBufferPtr = Instance.WinHelper.GetArg(6);
            uint InputBufferLength = (uint)Instance.WinHelper.GetArg(7);
            ulong OutputBufferPtr = Instance.WinHelper.GetArg(8);
            uint OutputBufferLength = (uint)Instance.WinHelper.GetArg(9);

            if (IoStatusBlockPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(IoStatusBlockPtr, (uint)(Instance.WinHelper.PointerSize * 2)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinFile File = Instance.WinHelper.GetFileByHandle(FileHandle, AccessMask.GiveTemp);
            if (File == null)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_HANDLE, 0);
                return NTSTATUS.STATUS_INVALID_HANDLE;
            }

            if (!File.Device || File.Handler == null)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_DEVICE_REQUEST, 0);
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
            }

            if (InputBufferPtr != 0 && InputBufferLength != 0 && !Instance.IsRegionMapped(InputBufferPtr, InputBufferLength))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_VIOLATION, 0);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if (OutputBufferPtr != 0 && OutputBufferLength != 0 && !Instance.IsRegionMapped(OutputBufferPtr, OutputBufferLength))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_VIOLATION, 0);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if (!HasIoControlAccess(Instance, FileHandle, IoControlCode))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            DeviceData Data = new DeviceData();

            if (InputBufferPtr != 0 && InputBufferLength != 0)
            {
                Data.InputBuffer = Instance.ReadMemory(InputBufferPtr, InputBufferLength);
                Data.InputLength = InputBufferLength;
            }

            byte[] RentedOutput = null;
            if (OutputBufferPtr != 0 && OutputBufferLength != 0)
            {
                RentedOutput = ArrayPool<byte>.Shared.Rent((int)OutputBufferLength);
                Array.Clear(RentedOutput, 0, (int)OutputBufferLength);
                Data.OutputBuffer = RentedOutput;
                Data.OutputLength = OutputBufferLength;
            }

            NTSTATUS Status;
            try
            {
                Status = File.Handler(IoControlCode, ref Data, Instance);
            }
            catch
            {
                Status = NTSTATUS.STATUS_UNSUCCESSFUL;
            }

            ulong Information = Data.Information;

            if (Status >= 0 && OutputBufferPtr != 0 && OutputBufferLength != 0 && Data.OutputBuffer != null)
            {
                uint ToWrite = Math.Min(OutputBufferLength, (uint)Data.OutputBuffer.Length);
                if (ToWrite > 0)
                {
                    Instance.WriteMemory(OutputBufferPtr, Data.OutputBuffer.AsSpan(0, (int)ToWrite));

                    if (Information == 0)
                        Information = ToWrite;
                }
            }

            if (RentedOutput != null && Status != NTSTATUS.STATUS_PENDING)
                ArrayPool<byte>.Shared.Return(RentedOutput);

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, Status, Information);

            if (EventHandle != 0 && Status != NTSTATUS.STATUS_PENDING)
            {
                WinEvent Ev = Instance.WinHelper.GetEventByHandle(EventHandle, AccessMask.GiveTemp);
                if (Ev != null)
                    Ev.Signaled = true;
            }

            return Status;
        }

        private static bool HasIoControlAccess(BinaryEmulator Instance, ulong FileHandle, uint IoControlCode)
        {
            uint RequiredAccess = (IoControlCode >> 14) & 0x3;
            if (RequiredAccess == 0)
                return true;

            if ((RequiredAccess & 0x1) != 0 &&
                !Instance.WinHelper.HandleManager.CheckAccess(FileHandle, AccessMask.GenericRead) &&
                !Instance.WinHelper.HandleManager.CheckAccess(FileHandle, AccessMask.FileReadData))
            {
                return false;
            }

            if ((RequiredAccess & 0x2) != 0 &&
                !Instance.WinHelper.HandleManager.CheckAccess(FileHandle, AccessMask.GenericWrite) &&
                !Instance.WinHelper.HandleManager.CheckAccess(FileHandle, AccessMask.FileWriteData))
            {
                return false;
            }

            return true;
        }

    }
}
