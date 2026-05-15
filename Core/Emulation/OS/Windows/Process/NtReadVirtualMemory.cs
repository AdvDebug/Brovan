using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Transactions;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtReadVirtualMemory : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
                ulong BaseAddressPtr = Instance.WinHelper.GetArg64(1);
                ulong BufferPtr = Instance.WinHelper.GetArg64(2);
                ulong NumberOfBytesToRead = Instance.WinHelper.GetArg64(3);
            current_process:
                if (ProcessHandle == ulong.MaxValue)
                {
                    if (BaseAddressPtr == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (!Instance.IsRegionMapped(BaseAddressPtr, sizeof(ulong)))
                        return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

                    if (BufferPtr == 0 || !Instance.IsRegionMapped(BufferPtr, sizeof(ulong)))
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (NumberOfBytesToRead == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    ulong BaseAddress = Instance.ReadMemoryULong(BaseAddressPtr);
                    ulong Buffer = Instance.ReadMemoryULong(BufferPtr);

                    if (BaseAddress == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (Instance.IsRegionFreed(BaseAddress, true))
                        return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

                    if (!Instance.IsRegionMapped(BaseAddress, NumberOfBytesToRead))
                        return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

                    if (Buffer == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (Instance.IsRegionFreed(Buffer, true))
                    {
                        Instance.TriggerEventMessage($"[!!] Tried reading from a freed buffer at 0x{Buffer:X} while using NtReadVirtualMemory.", LogFlags.Issues);
                        return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;
                    }

                    if (!Instance.IsRegionMapped(Buffer, NumberOfBytesToRead))
                        return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

                    byte[] value = Instance.ReadMemory(BaseAddress, (uint)NumberOfBytesToRead);
                    if (value.Length == 0)
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance.WriteMemory(Buffer, value))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    return NTSTATUS.STATUS_SUCCESS;
                }
                else
                {
                    if (!Instance.WinHelper.HandleExists(ProcessHandle))
                        return NTSTATUS.STATUS_INVALID_HANDLE;

                    WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessVMOperation | AccessMask.ProcessVMRead);
                    if (Process == null)
                        return NTSTATUS.STATUS_ACCESS_DENIED;

                    if (Process.PID == Instance.WinHelper.PID)
                    {
                        ProcessHandle = ulong.MaxValue;
                        goto current_process; // jump to the current process handling
                    }

                    if (BaseAddressPtr == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (!Instance.IsRegionMapped(BaseAddressPtr, sizeof(ulong)))
                        return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

                    if (BufferPtr == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if(NumberOfBytesToRead == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (!Instance.WriteMemory(BufferPtr, Instance.WinHelper.GenerateRandomData((int)NumberOfBytesToRead))) // generate random data?
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    Instance.TriggerEventMessage($"[+] The emulated process tried to read the memory of process \"{Process.Name}\", random data was generated for it.", LogFlags.Syscall);
                    return NTSTATUS.STATUS_SUCCESS;
                }
            }
            else if (Instance._binary.Architecture == BinaryArchitecture.x86)
            {

            }
            return Instance.WinUnimplemented;
        }
    }
}