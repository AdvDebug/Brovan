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
            {
                ulong ProcessHandle = Instance.WinHelper.GetArg(0);
                ulong BaseAddressPtr = Instance.WinHelper.GetArg(1);
                ulong BufferPtr = Instance.WinHelper.GetArg(2);
                ulong NumberOfBytesToRead = Instance.WinHelper.GetArg(3);
            current_process:
                if (HandleManager.IsCurrentProcessPseudoHandle(ProcessHandle))
                {
                    if (BaseAddressPtr == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (!Instance.IsRegionMapped(BaseAddressPtr, sizeof(ulong)))
                        return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

                    if (BufferPtr == 0 || !Instance.IsRegionMapped(BufferPtr, sizeof(ulong)))
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (NumberOfBytesToRead == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    ulong BaseAddress = Instance.WinHelper.ReadPointer(BaseAddressPtr);
                    ulong Buffer = Instance.WinHelper.ReadPointer(BufferPtr);

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
                        if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
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

                    ulong RemoteAddress = BaseAddressPtr;
                    ulong LocalBuffer = BufferPtr;
                    ulong BytesReadPtr = Instance.WinHelper.GetArg(4);

                    if (RemoteAddress == 0 || LocalBuffer == 0 || NumberOfBytesToRead == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (NumberOfBytesToRead > GuestSessionRegistry.MaxPayloadBytes)
                        NumberOfBytesToRead = GuestSessionRegistry.MaxPayloadBytes;

                    if (!Instance.IsRegionMapped(LocalBuffer, NumberOfBytesToRead))
                        return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

                    byte[] Remote = new byte[NumberOfBytesToRead];
                    NTSTATUS RemoteStatus = GuestSessionRegistry.SendRequest(
                        Process.PID,
                        GuestSessionRegistry.OpcodeReadMemory,
                        RemoteAddress,
                        0,
                        ReadOnlySpan<byte>.Empty,
                        Remote,
                        out int RemoteLength,
                        out _);

                    if (RemoteStatus != NTSTATUS.STATUS_SUCCESS)
                        return RemoteStatus;

                    if (!Instance._emulator.WriteMemory(LocalBuffer, Remote, 0, RemoteLength))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (BytesReadPtr != 0 && Instance.IsRegionMapped(BytesReadPtr, sizeof(ulong)))
                        Instance._emulator.WriteMemory(BytesReadPtr, (ulong)RemoteLength, 8);

                    if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                        Instance.TriggerEventMessage($"[+] Read 0x{RemoteLength:X} bytes from process \"{Process.Name}\" at 0x{RemoteAddress:X}.", LogFlags.Syscall);
                    return NTSTATUS.STATUS_SUCCESS;
                }
            }
            return Instance.WinUnimplemented;
        }
    }
}