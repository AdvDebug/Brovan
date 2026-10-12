using System.Buffers.Binary;
using Brovan.Core.Emulation.Guests;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// Serves what other members ask this one to run in its own address space. Driven from the scheduler, so a
    /// request lands between thread slices rather than inside one.
    /// </summary>
    internal static class RemoteProcessRequests
    {
        internal static void Drain(BinaryEmulator Instance)
        {
            while (GuestSessionMailbox.TryReceive(out SessionOperation Operation, out ulong Address, out ulong Argument, out int Length, out Span<byte> Payload))
            {
                NTSTATUS Status;
                ulong Result = 0;
                int OutputLength = 0;

                try
                {
                    Status = Execute(Instance, Operation, Address, Argument, Length, Payload.Slice(0, Length), Payload, out Result, out OutputLength);
                }
                catch (Exception Ex)
                {
                    Utils.LogError($"[RemoteProcessRequests] {Operation} failed: {Ex.Message}");
                    Status = NTSTATUS.STATUS_UNSUCCESSFUL;
                }

                GuestSessionMailbox.Complete(Status, Result, OutputLength);
            }
        }

        /// <param name="Input">Shares memory with <paramref name="Output"/>. Read all of it before writing Output.</param>
        private static NTSTATUS Execute(
            BinaryEmulator Instance,
            SessionOperation Operation,
            ulong Address,
            ulong Argument,
            int Length,
            ReadOnlySpan<byte> Input,
            Span<byte> Output,
            out ulong Result,
            out int OutputLength)
        {
            Result = 0;
            OutputLength = 0;

            switch (Operation)
            {
                // One NtReadVirtualMemory source chunk, copied whole or not at all.
                case SessionOperation.ReadMemory:
                {
                    if (Length <= 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (Instance.AccessibleLength(Address, (ulong)Length, false) < (ulong)Length)
                        return NTSTATUS.STATUS_PARTIAL_COPY;

                    if (!Instance.ReadMemory(Address, Output.Slice(0, Length)))
                        return NTSTATUS.STATUS_PARTIAL_COPY;

                    OutputLength = Length;
                    Result = (ulong)Length;
                    return NTSTATUS.STATUS_SUCCESS;
                }

                case SessionOperation.WriteMemory:
                {
                    if (Input.IsEmpty)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    ulong Writable = Instance.AccessibleLength(Address, (ulong)Input.Length, true);
                    if (Writable != 0 && !Instance._emulator.WriteMemory(Address, Input.Slice(0, (int)Writable)))
                        return NTSTATUS.STATUS_PARTIAL_COPY;

                    Result = Writable;
                    return Writable < (ulong)Input.Length ? NTSTATUS.STATUS_PARTIAL_COPY : NTSTATUS.STATUS_SUCCESS;
                }

                case SessionOperation.QueryMemory:
                {
                    NTSTATUS Status = NtQueryVirtualMemory.BuildBasicInformation(Instance, Address, out MEMORY_BASIC_INFORMATION Info);
                    if (Status != NTSTATUS.STATUS_SUCCESS)
                        return Status;

                    OutputLength = NtQueryVirtualMemory.CanonicalBasicInformationBytes;
                    Output.Slice(0, OutputLength).Clear();
                    NtQueryVirtualMemory.Serialize(Info, true, Output.Slice(0, OutputLength));
                    return NTSTATUS.STATUS_SUCCESS;
                }

                case SessionOperation.AllocateMemory:
                {
                    if (Input.Length < 32)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    ulong BaseAddress = Address;
                    ulong RegionSize = Argument;

                    NtAllocateVirtualMemory.AddressRequirements Requirements = new NtAllocateVirtualMemory.AddressRequirements
                    {
                        Lowest = BinaryPrimitives.ReadUInt64LittleEndian(Input.Slice(8)),
                        Highest = BinaryPrimitives.ReadUInt64LittleEndian(Input.Slice(16)),
                        Alignment = BinaryPrimitives.ReadUInt64LittleEndian(Input.Slice(24)),
                    };

                    NTSTATUS Status = NtAllocateVirtualMemory.Allocate(
                        Instance,
                        ref BaseAddress,
                        ref RegionSize,
                        BinaryPrimitives.ReadUInt32LittleEndian(Input),
                        BinaryPrimitives.ReadUInt32LittleEndian(Input.Slice(4)),
                        Requirements);

                    if (Status != NTSTATUS.STATUS_SUCCESS)
                        return Status;

                    OutputLength = sizeof(ulong);
                    BinaryPrimitives.WriteUInt64LittleEndian(Output, RegionSize);
                    Result = BaseAddress;
                    return NTSTATUS.STATUS_SUCCESS;
                }

                case SessionOperation.FreeMemory:
                {
                    if (Input.Length < 4)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    ulong BaseAddress = Address;
                    ulong RegionSize = Argument;

                    NTSTATUS Status = NtFreeVirtualMemory.Free(Instance, ref BaseAddress, ref RegionSize, BinaryPrimitives.ReadUInt32LittleEndian(Input));
                    if (Status != NTSTATUS.STATUS_SUCCESS)
                        return Status;

                    OutputLength = sizeof(ulong);
                    BinaryPrimitives.WriteUInt64LittleEndian(Output, RegionSize);
                    Result = BaseAddress;
                    return NTSTATUS.STATUS_SUCCESS;
                }

                case SessionOperation.ProtectMemory:
                {
                    if (Input.Length < 4)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    ulong BaseAddress = Address;
                    ulong RegionSize = Argument;

                    NTSTATUS Status = NtProtectVirtualMemory.Protect(Instance, ref BaseAddress, ref RegionSize, BinaryPrimitives.ReadUInt32LittleEndian(Input), out uint OldProtect);
                    if (Status != NTSTATUS.STATUS_SUCCESS)
                        return Status;

                    OutputLength = sizeof(ulong) + sizeof(uint);
                    BinaryPrimitives.WriteUInt64LittleEndian(Output, RegionSize);
                    BinaryPrimitives.WriteUInt32LittleEndian(Output.Slice(8), OldProtect);
                    Result = BaseAddress;
                    return NTSTATUS.STATUS_SUCCESS;
                }

                case SessionOperation.CreateThread:
                {
                    if (Address == 0 || !Instance.IsRegionMapped(Address, 1))
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    EmulatedThread Thread = Instance.Guest is WindowsGuest Guest
                        ? Guest.CreateEmulatedThread(Instance, Address, null, Argument, null, 8, 0, false)
                        : Instance.CreateEmulatedThread(Address, null, Argument, null);

                    if (Thread == null)
                        return NTSTATUS.STATUS_NO_MEMORY;

                    Instance.WinHelper?.ApplyThreadBasePriority(Thread);
                    Result = Thread.ThreadId;
                    return NTSTATUS.STATUS_SUCCESS;
                }

                case SessionOperation.ResumeProcess:
                {
                    Instance.ResumeSuspendedStart();
                    return NTSTATUS.STATUS_SUCCESS;
                }
            }

            return NTSTATUS.STATUS_NOT_SUPPORTED;
        }
    }
}
