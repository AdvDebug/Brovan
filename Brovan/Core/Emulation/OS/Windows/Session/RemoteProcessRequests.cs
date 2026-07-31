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
            while (GuestSessionMailbox.TryReceive(out SessionOperation Operation, out ulong Address, out ulong Argument, out int Length, out byte[] Input))
            {
                NTSTATUS Status;
                ulong Result = 0;
                byte[] Output = null;

                try
                {
                    Status = Execute(Instance, Operation, Address, Argument, Length, Input, out Result, out Output);
                }
                catch (Exception Ex)
                {
                    Utils.LogError($"[RemoteProcessRequests] {Operation} failed: {Ex.Message}");
                    Status = NTSTATUS.STATUS_UNSUCCESSFUL;
                }

                GuestSessionMailbox.Complete(Status, Result, Output ?? Array.Empty<byte>());
            }
        }

        private static NTSTATUS Execute(
            BinaryEmulator Instance,
            SessionOperation Operation,
            ulong Address,
            ulong Argument,
            int Length,
            byte[] Input,
            out ulong Result,
            out byte[] Output)
        {
            Result = 0;
            Output = null;

            switch (Operation)
            {
                case SessionOperation.ReadMemory:
                {
                    if (Length <= 0 || !Instance.IsRegionMapped(Address, (ulong)Length))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    byte[] Buffer = new byte[Length];
                    if (!Instance.ReadMemory(Address, Buffer, (uint)Length))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    Output = Buffer;
                    Result = (ulong)Length;
                    return NTSTATUS.STATUS_SUCCESS;
                }

                case SessionOperation.WriteMemory:
                {
                    if (Input == null || Input.Length == 0 || !Instance.IsRegionMapped(Address, (ulong)Input.Length))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(Address, Input))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    Result = (ulong)Input.Length;
                    return NTSTATUS.STATUS_SUCCESS;
                }

                case SessionOperation.AllocateMemory:
                {
                    if (Input == null || Input.Length < 8)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    ulong BaseAddress = Address;
                    ulong RegionSize = Argument;

                    NTSTATUS Status = NtAllocateVirtualMemory.Allocate(
                        Instance,
                        ref BaseAddress,
                        ref RegionSize,
                        BinaryPrimitives.ReadUInt32LittleEndian(Input),
                        BinaryPrimitives.ReadUInt32LittleEndian(Input.AsSpan(4)));

                    if (Status != NTSTATUS.STATUS_SUCCESS)
                        return Status;

                    Output = new byte[8];
                    BinaryPrimitives.WriteUInt64LittleEndian(Output, RegionSize);
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

                    Result = Thread.ThreadId;
                    return NTSTATUS.STATUS_SUCCESS;
                }
            }

            return NTSTATUS.STATUS_NOT_SUPPORTED;
        }
    }
}
