using Brovan.Core.Emulation.Guests;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static class RemoteProcessRequests
    {
        internal static void Drain(BinaryEmulator Instance)
        {
            while (GuestSessionRegistry.TryTakeRequest(out uint Opcode, out ulong Address, out ulong Extra, out int Length, out byte[] Input))
            {
                uint Status;
                ulong Result = 0;
                byte[] Output = null;

                try
                {
                    Status = Execute(Instance, Opcode, Address, Extra, Length, Input, out Result, out Output);
                }
                catch (Exception Ex)
                {
                    Utils.LogError($"[RemoteProcessRequests] Opcode {Opcode} failed: {Ex.Message}");
                    Status = (uint)NTSTATUS.STATUS_UNSUCCESSFUL;
                }

                GuestSessionRegistry.CompleteRequest(Status, Result, Output ?? Array.Empty<byte>());
            }
        }

        private static uint Execute(BinaryEmulator Instance, uint Opcode, ulong Address, ulong Extra, int Length, byte[] Input, out ulong Result, out byte[] Output)
        {
            Result = 0;
            Output = null;

            switch (Opcode)
            {
                case GuestSessionRegistry.OpcodeQueryPeb:
                    Result = Instance.PEB;
                    return (uint)NTSTATUS.STATUS_SUCCESS;

                case GuestSessionRegistry.OpcodeReadMemory:
                {
                    if (Length <= 0 || !Instance.IsRegionMapped(Address, (ulong)Length))
                        return (uint)NTSTATUS.STATUS_ACCESS_VIOLATION;

                    byte[] Buffer = new byte[Length];
                    if (!Instance.ReadMemory(Address, Buffer, (uint)Length))
                        return (uint)NTSTATUS.STATUS_ACCESS_VIOLATION;

                    Output = Buffer;
                    Result = (ulong)Length;
                    return (uint)NTSTATUS.STATUS_SUCCESS;
                }

                case GuestSessionRegistry.OpcodeWriteMemory:
                {
                    if (Input == null || Input.Length == 0 || !Instance.IsRegionMapped(Address, (ulong)Input.Length))
                        return (uint)NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(Address, Input))
                        return (uint)NTSTATUS.STATUS_ACCESS_VIOLATION;

                    Result = (ulong)Input.Length;
                    return (uint)NTSTATUS.STATUS_SUCCESS;
                }

                case GuestSessionRegistry.OpcodeCreateThread:
                {
                    if (Address == 0 || !Instance.IsRegionMapped(Address, 1))
                        return (uint)NTSTATUS.STATUS_INVALID_PARAMETER;

                    EmulatedThread Thread = Instance.Guest is WindowsGuest Guest
                        ? Guest.CreateEmulatedThread(Instance, Address, null, Extra, null, 8, 0, false)
                        : Instance.CreateEmulatedThread(Address, null, Extra, null);

                    if (Thread == null)
                        return (uint)NTSTATUS.STATUS_NO_MEMORY;

                    Result = Thread.ThreadId;
                    return (uint)NTSTATUS.STATUS_SUCCESS;
                }
            }

            return (uint)NTSTATUS.STATUS_NOT_SUPPORTED;
        }
    }
}
