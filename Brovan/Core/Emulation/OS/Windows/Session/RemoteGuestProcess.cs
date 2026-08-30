using System.Buffers.Binary;
using System.Diagnostics;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// A guest process living in another emulator. Nothing of its address space exists on this side, so every
    /// operation is carried out by that emulator through the session mailbox.
    /// </summary>
    public sealed class RemoteGuestProcess
    {
        private readonly Process Host;

        private RemoteGuestProcess(uint ProcessId, Process Host, ulong PebAddress, ulong ProcessParameters)
        {
            this.ProcessId = ProcessId;
            this.Host = Host;
            this.PebAddress = PebAddress;
            this.ProcessParameters = ProcessParameters;
        }

        internal uint ProcessId { get; }

        internal ulong PebAddress { get; }

        internal ulong ProcessParameters { get; }

        internal bool HasExited
        {
            get
            {
                try
                {
                    return Host.HasExited;
                }
                catch (InvalidOperationException)
                {
                    return true;
                }
            }
        }

        /// <summary>
        /// Builds the handle to a guest process running in another emulator.
        /// </summary>
        /// <param name="ProcessId">Guest process id, which is what the session slots are keyed on.</param>
        /// <param name="Host">Emulator instance hosting it.</param>
        internal static RemoteGuestProcess Adopt(uint ProcessId, Process Host, ulong PebAddress, ulong ProcessParameters)
        {
            return new RemoteGuestProcess(ProcessId, Host, PebAddress, ProcessParameters);
        }

        internal NTSTATUS ReadMemory(ulong Address, Span<byte> Destination, out int Read)
        {
            Read = 0;

            if (!TryResolveSlot(out int Slot, out NTSTATUS Status))
                return Status;

            return GuestSessionMailbox.Send(Slot, SessionOperation.ReadMemory, Address, 0, ReadOnlySpan<byte>.Empty, Destination, out Read, out _);
        }

        internal NTSTATUS WriteMemory(ulong Address, ReadOnlySpan<byte> Source, out ulong Written)
        {
            Written = 0;

            if (!TryResolveSlot(out int Slot, out NTSTATUS Status))
                return Status;

            return GuestSessionMailbox.Send(Slot, SessionOperation.WriteMemory, Address, 0, Source, Span<byte>.Empty, out _, out Written);
        }

        internal NTSTATUS AllocateMemory(ulong Address, ulong RegionSize, uint AllocationType, uint Protect, out ulong AllocatedBase, out ulong AllocatedSize)
        {
            AllocatedBase = 0;
            AllocatedSize = 0;

            if (!TryResolveSlot(out int Slot, out NTSTATUS Status))
                return Status;

            Span<byte> Request = stackalloc byte[8];
            BinaryPrimitives.WriteUInt32LittleEndian(Request, AllocationType);
            BinaryPrimitives.WriteUInt32LittleEndian(Request.Slice(4), Protect);

            Span<byte> Granted = stackalloc byte[8];
            NTSTATUS Result = GuestSessionMailbox.Send(Slot, SessionOperation.AllocateMemory, Address, RegionSize, Request, Granted, out int GrantedLength, out AllocatedBase);

            if (Result != NTSTATUS.STATUS_SUCCESS)
                return Result;

            if (GrantedLength < Granted.Length)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            AllocatedSize = BinaryPrimitives.ReadUInt64LittleEndian(Granted);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal NTSTATUS CreateThread(ulong StartRoutine, ulong Argument, out uint ThreadId)
        {
            ThreadId = 0;

            if (!TryResolveSlot(out int Slot, out NTSTATUS Status))
                return Status;

            NTSTATUS Result = GuestSessionMailbox.Send(Slot, SessionOperation.CreateThread, StartRoutine, Argument, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, out _, out ulong RemoteThreadId);
            if (Result == NTSTATUS.STATUS_SUCCESS)
                ThreadId = (uint)RemoteThreadId;

            return Result;
        }

        /// <summary>
        /// Releases a process that was created suspended, so its creator can inject before any guest code runs.
        /// </summary>
        internal NTSTATUS Resume()
        {
            if (!TryResolveSlot(out int Slot, out NTSTATUS Status))
                return Status;

            return GuestSessionMailbox.Send(Slot, SessionOperation.ResumeProcess, 0, 0, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, out _, out _);
        }

        /// <summary>
        /// Killing the host process leaves the guest no chance to shut down, so that is the fallback, not the path.
        /// </summary>
        internal NTSTATUS Terminate(uint ExitCode)
        {
            if (HasExited)
                return NTSTATUS.STATUS_SUCCESS;

            if (GuestSession.RequestTerminate(ProcessId, ExitCode))
                return NTSTATUS.STATUS_SUCCESS;

            try
            {
                Host.Kill();
                return NTSTATUS.STATUS_SUCCESS;
            }
            catch (Exception Ex)
            {
                Utils.LogError($"[RemoteGuestProcess] Failed to stop host process {ProcessId}: {Ex.Message}");
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }
        }

        private bool TryResolveSlot(out int Slot, out NTSTATUS Status)
        {
            if (GuestSession.TryFindLiveSlot(ProcessId, out Slot))
            {
                Status = NTSTATUS.STATUS_SUCCESS;
                return true;
            }

            Status = NTSTATUS.STATUS_INVALID_CID;
            return false;
        }
    }
}
