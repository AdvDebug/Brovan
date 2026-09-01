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
        private const uint StillActive = 0x103;

        private static readonly List<RemoteGuestProcess> Live = new List<RemoteGuestProcess>();

        private readonly Process Host;
        private readonly BinaryEmulator Owner;

        private RemoteGuestProcess(uint ProcessId, Process Host, BinaryEmulator Owner, ulong PebAddress, ulong ProcessParameters)
        {
            this.ProcessId = ProcessId;
            this.Host = Host;
            this.Owner = Owner;
            this.PebAddress = PebAddress;
            this.ProcessParameters = ProcessParameters;
        }

        internal uint ProcessId { get; }

        internal ulong PebAddress { get; }

        internal ulong ProcessParameters { get; }

        internal uint ExitCode { get; private set; } = StillActive;

        internal bool HasExited => Exited || Refresh();

        // The exit code is stored before this flag, so a reader that sees the flag sees the code with it.
        private volatile bool Exited;

        /// <summary>
        /// Builds the handle to a guest process running in another emulator.
        /// </summary>
        /// <param name="ProcessId">Guest process id, which is what the session slots are keyed on.</param>
        /// <param name="Host">Host process of the emulator running it.</param>
        internal static RemoteGuestProcess Adopt(uint ProcessId, Process Host, BinaryEmulator Owner, ulong PebAddress, ulong ProcessParameters)
        {
            RemoteGuestProcess Process = new RemoteGuestProcess(ProcessId, Host, Owner, PebAddress, ProcessParameters);

            lock (Live)
                Live.Add(Process);

            return Process;
        }

        // Nothing else reports an exit in another emulator, so this poll is the wake site for waiting threads.
        internal static void PollLive()
        {
            RemoteGuestProcess[] Snapshot;

            lock (Live)
            {
                if (Live.Count == 0)
                    return;

                Snapshot = Live.ToArray();
            }

            foreach (RemoteGuestProcess Process in Snapshot)
                Process.Refresh();
        }

        private bool Refresh()
        {
            if (Exited)
                return true;

            // The session table costs a lock and a scan, so read it only once the host is gone.
            if (!HostHasExited())
                return false;

            ExitCode = GuestSession.TryReadExit(ProcessId, out uint Code) ? Code : HostExitCode();
            Exited = true;
            Owner?.WakeSignal.Bump();

            lock (Live)
                Live.Remove(this);

            return true;
        }

        private bool HostHasExited()
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

        private uint HostExitCode()
        {
            try
            {
                return unchecked((uint)Host.ExitCode);
            }
            catch (Exception)
            {
                return 0;
            }
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

        internal NTSTATUS QueryMemory(ulong Address, Span<byte> Destination)
        {
            if (!TryResolveSlot(out int Slot, out NTSTATUS Status))
                return Status;

            Status = GuestSessionMailbox.Send(Slot, SessionOperation.QueryMemory, Address, 0, ReadOnlySpan<byte>.Empty, Destination, out int Length, out _);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            return Length == Destination.Length ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_UNSUCCESSFUL;
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
