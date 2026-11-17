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
        private const int ProbeIntervalMilliseconds = 50;

        private static readonly List<RemoteGuestProcess> Live = new List<RemoteGuestProcess>();

        private readonly Process Host;
        private readonly DateTime? HostStart;
        private readonly BinaryEmulator Owner;

        private RemoteGuestProcess(uint ProcessId, Process Host, BinaryEmulator Owner, ulong PebAddress, ulong ProcessParameters)
        {
            this.ProcessId = ProcessId;
            this.Host = Host;
            this.Owner = Owner;
            this.PebAddress = PebAddress;
            this.ProcessParameters = ProcessParameters;
            HostStart = ReadStartTime(Host);
        }

        private static DateTime? ReadStartTime(Process Host)
        {
            if (Host == null)
                return null;

            try
            {
                Host.Refresh();
                return Host.StartTime;
            }
            catch (Exception Error) when (Error is InvalidOperationException || Error is System.ComponentModel.Win32Exception || Error is NotSupportedException)
            {
                return null;
            }
        }

        internal uint ProcessId { get; }

        internal ulong PebAddress { get; }

        internal ulong ProcessParameters { get; }

        internal uint ExitCode { get; private set; } = StillActive;

        internal bool HasExited => Exited || Refresh();

        // The exit code is stored before this flag, so a reader that sees the flag sees the code with it.
        private volatile bool Exited;

        private long NextProbeTick;

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

        // A wait scan asks on every pass and the table costs a lock and a scan. The watcher poll turns a
        // stale answer into a wake.
        private bool Refresh()
        {
            if (Exited)
                return true;

            long Now = Environment.TickCount64;
            if (Now < NextProbeTick)
                return false;

            NextProbeTick = Now + ProbeIntervalMilliseconds;

            if (GuestSession.TryFindLiveSlot(ProcessId, out _))
                return false;

            // A lookup that could not take the session lock finds no slot either.
            if (!GuestSession.TryReadExit(ProcessId, out uint Code) && !TryReadHostExit(out Code))
                return false;

            ExitCode = Code;
            Exited = true;
            Owner?.WakeSignal.Bump();

            lock (Live)
                Live.Remove(this);

            return true;
        }

        private bool TryReadHostExit(out uint Code)
        {
            Code = 0;
            if (Host == null)
                return true;

            try
            {
                if (!Host.HasExited)
                    return false;

                Code = unchecked((uint)Host.ExitCode);
                return true;
            }
            catch (Exception Error) when (Error is InvalidOperationException || Error is NotSupportedException || Error is System.ComponentModel.Win32Exception)
            {
                return true;
            }
        }

        internal NTSTATUS ReadMemory(ulong Address, Span<byte> Destination, out int Read)
        {
            Read = 0;

            return Call(SessionOperation.ReadMemory, Address, 0, ReadOnlySpan<byte>.Empty, Destination, out Read, out _);
        }

        internal NTSTATUS WriteMemory(ulong Address, ReadOnlySpan<byte> Source, out ulong Written)
        {
            Written = 0;

            return Call(SessionOperation.WriteMemory, Address, 0, Source, Span<byte>.Empty, out _, out Written);
        }

        internal NTSTATUS QueryMemory(ulong Address, Span<byte> Destination)
        {
            NTSTATUS Status = Call(SessionOperation.QueryMemory, Address, 0, ReadOnlySpan<byte>.Empty, Destination, out int Length, out _);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            return Length == Destination.Length ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_UNSUCCESSFUL;
        }

        internal NTSTATUS AllocateMemory(ulong Address, ulong RegionSize, uint AllocationType, uint Protect, NtAllocateVirtualMemory.AddressRequirements Requirements, out ulong AllocatedBase, out ulong AllocatedSize)
        {
            AllocatedBase = 0;
            AllocatedSize = 0;

            Span<byte> Request = stackalloc byte[32];
            BinaryPrimitives.WriteUInt32LittleEndian(Request, AllocationType);
            BinaryPrimitives.WriteUInt32LittleEndian(Request.Slice(4), Protect);
            BinaryPrimitives.WriteUInt64LittleEndian(Request.Slice(8), Requirements.Lowest);
            BinaryPrimitives.WriteUInt64LittleEndian(Request.Slice(16), Requirements.Highest);
            BinaryPrimitives.WriteUInt64LittleEndian(Request.Slice(24), Requirements.Alignment);

            Span<byte> Granted = stackalloc byte[8];
            NTSTATUS Result = Call(SessionOperation.AllocateMemory, Address, RegionSize, Request, Granted, out int GrantedLength, out AllocatedBase);

            if (Result != NTSTATUS.STATUS_SUCCESS)
                return Result;

            if (GrantedLength < Granted.Length)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            AllocatedSize = BinaryPrimitives.ReadUInt64LittleEndian(Granted);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal NTSTATUS FreeMemory(ulong Address, ulong RegionSize, uint FreeType, out ulong FreedBase, out ulong FreedSize)
        {
            FreedBase = 0;
            FreedSize = 0;

            Span<byte> Request = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(Request, FreeType);

            Span<byte> Freed = stackalloc byte[8];
            NTSTATUS Result = Call(SessionOperation.FreeMemory, Address, RegionSize, Request, Freed, out int FreedLength, out FreedBase);
            if (Result != NTSTATUS.STATUS_SUCCESS)
                return Result;

            if (FreedLength < Freed.Length)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            FreedSize = BinaryPrimitives.ReadUInt64LittleEndian(Freed);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal NTSTATUS ProtectMemory(ulong Address, ulong RegionSize, uint NewProtect, out ulong ProtectedBase, out ulong ProtectedSize, out uint OldProtect)
        {
            ProtectedBase = 0;
            ProtectedSize = 0;
            OldProtect = 0;

            Span<byte> Request = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(Request, NewProtect);

            Span<byte> Changed = stackalloc byte[12];
            NTSTATUS Result = Call(SessionOperation.ProtectMemory, Address, RegionSize, Request, Changed, out int ChangedLength, out ProtectedBase);
            if (Result != NTSTATUS.STATUS_SUCCESS)
                return Result;

            if (ChangedLength < Changed.Length)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            ProtectedSize = BinaryPrimitives.ReadUInt64LittleEndian(Changed);
            OldProtect = BinaryPrimitives.ReadUInt32LittleEndian(Changed.Slice(8));
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal NTSTATUS CreateThread(ulong StartRoutine, ulong Argument, out uint ThreadId)
        {
            ThreadId = 0;

            NTSTATUS Result = Call(SessionOperation.CreateThread, StartRoutine, Argument, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, out _, out ulong RemoteThreadId);
            if (Result == NTSTATUS.STATUS_SUCCESS)
                ThreadId = (uint)RemoteThreadId;

            return Result;
        }

        /// <summary>
        /// Releases a process that was created suspended, so its creator can inject before any guest code runs.
        /// </summary>
        internal NTSTATUS Resume()
        {
            return Call(SessionOperation.ResumeProcess, 0, 0, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, out _, out _);
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

            if (Host == null || HostStart == null || ReadStartTime(Host) != HostStart)
                return NTSTATUS.STATUS_INVALID_CID;

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

        private NTSTATUS Call(SessionOperation Operation, ulong Address, ulong Argument, ReadOnlySpan<byte> Input, Span<byte> Output, out int OutputLength,
            out ulong Result)
        {
            OutputLength = 0;
            Result = 0;

            if (!GuestSession.TryFindLiveSlot(ProcessId, out int Slot))
                return NTSTATUS.STATUS_INVALID_CID;

            MailboxOutcome Outcome = RemoteCalls.Send(Owner, this, Slot, Operation, Address, Argument, Input, Output, out NTSTATUS Status, out OutputLength,
                out Result);
            return StatusOf(Outcome, Status);
        }

        internal static NTSTATUS StatusOf(MailboxOutcome Outcome, NTSTATUS Answered) => Outcome switch
        {
            MailboxOutcome.Answered => Answered,
            MailboxOutcome.TooLarge => NTSTATUS.STATUS_INVALID_PARAMETER,
            MailboxOutcome.TargetGone => NTSTATUS.STATUS_INVALID_CID,
            MailboxOutcome.TimedOut => NTSTATUS.STATUS_IO_TIMEOUT,
            _ => NTSTATUS.STATUS_NOT_SUPPORTED,
        };
    }
}
