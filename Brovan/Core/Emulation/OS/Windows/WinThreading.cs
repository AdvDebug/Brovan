using System.Collections.Generic;
using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Emulation.OS.Windows.WinSysHelper;

namespace Brovan.Core.Emulation.OS.Windows
{
    public sealed class WinPendingUserApc
    {
        public const uint SpecialUserApc = 0x1;

        public uint Flags;
        public ulong ApcRoutine;
        public ulong ApcArgument1;
        public ulong ApcArgument2;
        public ulong ApcArgument3;

        public bool IsSpecial => (Flags & SpecialUserApc) != 0;
    }

    public sealed class WindowsThreadState
    {
        public int ImpersonationTokenHandle { get; set; }
        public ulong Teb { get; set; }

        // The 64-bit TEB a WOW64 thread also owns. SysWOW64 modules reach it through WowTebOffset and use x64 offsets in it.
        public ulong NativeTeb { get; set; }
        public ulong InitialContext { get; set; }
        public WinToken ImpersonationToken { get; set; }
        public ulong ExceptionFunc { get; set; }
        public bool ApcAlertable { get; set; }
        public List<WinPendingUserApc> PendingUserApcs { get; set; } = new();
        public ulong ApcFunc { get; set; }
        public bool DispatchException { get; set; }
        public bool IsHandlingException { get; set; }
        public int ExceptionNesting { get; set; }
        public ulong Win32ThreadInfo { get; set; }
        public ExceptionInformation ExceptionInformation { get; set; }
        public bool WorkerFactoryWaitActive { get; set; }
        public ulong WorkerFactoryHandle { get; set; }
        public ulong WorkerFactoryMiniPackets { get; set; }
        public ulong WorkerFactoryPacketsReturned { get; set; }
        public uint WorkerFactoryMaxPackets { get; set; }
        public List<WinIoCompletionEntry> WorkerFactoryReservedEntries { get; set; } = new();
        public bool IoCompletionWaitActive { get; set; }
        public ulong IoCompletionHandle { get; set; }
        public ulong IoCompletionKeyContextPtr { get; set; }
        public ulong IoCompletionApcContextPtr { get; set; }
        public ulong IoCompletionIoStatusBlockPtr { get; set; }

        // NtRemoveIoCompletionEx writes FILE_IO_COMPLETION_INFORMATION records here instead of the three pointers above.
        public ulong IoCompletionInformationPtr { get; set; }
        public ulong IoCompletionEntriesRemovedPtr { get; set; }
        public uint IoCompletionMaxEntries { get; set; }
        public List<WinIoCompletionEntry> IoCompletionReservedEntries { get; set; } = new();

        // KTHREAD.Queue. A thread bound to a port takes its packets before it checks for a user APC.
        public WinIoCompletion BoundIoCompletion { get; set; }

        internal ParkedIoRequest IoRequest { get; set; }

        // HostWork outlives the wait. The re-run consumes it.
        internal bool HostWorkWaitActive { get; set; }
        internal Task HostWork { get; set; }

        // Kept across the retries of one syscall, which NT sees as one wait.
        internal WinPendingIo? SyncIo { get; set; }
        internal bool SyncIoCancelled { get; set; }
        internal bool SyncIoBetweenRetries { get; set; }
        internal ulong SyncIoRip { get; set; }
        internal uint SyncIoSyscall { get; set; }

        internal void ResetSyncIo()
        {
            SyncIo = null;
            SyncIoCancelled = false;
            SyncIoBetweenRetries = false;
        }
        public ulong WaitResumeRIP { get; set; }
        public ulong WaitReturnRIP { get; set; }
        public bool WaitAlertable { get; set; }
        public bool WaitCompleted { get; set; }
        public NTSTATUS WaitStatus { get; set; }
        public List<object> WaitObjects { get; set; }
        public long WaitCheckedEpoch = -1;
        public List<ulong> WaitCheckedHandles;
        public WaitableHandleObject[] WaitCheckedObjects;

        // FiledSlots[i] is this thread's index in FiledObjects[i].FiledWaiters.
        internal WaitableHandleObject[] FiledObjects;
        internal int[] FiledSlots;
        internal int FiledDeadlineIndex = -1;
        internal bool WaitFiled => FiledObjects != null;
        public bool AlertByThreadIdPending { get; set; }
        public bool AlertByThreadIdWaitActive { get; set; }
        public ulong AlertByThreadIdAddress { get; set; }
        public bool MsgWaitActive { get; set; }
        public uint MsgWaitMask { get; set; }
        public ulong ClientThreadInfo { get; set; }
        public ulong ClientFocusInfo { get; set; }
        public bool WaitMessageActive { get; set; }
        public bool GetMessageWaitActive { get; set; }
        public bool RetrySyscallActive { get; set; }
        public uint RetrySyscallNumber { get; set; }
        public ulong PipeWaitHandle { get; set; }
        public long PipeWaitDeadline { get; set; } = -1;
        public ulong GetMessageMessagePtr { get; set; }
        public ulong GetMessageHwndFilter { get; set; }
        public uint GetMessageMinMessage { get; set; }
        public uint GetMessageMaxMessage { get; set; }

        // GetMessagePos and GetMessageTime report these.
        public int LastMessageX { get; set; }
        public int LastMessageY { get; set; }
        public uint LastMessageTime { get; set; }

        public Stack<WinUserCallbackFrame> UserCallbackFrames { get; set; } = new();

        // Set by a returning WM_PAINT callback, so the re-run of its syscall knows itself apart from a
        // fresh call made inside the procedure.
        public ulong PendingPaintRetryHwnd { get; set; }

        // Increment over the process class. 16 or -16 pins it to the class edge.
        public int PriorityIncrement { get; set; }
        public int PrioritySaturation { get; set; }

        public bool HiddenFromDebugger { get; set; }
        public string Description { get; set; }
        public long CreateTime { get; set; }
        public long ExitTime { get; set; }
        public byte IdealProcessor { get; set; }

        public void ResetIoCompletionWait()
        {
            IoCompletionWaitActive = false;
            IoCompletionHandle = 0;
            IoCompletionKeyContextPtr = 0;
            IoCompletionApcContextPtr = 0;
            IoCompletionIoStatusBlockPtr = 0;
            IoCompletionInformationPtr = 0;
            IoCompletionEntriesRemovedPtr = 0;
            IoCompletionMaxEntries = 0;
            IoCompletionReservedEntries.Clear();
        }
    }

    public sealed class WinUserCallbackFrame
    {
        public ulong SavedRsp;
        public ulong SavedReturnAddress;
        public ulong SyscallRetryRip;
        public ulong PaintRetryHwnd;

        public ulong SavedSyscallNumber;
        public ulong SavedArg0;
        public ulong SavedArg1;
        public ulong SavedArg2;
        public ulong SavedArg3;

        public WinCallbackContinuation Continuation;
        public ulong? DeferredSyscallResult;
    }

    // Runs when the callback returns, on the caller's stack. True when it entered another callback.
    public abstract class WinCallbackContinuation
    {
        internal abstract bool Resume(BinaryEmulator Emulator, ref ulong Value);
    }

    public sealed class WinScrollChildMoves : WinCallbackContinuation
    {
        public readonly List<ulong> Children = new();
        public int Next;
        public int Result;
        public ulong UpdateAddress;
        public GdiClipRect UpdateRect;

        internal override bool Resume(BinaryEmulator Emulator, ref ulong Value)
        {
            if (Win32k.Win32kHelper.SendScrollChildMoves(Emulator, this))
                return true;

            Value = Win32k.Win32kHelper.FinishScrollWindow(Emulator, UpdateAddress, UpdateRect, Result);
            return false;
        }
    }

    public sealed class WinPaintBegin : WinCallbackContinuation
    {
        public ulong Hwnd;
        public ulong Hdc;
        public ulong PaintStruct;

        internal override bool Resume(BinaryEmulator Emulator, ref ulong Value)
        {
            Value = Win32k.Win32kHelper.FinishBeginPaint(Emulator, this, Value);
            return false;
        }
    }

    public sealed class WinWindowCreation : WinCallbackContinuation
    {
        public ulong Hwnd;
        public WinWindowCreationStep Step;

        internal override bool Resume(BinaryEmulator Emulator, ref ulong Value)
        {
            return Emulator.WinHelper.ContinueWindowCreation(this, Value, out Value);
        }
    }

    // One SetWindowPos or EndDeferWindowPos entry in progress. WM_WINDOWPOSCHANGING can change the request.
    public sealed class WinWindowPosChange : WinCallbackContinuation
    {
        internal Win32k.Win32kHelper.Win32kDeferredWindowPos Position;
        public ulong WindowPos;
        public bool Changed;
        internal List<Win32k.Win32kHelper.Win32kDeferredWindowPos> Batch;
        public int Next;

        internal override bool Resume(BinaryEmulator Emulator, ref ulong Value)
        {
            return Win32k.Win32kHelper.ContinueWindowPos(Emulator, this, out Value);
        }
    }

    public sealed class WinWindowDestruction : WinCallbackContinuation
    {
        public ulong Result;
        public readonly List<WinWindowDestructionStep> Steps = new();
        public readonly HashSet<ulong> Planned = new();
        public int Next;
        public ulong PendingRelease;

        internal override bool Resume(BinaryEmulator Emulator, ref ulong Value)
        {
            if (Emulator.WinHelper.RunWindowDestruction(this))
                return true;

            Value = Result;
            return false;
        }
    }

    public readonly struct WinWindowDestructionStep
    {
        public readonly ulong Hwnd;
        public readonly uint Message;
        public readonly bool Root;

        public WinWindowDestructionStep(ulong Hwnd, uint Message, bool Root)
        {
            this.Hwnd = Hwnd;
            this.Message = Message;
            this.Root = Root;
        }
    }

    public enum WinWindowCreationStep
    {
        NonClientCreate,
        Create,
        Size,
        Move,
    }

    public static class WinEmulatedThread
    {
        public static WindowsThreadState GetState(EmulatedThread Thread)
        {
            if (Thread == null)
                return null;

            WindowsThreadState State = Thread.GuestState as WindowsThreadState;
            if (State == null)
            {
                State = new WindowsThreadState();
                Thread.GuestState = State;
            }

            State.PendingUserApcs ??= new List<WinPendingUserApc>();
            return State;
        }

        public static WindowsThreadState TryGetState(EmulatedThread Thread)
        {
            return Thread?.GuestState as WindowsThreadState;
        }

        public static bool HasState(EmulatedThread Thread)
        {
            return Thread?.GuestState is WindowsThreadState;
        }

        public static bool IsAlertable(EmulatedThread Thread)
        {
            WindowsThreadState State = TryGetState(Thread);
            return State != null && State.ApcAlertable && State.PendingUserApcs != null && State.PendingUserApcs.Count > 0;
        }
    }
}

namespace Brovan.Core.Emulation
{
    using Brovan.Core.Emulation.OS.Windows;

    public partial class EmulatedThread : IHandleObject
    {
        public string ObjectId => ThreadId.ToString();
        public HandleType ObjectType => HandleType.ThreadHandle;
    }
}