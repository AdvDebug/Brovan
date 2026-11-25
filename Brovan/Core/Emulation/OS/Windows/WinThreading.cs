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

    // Abandon can run under the scheduler lock, so it only marks what it holds.
    internal interface IAbandonableWork
    {
        void Abandon();
    }

    internal enum WindowsWaitKind : byte
    {
        None,
        Timeout,
        Objects,
        MessageObjects,
        Alert,
        IoCompletion,
        WorkerFactory,
        IoRequest,
        Retry,
        HostWorkRetry,
        WaitMessage,
        GetMessage,
        SendReply,
    }

    internal static class WindowsWaitKinds
    {
        internal static bool HoldsObjects(this WindowsWaitKind Kind) => Kind is WindowsWaitKind.Objects or WindowsWaitKind.MessageObjects;

        internal static bool IsRetry(this WindowsWaitKind Kind) => Kind is WindowsWaitKind.Retry or WindowsWaitKind.HostWorkRetry;

        internal static bool TakesQueuePort(this WindowsWaitKind Kind)
            => Kind is WindowsWaitKind.WaitMessage or WindowsWaitKind.GetMessage or WindowsWaitKind.MessageObjects;

        internal static bool TakesCompletions(this WindowsWaitKind Kind) => Kind is WindowsWaitKind.WorkerFactory or WindowsWaitKind.IoCompletion;

        // NT: an object or alert wait that reaches its deadline returns STATUS_TIMEOUT, and a park on a deadline alone
        // returns success.
        internal static bool EndsWithTimeoutStatus(this WindowsWaitKind Kind) => Kind.HoldsObjects() || Kind == WindowsWaitKind.Alert;

        // Message and send-reply waits read win32k state, and an I/O request's timeout finishes the request.
        internal static bool NeedsKernelLock(this WindowsWaitKind Kind)
            => Kind is WindowsWaitKind.WaitMessage or WindowsWaitKind.GetMessage or WindowsWaitKind.MessageObjects
                or WindowsWaitKind.SendReply or WindowsWaitKind.IoRequest;
    }

    public sealed class WindowsThreadState
    {
        public int ImpersonationTokenHandle { get; set; }
        public ulong Teb { get; set; }

        // The 64-bit TEB a WOW64 thread also owns. SysWOW64 modules reach it through WowTebOffset and use x64 offsets in it.
        public ulong NativeTeb { get; set; }

        // NT enters LdrInitializeThunk when the thread first runs (PspInitializeThunkContext).
        public bool LoaderThunkPending { get; set; }
        public WinToken ImpersonationToken { get; set; }
        public ulong ExceptionFunc { get; set; }
        public bool ApcAlertable { get; set; }
        public List<WinPendingUserApc> PendingUserApcs { get; set; } = new();
        public ulong ApcFunc { get; set; }
        public bool DispatchException { get; set; }

        // NT holds a written context in the trap frame until the thread runs.
        public bool EFlagsFromContext { get; set; }
        public bool DebugRegistersFromContext { get; set; }

        // WOW64 reads a CPU area context back as written until the thread runs.
        public ulong? Wow64EFlags { get; set; }
        public bool Wow64DebugRegistersHeld { get; set; }

        // Kept after the thread runs so the next write can reuse it.
        public ulong[]? Wow64DebugRegisters { get; set; }

        public void ReleaseHeldContext()
        {
            EFlagsFromContext = false;
            DebugRegistersFromContext = false;
            Wow64EFlags = null;
            Wow64DebugRegistersHeld = false;
        }

        public ulong Win32ThreadInfo { get; set; }
        public ExceptionInformation ExceptionInformation { get; set; }
        public WinWorkerFactory WorkerFactory { get; set; }
        public ulong WorkerFactoryMiniPackets { get; set; }
        public ulong WorkerFactoryPacketsReturned { get; set; }
        public uint WorkerFactoryMaxPackets { get; set; }
        public List<WinIoCompletionEntry> WorkerFactoryReservedEntries { get; set; } = new();
        public WinIoCompletion IoCompletion { get; set; }
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
        internal Task HostWork { get; set; }

        // Work the re-run never took. Its owner, the task's AsyncState, lets go of what it holds.
        internal void DropHostWork()
        {
            Task Work = HostWork;
            HostWork = null;
            if (Work?.AsyncState is IAbandonableWork Owner)
                Owner.Abandon();
        }

        // Kept across the retries of one syscall, which NT sees as one wait.
        internal WinPendingIo? SyncIo { get; set; }
        internal bool SyncIoCancelled { get; set; }
        internal bool SyncIoBetweenRetries { get; set; }
        internal bool SyncIoRerun { get; set; }
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
        internal WindowsWaitKind WaitKind { get; private set; }

        // NT: a wait holds the objects its handles named at entry.
        internal WaitEntry[] WaitObjects = Array.Empty<WaitEntry>();
        internal int WaitObjectCount;
        public long WaitCheckedEpoch = -1;
        public long WaitCheckedGeneration = -1;
        internal bool WaitCheckedFileable;

        // FiledSlots[i] is this thread's index in FiledObjects[i].FiledWaiters.
        internal WaitableHandleObject[] FiledObjects = Array.Empty<WaitableHandleObject>();
        internal int FiledCount;
        internal long FiledGeneration;
        internal int[] FiledSlots;
        internal int FiledDeadlineIndex = -1;
        internal bool WaitFiled => FiledCount != 0;

        internal ThreadEndObject EndObject;

        internal void AddWaitObject(IHandleObject Object, WaitableHandleObject Waitable)
        {
            if (WaitObjectCount == WaitObjects.Length)
                Array.Resize(ref WaitObjects, Math.Max(4, WaitObjectCount * 2));

            WaitObjects[WaitObjectCount++] = new WaitEntry { Object = Object, Waitable = Waitable };
        }

        internal void StartWait(WindowsWaitKind Kind)
        {
            if (!Kind.HoldsObjects())
                ClearWaitObjects();
            ObjectsNeedKernelLock = Kind == WindowsWaitKind.Objects && HasObjectCheckedUnderKernelLock();
            WaitKind = Kind;
        }

        internal bool ObjectsNeedKernelLock { get; private set; }

        internal bool WaitNeedsKernelLock => WaitKind.NeedsKernelLock() || ObjectsNeedKernelLock;

        // An object with no wait object, or a port or worker factory whose packets can target one.
        internal bool HasObjectCheckedUnderKernelLock()
        {
            for (int i = 0; i < WaitObjectCount; i++)
            {
                if (WaitObjects[i].Waitable is null or WinIoCompletion or WinWorkerFactory)
                    return true;
            }

            return false;
        }

        // Data that outlives a wait stays with its owner: HostWork, the sync I/O and pipe retry state,
        // AlertByThreadIdPending and PendingSends.
        internal void EndWait()
        {
            switch (WaitKind)
            {
                case WindowsWaitKind.WorkerFactory:
                    WorkerFactory = null;
                    WorkerFactoryMiniPackets = 0;
                    WorkerFactoryPacketsReturned = 0;
                    WorkerFactoryMaxPackets = 0;
                    WorkerFactoryReservedEntries?.Clear();
                    break;

                case WindowsWaitKind.IoCompletion:
                    ResetIoCompletionWait();
                    break;

                case WindowsWaitKind.IoRequest:
                    IoRequest = null;
                    break;

                case WindowsWaitKind.Retry:
                case WindowsWaitKind.HostWorkRetry:
                case WindowsWaitKind.GetMessage:
                    RetrySyscallNumber = 0;
                    break;

                case WindowsWaitKind.MessageObjects:
                    MsgWaitMask = 0;
                    break;

                case WindowsWaitKind.Alert:
                    AlertByThreadIdAddress = 0;
                    break;
            }

            ClearWaitObjects();
            WaitKind = WindowsWaitKind.None;
            ObjectsNeedKernelLock = false;
            WaitResumeRIP = 0;
            WaitReturnRIP = 0;
            WaitAlertable = false;
            ApcAlertable = false;
        }

        // Called by the scan. Each change goes to a kind that needs no more than the scheduler lock.
        internal void ChangeKindInScan(WindowsWaitKind To)
        {
            bool Allowed = To == WindowsWaitKind.Retry
                ? WaitKind is WindowsWaitKind.SendReply or WindowsWaitKind.GetMessage
                : To == WindowsWaitKind.None && WaitKind is WindowsWaitKind.WaitMessage or WindowsWaitKind.GetMessage;
            if (!Allowed && RankedLock.OrderChecked)
                Environment.FailFast($"[WaitKind] A scan changed a {WaitKind} wait into {To}.");

            WaitKind = To;
        }

        internal void ClearWaitObjects()
        {
            Array.Clear(WaitObjects, 0, WaitObjectCount);
            WaitObjectCount = 0;
        }
        public bool AlertByThreadIdPending { get; set; }
        public ulong AlertByThreadIdAddress { get; set; }
        public uint MsgWaitMask { get; set; }
        public long MsgWaitTimeout { get; set; } = -1;
        internal WinIoCompletion QueuePort;
        internal ulong QueuePortHandle;
        internal ulong[] CoreMessagingWindows;
        public ulong ClientThreadInfo { get; set; }
        public ulong ClientFocusInfo { get; set; }

        // Innermost last. The rerun of a send finds its record by callback depth.
        internal List<WinSentMessageReply> PendingSends { get; set; }
        internal WinSentMessageReply InnermostSend => PendingSends is { Count: > 0 } Sends ? Sends[^1] : null;
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

        // An absolute base priority that overrides the class rules (KeSetActualBasePriorityThread). 0 means none.
        public int ActualBasePriority { get; set; }

        internal MmThreadClient MmcssRegistration { get; set; }

        public bool HiddenFromDebugger { get; set; }
        public string Description { get; set; }
        public long CreateTime { get; set; }
        public long ExitTime { get; set; }
        public byte IdealProcessor { get; set; }

        public void ResetIoCompletionWait()
        {
            IoCompletion = null;
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

        // WOW64 restores the whole x86 context and the exception list after a callback.
        public ulong[] SavedRegisters32;
        public uint SavedExceptionList;

        public WinCallbackContinuation Continuation;
        public ulong? DeferredSyscallResult;

        internal WinSentMessageReply ReceivedSend;
    }

    internal sealed class WinSentMessageReply
    {
        internal readonly EmulatedThread Sender;
        internal readonly int Depth;
        internal readonly ulong Hwnd;
        internal readonly uint Message;
        internal readonly bool Ansi;
        internal ulong Result;
        internal bool Replied;

        internal WinSentMessageReply(EmulatedThread Sender, int Depth, ulong Hwnd, uint Message, bool Ansi)
        {
            this.Sender = Sender;
            this.Depth = Depth;
            this.Hwnd = Hwnd;
            this.Message = Message;
            this.Ansi = Ansi;
        }

        // A terminated sender keeps its stack until this runs.
        internal void EndDelivery(BinaryEmulator Emulator, ulong Value)
        {
            if (Replied)
                return;

            Result = Value;
            Replied = true;
            Emulator.WakeSignal.Bump();
            if (Sender.State == EmulatedThreadState.Terminated)
                Emulator.WinHelper.ReleaseThreadStack(Sender);
        }
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

    public sealed class WinSendMessageCallback : WinCallbackContinuation
    {
        public ulong Hwnd;
        public uint Message;
        public ulong Callback;
        public ulong Data;

        internal override bool Resume(BinaryEmulator Emulator, ref ulong Value)
        {
            return Win32k.Win32kHelper.InvokeWindowProc(Emulator, Hwnd, Callback, Message, Data, Value, DeferredSyscallResult: 1);
        }
    }

    internal sealed class WinPostedMessageRead : WinCallbackContinuation
    {
        private readonly ulong MessagePtr;
        private readonly Win32k.Win32kMessage Message;
        private readonly WindowsThreadState Reader;

        internal WinPostedMessageRead(ulong MessagePtr, in Win32k.Win32kMessage Message, WindowsThreadState Reader)
        {
            this.MessagePtr = MessagePtr;
            this.Message = Message;
            this.Reader = Reader;
        }

        internal override bool Resume(BinaryEmulator Emulator, ref ulong Value)
        {
            if (!Win32k.Win32kHelper.WriteMessage(Emulator, MessagePtr, Message, Reader))
                Brovan.Core.Helpers.Utils.LogError($"[-] win32k: the message buffer at 0x{MessagePtr:X} could not take its message after the window procedure ran.");
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
        public uint ExitingThreadId;
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
            State.EndObject ??= new ThreadEndObject(Thread);
            return State;
        }

        public static WindowsThreadState TryGetState(EmulatedThread Thread)
        {
            return Thread?.GuestState as WindowsThreadState;
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