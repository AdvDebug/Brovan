using System.Collections.Generic;
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
        public ulong WaitResumeRIP { get; set; }
        public ulong WaitReturnRIP { get; set; }
        public bool WaitAlertable { get; set; }
        public bool WaitCompleted { get; set; }
        public NTSTATUS WaitStatus { get; set; }
        public List<object> WaitObjects { get; set; }
        public bool AlertByThreadIdPending { get; set; }
        public bool AlertByThreadIdWaitActive { get; set; }
        public ulong AlertByThreadIdAddress { get; set; }
        public bool MsgWaitActive { get; set; }
        public uint MsgWaitMask { get; set; }
        public bool GetMessageWaitActive { get; set; }
        public ulong GetMessageMessagePtr { get; set; }
        public ulong GetMessageHwndFilter { get; set; }
        public uint GetMessageMinMessage { get; set; }
        public uint GetMessageMaxMessage { get; set; }
        public Stack<WinUserCallbackFrame> UserCallbackFrames { get; set; } = new();
    }

    public sealed class WinUserCallbackFrame
    {
        public ulong SavedRip;
        public ulong SavedRsp;
        public ulong SavedReturnAddress;
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