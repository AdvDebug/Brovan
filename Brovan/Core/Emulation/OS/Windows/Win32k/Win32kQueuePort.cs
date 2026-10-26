using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal static class Win32kQueuePort
    {
        // NT: win32k posts this to a CoreMessaging window when its list of completed waits stops being empty.
        internal const uint DispatchMessage = 0x60;
        private const ulong DispatchWParam = 1;
        internal const int SlotCount = 2;
        private const ulong InputContext = 0x80000000;

        internal static void EnsurePort(BinaryEmulator Instance, WindowsThreadState State)
        {
            if (State.QueuePort != null)
                return;

            State.QueuePort = new WinIoCompletion { Name = Instance.WinHelper.GenerateAnonymousObjectName("IoCompletion_") };
            State.QueuePortHandle = Instance.WinHelper.OpenObjectHandle(State.QueuePort, AccessMask.IoCompletionAllAccess, ObjectHandleFlags.ProtectFromClose).Handle;
            State.CoreMessagingWindows = new ulong[SlotCount];
        }

        internal static void ReleasePort(BinaryEmulator Instance, WindowsThreadState State)
        {
            if (State?.QueuePort == null)
                return;

            Instance.WinHelper.CloseHandle(State.QueuePortHandle);
            State.QueuePort = null;
            State.QueuePortHandle = 0;
            State.CoreMessagingWindows = null;
        }

        internal static void ForgetWindow(BinaryEmulator Instance, WinWindow Window)
        {
            if (!Instance.TryGetThread(Window.OwnerThreadId, out EmulatedThread Owner))
                return;

            ulong[] Windows = WinEmulatedThread.TryGetState(Owner)?.CoreMessagingWindows;
            if (Windows == null)
                return;

            for (int i = 0; i < Windows.Length; i++)
            {
                if (Windows[i] == Window.Hwnd)
                    Windows[i] = 0;
            }
        }

        internal static bool HasCoreMessagingWindow(WindowsThreadState State)
        {
            ulong[] Windows = State?.CoreMessagingWindows;
            if (Windows == null)
                return false;

            for (int i = 0; i < Windows.Length; i++)
            {
                if (Windows[i] != 0)
                    return true;
            }

            return false;
        }

        internal static int GetSlot(WindowsThreadState State, ulong Hwnd)
        {
            ulong[] Windows = State?.CoreMessagingWindows;
            if (Windows == null || Hwnd == 0)
                return -1;

            for (int i = 0; i < Windows.Length; i++)
            {
                if (Windows[i] == Hwnd)
                    return i;
            }

            return -1;
        }

        internal static bool TryEndMsgWait(BinaryEmulator Instance, EmulatedThread Thread, WindowsThreadState State, uint WakeMask)
        {
            if (State.QueuePort == null)
                return false;

            Instance.MaterializeSignaledWaitPackets(State.QueuePortHandle);
            while (State.QueuePort.PendingCount > 0)
            {
                WinIoCompletionEntry Entry = Instance.TakeIoCompletionEntry(State.QueuePort);
                if (!HandlePacket(Instance, State, Entry, InputContext) || Win32kHelper.HasQueuedInputEvent(Instance, WakeMask, Thread.ThreadId))
                    return true;
            }

            return false;
        }

        // NT: WaitMessage handles every packet and goes on sleeping until a message is ready (xxxRealSleepThread).
        internal static void TakePackets(BinaryEmulator Instance, WindowsThreadState State)
        {
            if (State.QueuePort == null)
                return;

            Instance.MaterializeSignaledWaitPackets(State.QueuePortHandle);
            while (State.QueuePort.PendingCount > 0)
                HandlePacket(Instance, State, Instance.TakeIoCompletionEntry(State.QueuePort), InputContext);
        }

        // The skip and stop rules follow xxxDrainQueueCompletions.
        internal static void Drain(BinaryEmulator Instance, WindowsThreadState State, ulong DrainSlot)
        {
            Instance.MaterializeSignaledWaitPackets(State.QueuePortHandle);
            for (int Pending = State.QueuePort.PendingCount; Pending > 0; Pending--)
            {
                WinIoCompletionEntry Entry = Instance.TakeIoCompletionEntry(State.QueuePort);
                if ((uint)Entry.ApcContext == InputContext)
                    continue;

                if (!HandlePacket(Instance, State, Entry, DrainSlot))
                    return;
            }
        }

        internal static void DrainForMessages(BinaryEmulator Instance, uint ThreadId, uint WakeMask)
        {
            if ((WakeMask & Win32kHelper.QS_POSTMESSAGE) == 0 || !Instance.TryGetThread(ThreadId, out EmulatedThread Reader))
                return;

            WindowsThreadState State = WinEmulatedThread.TryGetState(Reader);
            if (HasCoreMessagingWindow(State))
                Drain(Instance, State, InputContext);
        }

        // The list push and the dispatch message follow xxxHandleCoreMessagingQueueCompletion.
        private static bool HandlePacket(BinaryEmulator Instance, WindowsThreadState State, WinIoCompletionEntry Entry, ulong DrainSlot)
        {
            ulong Slot = Entry.ApcContext;
            if ((Slot & InputContext) != 0)
                return false;

            ulong Window = Slot < SlotCount ? State.CoreMessagingWindows[Slot] : 0;
            if (Window == 0)
            {
                // NT sends the dispatch message to each registered window here. Sent from this path, it would stay pending.
                Utils.LogError($"[-] win32k: a queue port packet with context 0x{Slot:X} belongs to no CoreMessaging window.");
                return false;
            }

            ulong Block = Instance.WinHelper.ReadCoreMessagingTebEntry(State);
            ulong HeadPtr = Block + 8 + Slot * 8;
            ulong Node = Entry.KeyContext;
            if (Block == 0 || !NtWow64GetNativeSystemInformation.IsUserRange(HeadPtr, 8) || !Instance.WinHelper.TryReadUInt64(HeadPtr, out ulong Head))
            {
                Utils.LogError("[-] win32k: CoreMessaging's TEB block cannot be read, so a completed wait is dropped.");
                return true;
            }

            if (Head == 0 && ((DrainSlot & InputContext) != 0 || DrainSlot != Slot))
                Win32kHelper.PostMessage(Instance, Window, DispatchMessage, DispatchWParam, 0);

            if ((Node & 3) != 0 || !NtWow64GetNativeSystemInformation.IsUserRange(Node, 8)
                || !Instance.WinHelper.WriteUInt64(Node, Head) || !Instance.WinHelper.WriteUInt64(HeadPtr, Node))
            {
                Utils.LogError($"[-] win32k: a CoreMessaging wait node at 0x{Node:X} cannot be linked, so it is dropped.");
            }

            return true;
        }
    }
}
