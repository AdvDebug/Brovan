using static Brovan.Core.Helpers.BinaryHelpers;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserDispatchMessage : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong MessagePtr = Instance.WinHelper.GetArg(0);
            if (!Win32kHelper.TryReadMessage(Instance, MessagePtr, out Win32kMessage Message))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinWindow Window = Message.Hwnd == 0 ? null : Instance.WinHelper.GetWindow(Message.Hwnd);
            if (Message.Hwnd != 0 && Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Window == null || Window.WndProc == 0)
            {
                ulong FallbackResult = Win32kHelper.DispatchMessage(Instance, Message);
                Instance.SetRawSyscallReturn(FallbackResult);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong Peb = Instance.PEB;
            ulong KernelCallbackTable = Peb != 0 ? Instance.ReadMemoryULong(Peb + 0x58) : 0;
            if (KernelCallbackTable == 0)
            {
                ulong FallbackResult = Win32kHelper.DispatchMessage(Instance, Message);
                Instance.SetRawSyscallReturn(FallbackResult);
                return NTSTATUS.STATUS_SUCCESS;
            }

            const uint FN_DWORDOPTINLPMSG_INDEX = 4;
            ulong Callback = Instance.ReadMemoryULong(KernelCallbackTable + FN_DWORDOPTINLPMSG_INDEX * 8);
            if (Callback == 0)
            {
                ulong FallbackResult = Win32kHelper.DispatchMessage(Instance, Message);
                Instance.SetRawSyscallReturn(FallbackResult);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong CurrentRsp = Instance.ReadRegister(Registers.UC_X86_REG_RSP);
            ulong OriginalReturnAddress = Instance.ReadMemoryULong(CurrentRsp);

            WindowsThreadState State = WinEmulatedThread.GetState(Instance.CurrentThread);
            WinUserCallbackFrame Frame = new WinUserCallbackFrame
            {
                SavedRsp = CurrentRsp,
                SavedReturnAddress = OriginalReturnAddress,
            };
            State.UserCallbackFrames.Push(Frame);

            const ulong StackReserved = 0x200;
            ulong ArgBuffer = (CurrentRsp - StackReserved) & ~0xFUL;
            const uint CallbackArgSize = 0x40;

            for (uint i = 0; i < CallbackArgSize; i += 8)
                Instance._emulator.WriteMemory(ArgBuffer + i, 0UL, 8);

            Instance._emulator.WriteMemory(ArgBuffer + 0x00, Message.Hwnd, 8);
            Instance._emulator.WriteMemory(ArgBuffer + 0x08, Message.Message, 4);
            Instance._emulator.WriteMemory(ArgBuffer + 0x10, Message.WParam, 8);
            Instance._emulator.WriteMemory(ArgBuffer + 0x18, 0u, 4);
            Instance._emulator.WriteMemory(ArgBuffer + 0x28, Window.WndProc, 8);
            Instance._emulator.WriteMemory(ArgBuffer + 0x30, Message.LParam, 8);

            ulong DispatcherRsp = (ArgBuffer - 0x80) & ~0xFUL;
            for (ulong i = DispatcherRsp; i < ArgBuffer; i += 8)
                Instance._emulator.WriteMemory(i, 0UL, 8);

            Instance._emulator.WriteMemory(DispatcherRsp + 0x20, ArgBuffer, 8);
            Instance._emulator.WriteMemory(DispatcherRsp + 0x28, 0u, 4);
            Instance._emulator.WriteMemory(DispatcherRsp + 0x2C, FN_DWORDOPTINLPMSG_INDEX, 4);

            Instance.WriteRegister(Registers.UC_X86_REG_RCX, ArgBuffer);
            Instance.WriteRegister(Registers.UC_X86_REG_RSP, DispatcherRsp - 8);
            Instance.WriteRegister(Instance.IPRegister, Callback - 2);
            Instance.SuppressSyscallStatusWrite = true;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
