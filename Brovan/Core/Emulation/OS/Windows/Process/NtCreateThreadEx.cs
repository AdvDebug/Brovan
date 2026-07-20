using Brovan.Core.Emulation.Guests;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateThreadEx : IWinSyscall
    {
        private const ulong PS_ATTRIBUTE_CLIENT_ID = 0x10003;
        private const ulong PS_ATTRIBUTE_TEB_ADDRESS = 0x10004;

        private static void WriteThreadCreationAttributes(BinaryEmulator Instance, EmulatedThread Thread, ulong AttributeList)
        {
            if (Instance == null || Thread == null || AttributeList == 0)
                return;

            if (!Instance.IsRegionMapped(AttributeList, 8))
                return;

            ulong TotalLength = Instance.ReadMemoryULong(AttributeList);
            if (TotalLength < 8 + 32)
                return;

            ulong Count = (TotalLength - 8) / 32;
            if (Count > 32)
                Count = 32;

            for (ulong Index = 0; Index < Count; Index++)
            {
                ulong AttributeAddress = AttributeList + 8 + Index * 32;
                if (!Instance.IsRegionMapped(AttributeAddress, 32))
                    break;

                ulong Attribute = Instance.ReadMemoryULong(AttributeAddress);
                ulong Size = Instance.ReadMemoryULong(AttributeAddress + 8);
                ulong ValuePtr = Instance.ReadMemoryULong(AttributeAddress + 16);

                if (Attribute == PS_ATTRIBUTE_CLIENT_ID && Size >= 16 && ValuePtr != 0 && Instance.IsRegionMapped(ValuePtr, 16))
                {
                    Instance._emulator.WriteMemory(ValuePtr, (ulong)Instance.WinHelper.PID, 8);
                    Instance._emulator.WriteMemory(ValuePtr + 8, (ulong)Thread.ThreadId, 8);
                }
                else if (Attribute == PS_ATTRIBUTE_TEB_ADDRESS && Size >= 8 && ValuePtr != 0 && Instance.IsRegionMapped(ValuePtr, 8))
                {
                    WindowsThreadState State = WinEmulatedThread.GetState(Thread);
                    Instance._emulator.WriteMemory(ValuePtr, State.Teb, 8);
                }
            }
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong ThreadHandlePtr = Instance.WinHelper.GetArg(0);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
            ulong ProcessHandle = Instance.WinHelper.GetArg(3);
            ulong StartRoutine = Instance.WinHelper.GetArg(4);
            ulong Argument = Instance.WinHelper.GetArg(5);
            ulong CreateFlags = (uint)Instance.WinHelper.GetArg(6);
            ulong StackSize = Instance.WinHelper.GetArg(8);
            ulong AttributeList = Instance.WinHelper.GetArg(10);

            if (ThreadHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(ThreadHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (StartRoutine == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            // Only current-process thread creation is modeled.
            if (!HandleManager.IsCurrentProcessPseudoHandle(ProcessHandle))
            {
                if (!Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                WinProcess Target = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessCreateThread);
                if (Target == null || Target.PID != Instance.WinHelper.PID)
                    return NTSTATUS.STATUS_NOT_SUPPORTED;
            }

            ulong? StackOverride = null;
            if (StackSize != 0)
                StackOverride = StackSize;

            WindowsGuest Guest = Instance.Guest as WindowsGuest;
            EmulatedThread NewThread = Guest != null
                ? Guest.CreateEmulatedThread(Instance, StartRoutine, null, Argument, StackOverride, 8, (uint)CreateFlags, false)
                : Instance.CreateEmulatedThread(StartRoutine, null, Argument, StackOverride);
            if (NewThread == null)
                return NTSTATUS.STATUS_NO_MEMORY;

            AccessMask Permissions = (AccessMask)(uint)DesiredAccess;
            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(NewThread, Permissions);
            Instance.WinHelper.AddWinHandle(Handle);

            if (!Instance._emulator.WriteMemory(ThreadHandlePtr, Handle.Handle, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WriteThreadCreationAttributes(Instance, NewThread, AttributeList);

            // THREAD_CREATE_FLAGS_CREATE_SUSPENDED
            if ((CreateFlags & 0x1UL) != 0)
            {
                NewThread.SuspendCount = 1;
                NewThread.State = EmulatedThreadState.Suspended;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
