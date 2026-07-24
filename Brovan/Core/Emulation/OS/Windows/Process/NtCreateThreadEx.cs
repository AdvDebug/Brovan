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

            WinSysHelper Helper = Instance.WinHelper;
            ulong PointerSize = (ulong)Helper.PointerSize;
            ulong AttributeSize = PointerSize * 4;

            if (!Instance.IsRegionMapped(AttributeList, PointerSize))
                return;

            ulong TotalLength = Helper.ReadPointer(AttributeList);
            if (TotalLength < PointerSize + AttributeSize)
                return;

            ulong Count = (TotalLength - PointerSize) / AttributeSize;
            if (Count > 32)
                Count = 32;

            for (ulong Index = 0; Index < Count; Index++)
            {
                ulong AttributeAddress = AttributeList + PointerSize + Index * AttributeSize;
                if (!Instance.IsRegionMapped(AttributeAddress, AttributeSize))
                    break;

                ulong Attribute = Helper.ReadPointer(AttributeAddress);
                ulong Size = Helper.ReadPointer(AttributeAddress + PointerSize);
                ulong ValuePtr = Helper.ReadPointer(AttributeAddress + PointerSize * 2);

                if (Attribute == PS_ATTRIBUTE_CLIENT_ID && Size >= PointerSize * 2 && ValuePtr != 0 && Instance.IsRegionMapped(ValuePtr, PointerSize * 2))
                {
                    Helper.WritePointer(ValuePtr, Helper.PID);
                    Helper.WritePointer(ValuePtr + PointerSize, Thread.ThreadId);
                }
                else if (Attribute == PS_ATTRIBUTE_TEB_ADDRESS && Size >= PointerSize && ValuePtr != 0 && Instance.IsRegionMapped(ValuePtr, PointerSize))
                {
                    WindowsThreadState State = WinEmulatedThread.GetState(Thread);
                    Helper.WritePointer(ValuePtr, State.Teb);
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

            if (!Instance.WinHelper.WritePointer(ThreadHandlePtr, Handle.Handle))
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
