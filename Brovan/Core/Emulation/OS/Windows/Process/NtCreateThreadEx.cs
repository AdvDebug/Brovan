using Brovan.Core.Emulation.Guests;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateThreadEx : IWinSyscall
    {
        private const ulong PS_ATTRIBUTE_CLIENT_ID = 0x10003;
        private const ulong PS_ATTRIBUTE_TEB_ADDRESS = 0x10004;

        private static void WriteThreadCreationAttributes(BinaryEmulator Instance, uint ProcessId, uint ThreadId, ulong Teb, ulong AttributeList)
        {
            if (Instance == null || AttributeList == 0)
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
                    Helper.WritePointer(ValuePtr, ProcessId);
                    Helper.WritePointer(ValuePtr + PointerSize, ThreadId);
                }
                else if (Attribute == PS_ATTRIBUTE_TEB_ADDRESS && Teb != 0 && Size >= PointerSize && ValuePtr != 0 && Instance.IsRegionMapped(ValuePtr, PointerSize))
                {
                    Helper.WritePointer(ValuePtr, Teb);
                }
            }
        }

        // Matches RtlCreateUserStack.
        private static bool TryGetStackReserve(BinaryEmulator Instance, ulong ImageReserve, ulong CommitSize, ulong ReserveSize, out ulong Reserve)
        {
            const ulong Megabyte = 0x100000;
            const ulong Granularity = 0x10000;

            Reserve = ReserveSize != 0 ? ReserveSize : ImageReserve;
            if (CommitSize > Instance.MaxAddress || Reserve > Instance.MaxAddress)
                return false;

            if (CommitSize >= Reserve)
                Reserve = BinaryEmulator.AlignUp(CommitSize, Megabyte);

            Reserve = BinaryEmulator.AlignUp(Reserve, Granularity);
            return Reserve != 0 && Reserve <= Instance.MaxAddress;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong ThreadHandlePtr = Instance.WinHelper.GetArg(0);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
            ulong ProcessHandle = Instance.WinHelper.GetArg(3);
            ulong StartRoutine = Instance.WinHelper.GetArg(4);
            ulong Argument = Instance.WinHelper.GetArg(5);
            ulong CreateFlags = (uint)Instance.WinHelper.GetArg(6);
            ulong CommitSize = Instance.WinHelper.GetArg(8);
            ulong ReserveSize = Instance.WinHelper.GetArg(9);
            ulong AttributeList = Instance.WinHelper.GetArg(10);

            if (ThreadHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(ThreadHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (StartRoutine == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!HandleManager.IsCurrentProcessPseudoHandle(ProcessHandle))
            {
                if (!Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                WinProcess Target = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessCreateThread);
                if (Target == null)
                    return NTSTATUS.STATUS_ACCESS_DENIED;

                if (Target.PID != Instance.WinHelper.PID)
                {
                    if (Target.Remote == null)
                        return NTSTATUS.STATUS_INVALID_CID;

                    // A remote thread cannot start suspended.
                    if ((CreateFlags & 0x1UL) != 0)
                        return NTSTATUS.STATUS_NOT_SUPPORTED;

                    NTSTATUS RemoteStatus = Target.Remote.CreateThread(StartRoutine, Argument, out uint RemoteThreadId);
                    if (RemoteStatus != NTSTATUS.STATUS_SUCCESS)
                        return RemoteStatus;

                    WinRemoteThread Remote = new WinRemoteThread
                    {
                        Process = Target.Remote,
                        ThreadId = RemoteThreadId,
                    };

                    WinHandle RemoteHandle = Instance.WinHelper.HandleManager.AddHandle(Remote, (AccessMask)(uint)DesiredAccess);
                    Instance.WinHelper.AddWinHandle(RemoteHandle);

                    if (!Instance.WinHelper.WritePointer(ThreadHandlePtr, RemoteHandle.Handle))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    WriteThreadCreationAttributes(Instance, Target.PID, RemoteThreadId, 0, AttributeList);
                    return NTSTATUS.STATUS_SUCCESS;
                }
            }

            WindowsGuest Guest = Instance.Guest as WindowsGuest;
            ulong? StackOverride = CommitSize != 0 ? CommitSize : null;
            if (Guest != null)
            {
                if (!TryGetStackReserve(Instance, Guest.StackSize, CommitSize, ReserveSize, out ulong Reserve) ||
                    !Instance.TryFindFreeBaseAddress(Instance.AlignToPageSize(Reserve), 0x10000, Instance.BaseAddress, Instance.MaxAddress, out _))
                    return NTSTATUS.STATUS_NO_MEMORY;

                StackOverride = Reserve;
            }

            EmulatedThread NewThread = Guest != null
                ? Guest.CreateEmulatedThread(Instance, StartRoutine, null, Argument, StackOverride, 8, (uint)CreateFlags, false)
                : Instance.CreateEmulatedThread(StartRoutine, null, Argument, StackOverride);
            if (NewThread == null)
                return NTSTATUS.STATUS_NO_MEMORY;

            if (Guest != null)
                Instance.WinHelper.ApplyThreadBasePriority(NewThread);

            AccessMask Permissions = (AccessMask)(uint)DesiredAccess;
            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(NewThread, Permissions);
            Instance.WinHelper.AddWinHandle(Handle);

            if (!Instance.WinHelper.WritePointer(ThreadHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong Teb = Guest != null ? WinEmulatedThread.GetState(NewThread).Teb : 0;
            WriteThreadCreationAttributes(Instance, Instance.WinHelper.PID, NewThread.ThreadId, Teb, AttributeList);

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
