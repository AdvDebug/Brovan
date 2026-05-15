using System;
using System.Buffers.Binary;
using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal sealed class Sched_getaffinity : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            int pid = unchecked((int)Context.Arg0);
            ulong len = Context.Arg1;
            ulong user_mask_ptr = Context.Arg2;

            if (!IsKnownTask(Helper, pid))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ESRCH);
                return;
            }

            int MaskBytes = Context.Abi == SyscallAbi.X64 ? 8 : 4;
            if (len < (ulong)MaskBytes)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (user_mask_ptr == 0 || !Instance.IsRegionMapped(user_mask_ptr, (ulong)MaskBytes))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Span<byte> Mask = stackalloc byte[8];
            Mask.Clear();
            ulong CpuMask = Helper.SystemIdentity.GetCpuMask64();
            if (Context.Abi == SyscallAbi.X64)
                BinaryPrimitives.WriteUInt64LittleEndian(Mask.Slice(0, 8), CpuMask);
            else
                BinaryPrimitives.WriteUInt32LittleEndian(Mask.Slice(0, 4), unchecked((uint)CpuMask));

            if (!Instance.WriteMemory(user_mask_ptr, Mask.Slice(0, MaskBytes)))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Helper.SetReturnValue(Instance, Context, MaskBytes);
        }

        private static bool IsKnownTask(LinuxSyscallsHelper Helper, int Pid)
        {
            if (Pid == 0 || Pid == Helper.PID)
                return true;

            if (Pid > 0 && Helper.TryGetProcessInfo(Pid, out _))
                return true;

            return Pid > 0 && Helper.TryGetThreadInfo((uint)Pid, out _);
        }
    }
}
