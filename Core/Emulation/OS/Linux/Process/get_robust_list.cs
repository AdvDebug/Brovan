using System;
using System.Buffers.Binary;
using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Get_robust_list : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            EmulatedThread TargetThread = null;
            int RequestedTid = unchecked((int)Context.Arg0);
            if (RequestedTid == 0)
                TargetThread = Instance.CurrentThread;
            else
                Instance.Threads.TryGetValue(unchecked((uint)RequestedTid), out TargetThread);

            if (TargetThread == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ESRCH);
                return;
            }

            ulong WordSize = Context.Abi == SyscallAbi.X64 ? 8UL : 4UL;
            ulong Head = 0;
            LinuxThreadState State = TargetThread.GuestState as LinuxThreadState;
            if (State != null)
                Head = State.RobustListHead;

            if (!Instance.IsRegionMapped(Context.Arg1, WordSize) || !Instance.IsRegionMapped(Context.Arg2, WordSize))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            if (!WriteWord(Instance, Context.Arg1, WordSize, Head) || !WriteWord(Instance, Context.Arg2, WordSize, WordSize * 3))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Helper.SetReturnValue(Instance, Context, 0L);
        }

        private static bool WriteWord(BinaryEmulator Instance, ulong Address, ulong WordSize, ulong Value)
        {
            if (WordSize == 8)
            {
                Span<byte> Bytes = stackalloc byte[8];
                BinaryPrimitives.WriteUInt64LittleEndian(Bytes, Value);
                return Instance.WriteMemory(Address, Bytes);
            }

            Span<byte> CompatBytes = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(CompatBytes, unchecked((uint)Value));
            return Instance.WriteMemory(Address, CompatBytes);
        }
    }
}
