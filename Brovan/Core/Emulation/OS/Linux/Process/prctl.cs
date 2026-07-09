using System.Buffers.Binary;
using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Prctl : ILinuxSyscall
    {
        private const ulong PR_GET_DUMPABLE = 3;
        private const ulong PR_SET_NAME = 15;
        private const ulong PR_GET_NAME = 16;
        private const ulong PR_CAPBSET_READ = 23;
        private const ulong PR_GET_TSC = 25;
        private const ulong PR_GET_CHILD_SUBREAPER = 37;
        private const ulong PR_GET_TID_ADDRESS = 40;
        private const ulong PR_GET_AUXV = 0x41555856;

        // TASK_COMM_LEN — length of the buffer passed to PR_GET_NAME.
        private const int TASK_COMM_LEN = 16;

        // Default timer slack value in nanoseconds (50 microseconds, same as kernel default).
        private const long DEFAULT_TIMERSLACK_NS = 50000L;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong option = Context.Arg0;
            ulong arg2 = Context.Arg1;
            ulong arg3 = Context.Arg2;
            Console.WriteLine(option);
            switch (option)
            {
                case PR_GET_DUMPABLE:
                    // 1 = SUID_DUMP_USER
                    Helper.SetReturnValue(Instance, Context, 1L);
                    return;

                case PR_SET_NAME:
                    if (arg2 == 0 || !Instance.IsRegionMapped(arg2, TASK_COMM_LEN))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                        return;
                    }

                    Helper.SetReturnValue(Instance, Context, 0L);
                    return;

                case PR_GET_NAME:
                    if (arg2 == 0 || !Instance.IsRegionMapped(arg2, TASK_COMM_LEN))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                        return;
                    }

                    Span<byte> nameBuf = stackalloc byte[TASK_COMM_LEN];
                    nameBuf.Clear();

                    if (!Instance.WriteMemory(arg2, nameBuf))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                        return;
                    }

                    Helper.SetReturnValue(Instance, Context, 0L);
                    return;

                case PR_CAPBSET_READ:
                    // pretend every capability is in the bounding set
                    Helper.SetReturnValue(Instance, Context, 1L);
                    return;

                case PR_GET_CHILD_SUBREAPER:
                    // write 0 (not a subreaper) to the caller's int pointer
                    if (arg2 == 0 || !Instance.IsRegionMapped(arg2, 4))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                        return;
                    }

                    if (!Instance._emulator.WriteMemory(arg2, 0))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                        return;
                    }

                    Helper.SetReturnValue(Instance, Context, 0L);
                    return;

                case PR_GET_TID_ADDRESS:
                    {
                        // return the clear_child_tid address tracked by set_tid_address()/clone()
                        int PointerSize = Context.Abi == SyscallAbi.X64 ? 8 : 4;
                        if (arg2 == 0 || !Instance.IsRegionMapped(arg2, (ulong)PointerSize))
                        {
                            Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                            return;
                        }

                        LinuxThreadState TIDState = Instance.CurrentThread?.GuestState as LinuxThreadState;
                        ulong TIDAddress = TIDState?.TIDPtr ?? 0UL;
                        if(PointerSize == 8 && !Instance._emulator.WriteMemory(arg2, TIDAddress) || !Instance._emulator.WriteMemory(arg2, unchecked((int)TIDAddress)))
                        {
                            Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                            return;
                        }

                        Helper.SetReturnValue(Instance, Context, 0L);
                        return;
                    }

                case PR_GET_TSC:
                    // PR_TSC_ENABLE = 1
                    if (arg2 == 0 || !Instance.IsRegionMapped(arg2, 4))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                        return;
                    }

                    if (!Instance._emulator.WriteMemory(arg2, 1))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                        return;
                    }

                    Helper.SetReturnValue(Instance, Context, 0L);
                    return;

                case PR_GET_AUXV:
                    {
                        byte[] auxv = Helper.AuxiliaryVector ?? Array.Empty<byte>();
                        ulong requestedSize = arg3;
                        ulong copySize = Math.Min((ulong)auxv.Length, requestedSize);

                        if (copySize > 0)
                        {
                            if (arg2 == 0 || !Instance.IsRegionMapped(arg2, copySize))
                            {
                                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                                return;
                            }

                            if (!Instance.WriteMemory(arg2, auxv.AsSpan(0, (int)copySize)))
                            {
                                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                                return;
                            }
                        }

                        Helper.SetReturnValue(Instance, Context, (long)auxv.Length);
                        return;
                    }

                default:
                    Helper.SetReturnValue(Instance, Context, 0L);
                    return;
            }
        }
    }
}