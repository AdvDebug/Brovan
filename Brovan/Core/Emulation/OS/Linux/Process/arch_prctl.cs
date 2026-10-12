using System;
using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Arch_prctl : ILinuxSyscall
    {
        private const uint ARCH_SET_GS = 0x1001;
        private const uint ARCH_SET_FS = 0x1002;
        private const uint ARCH_GET_FS = 0x1003;
        private const uint ARCH_GET_GS = 0x1004;
        private const uint ARCH_GET_CPUID = 0x1011;
        private const uint ARCH_SET_CPUID = 0x1012;

        // Linux TASK_SIZE_MAX with 4-level paging.
        internal const ulong TASK_SIZE_MAX = 0x7FFFFFFFF000;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            uint op = (uint)Context.Arg0;
            ulong value = Context.Arg1;

            switch (op)
            {
                case ARCH_SET_FS:
                case ARCH_SET_GS:
                    if (Context.Abi != SyscallAbi.X64)
                    {
                        Helper.SetReturnValue(Instance, -(long)LinuxErrno.EINVAL);
                        return;
                    }

                    if (value >= TASK_SIZE_MAX)
                    {
                        Helper.SetReturnValue(Instance, -(long)LinuxErrno.EPERM);
                        return;
                    }

                    Instance.WriteRegister(op == ARCH_SET_FS ? Registers.UC_X86_REG_FS_BASE : Registers.UC_X86_REG_GS_BASE, value);
                    Helper.SetReturnValue(Instance, 0L);
                    return;

                case ARCH_GET_FS:
                case ARCH_GET_GS:
                    if (Context.Abi != SyscallAbi.X64)
                    {
                        Helper.SetReturnValue(Instance, -(long)LinuxErrno.EINVAL);
                        return;
                    }

                    if (!Instance.IsAccessible(value, 8, true))
                    {
                        Helper.SetReturnValue(Instance, -(long)LinuxErrno.EFAULT);
                        return;
                    }

                    Span<byte> BaseBytes = stackalloc byte[8];
                    BinaryPrimitives.WriteUInt64LittleEndian(BaseBytes, Instance.ReadRegister(op == ARCH_GET_FS ? Registers.UC_X86_REG_FS_BASE : Registers.UC_X86_REG_GS_BASE));
                    if (!Instance.WriteMemory(value, BaseBytes))
                    {
                        Helper.SetReturnValue(Instance, -(long)LinuxErrno.EFAULT);
                        return;
                    }
                    Helper.SetReturnValue(Instance, 0L);
                    return;

                // These match Linux on a CPU without CPUID faulting (do_arch_prctl_common).
                case ARCH_GET_CPUID:
                    Helper.SetReturnValue(Instance, 1L);
                    return;

                case ARCH_SET_CPUID:
                    Helper.SetReturnValue(Instance, -(long)LinuxErrno.ENODEV);
                    return;

                default:
                    Helper.SetReturnValue(Instance, -(long)LinuxErrno.EINVAL);
                    return;
            }
        }
    }
}
