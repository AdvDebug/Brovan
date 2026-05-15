using System;
using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Arch_prctl : ILinuxSyscall
    {
        private const ulong ARCH_SET_GS = 0x1001;
        private const ulong ARCH_SET_FS = 0x1002;
        private const ulong ARCH_GET_FS = 0x1003;
        private const ulong ARCH_GET_GS = 0x1004;
        private const ulong ARCH_GET_CPUID = 0x1005;
        private const ulong ARCH_SET_CPUID = 0x1006;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong op = Context.Arg0;
            ulong value = Context.Arg1;

            switch (op)
            {
                case ARCH_SET_FS:
                    if (Context.Abi != SyscallAbi.X64)
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                        return;
                    }

                    Instance.WriteRegister(Registers.UC_X86_REG_FS_BASE, value);
                    Helper.SetReturnValue(Instance, Context, 0L);
                    return;

                case ARCH_SET_GS:
                    if (Context.Abi != SyscallAbi.X64)
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                        return;
                    }

                    Instance.WriteRegister(Registers.UC_X86_REG_GS_BASE, value);
                    Helper.SetReturnValue(Instance, Context, 0L);
                    return;

                case ARCH_GET_FS:
                    if (Context.Abi != SyscallAbi.X64)
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                        return;
                    }

                    if (!Instance.IsRegionMapped(value, 8))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                        return;
                    }

                    Span<byte> FsBaseBytes = stackalloc byte[8];
                    BinaryPrimitives.WriteUInt64LittleEndian(FsBaseBytes, Instance.ReadRegister(Registers.UC_X86_REG_FS_BASE));
                    if (!Instance.WriteMemory(value, FsBaseBytes))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                        return;
                    }
                    Helper.SetReturnValue(Instance, Context, 0L);
                    return;

                case ARCH_GET_GS:
                    if (Context.Abi != SyscallAbi.X64)
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                        return;
                    }

                    if (!Instance.IsRegionMapped(value, 8))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                        return;
                    }

                    Span<byte> GsBaseBytes = stackalloc byte[8];
                    BinaryPrimitives.WriteUInt64LittleEndian(GsBaseBytes, Instance.ReadRegister(Registers.UC_X86_REG_GS_BASE));
                    if (!Instance.WriteMemory(value, GsBaseBytes))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                        return;
                    }
                    Helper.SetReturnValue(Instance, Context, 0L);
                    return;

                case ARCH_GET_CPUID:
                    {
                        int size = Context.Abi == SyscallAbi.X64 ? 8 : 4;
                        if (!Instance.IsRegionMapped(value, (ulong)size))
                        {
                            Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                            return;
                        }

                        if (Context.Abi == SyscallAbi.X64)
                        {
                            Span<byte> CpuidBytes = stackalloc byte[8];
                            BinaryPrimitives.WriteUInt64LittleEndian(CpuidBytes, Helper.CpuidEnabled ? 1UL : 0UL);
                            if (!Instance.WriteMemory(value, CpuidBytes))
                            {
                                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                                return;
                            }
                        }
                        else
                        {
                            Span<byte> CpuidBytes = stackalloc byte[4];
                            BinaryPrimitives.WriteUInt32LittleEndian(CpuidBytes, Helper.CpuidEnabled ? 1U : 0U);
                            if (!Instance.WriteMemory(value, CpuidBytes))
                            {
                                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                                return;
                            }
                        }

                        Helper.SetReturnValue(Instance, Context, 0L);
                        return;
                    }

                case ARCH_SET_CPUID:
                    Helper.CpuidEnabled = value != 0;
                    Helper.SetReturnValue(Instance, Context, 0L);
                    return;

                default:
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
            }
        }
    }
}
