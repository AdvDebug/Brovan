using System;
using System.Security.Cryptography;

namespace Brovan.Core.Emulation.OS.Linux.Misc
{
    internal class Getrandom : ILinuxSyscall
    {
        [Flags]
        private enum GETRANDOM_FLAGS : uint
        {
            NONE = 0,
            GRND_NONBLOCK = 0x0001,
            GRND_RANDOM = 0x0002,
        }

        // linux man page documents a 512-byte maximum per call when using the random source
        private const ulong GRND_RANDOM_MAX = 512;

        private const ulong GRND_URANDOM_MAX = 0x01FFFFFF;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong buf = Context.Arg0;
            ulong size = Context.Arg1;
            uint flags = (uint)Context.Arg2;

            uint AllowedFlags = (uint)GETRANDOM_FLAGS.GRND_NONBLOCK | (uint)GETRANDOM_FLAGS.GRND_RANDOM;

            if ((flags & ~AllowedFlags) != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (size == 0)
            {
                Helper.SetReturnValue(Instance, Context, LinuxErrno.ESUCCESS);
                return;
            }

            if ((flags & (uint)GETRANDOM_FLAGS.GRND_RANDOM) != 0)
            {
                if (size > GRND_RANDOM_MAX)
                    size = GRND_RANDOM_MAX;
            }
            else
            {
                if (size > GRND_URANDOM_MAX)
                    size = GRND_URANDOM_MAX;
            }

            Span<byte> Data = Helper.Shared.GetSpan(size);
            RandomNumberGenerator.Fill(Data);

            if (!Instance.WriteMemory(buf, Data))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Helper.SetReturnValue(Instance, Context, size);
        }
    }
}