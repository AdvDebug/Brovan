namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Munmap : ILinuxSyscall
    {
        private const ulong PAGE_SIZE = 0x1000;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong addr = Context.Arg0;
            ulong length = Context.Arg1;

            if (length == 0 || !Instance.IsAlignedToPageSize(addr) || length > ulong.MaxValue - (PAGE_SIZE - 1) || addr > ulong.MaxValue - length)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            ulong AlignedLength = Instance.AlignToPageSize(length);
            ulong End = addr + AlignedLength;
            for (int i = Instance._memory.Count - 1; i >= 0; i--)
            {
                MemoryRegion Region = Instance._memory[i];
                ulong RegionMappedSize = Instance.AlignToPageSize(Region.Size);
                ulong RegionStart = Region.BaseAddress;
                ulong RegionEnd = RegionStart + RegionMappedSize;

                if (RegionMappedSize == 0 || RegionEnd <= addr || RegionStart >= End)
                    continue;

                ulong UnmapStart = Math.Max(addr, RegionStart);
                ulong UnmapEnd = Math.Min(End, RegionEnd);
                ulong UnmapSize = UnmapEnd - UnmapStart;
                if (UnmapSize == 0)
                    continue;

                if (!Instance._emulator.UnmapMemory(UnmapStart, UnmapSize))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
                }

                Instance.RemoveMemoryRegionAt(i);
                Instance.AddFreedRegion(UnmapStart, UnmapSize);
                if (RegionStart < UnmapStart)
                {
                    MemoryRegion Left = Region;
                    Left.Size = UnmapStart - RegionStart;
                    Left.RequestedSize = Left.Size;
                    Left.PoisonedMemory = default;
                    Instance.AddMemoryRegion(Left);
                }

                if (UnmapEnd < RegionEnd)
                {
                    MemoryRegion Right = Region;
                    Right.BaseAddress = UnmapEnd;
                    Right.Size = RegionEnd - UnmapEnd;
                    Right.RequestedSize = Right.Size;
                    Right.PoisonedMemory = default;
                    Instance.AddMemoryRegion(Right);
                }
            }

            Helper.SetReturnValue(Instance, Context, LinuxErrno.ESUCCESS);
        }
    }
}
