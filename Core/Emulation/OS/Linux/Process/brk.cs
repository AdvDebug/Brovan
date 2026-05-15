using System;

namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Brk : ILinuxSyscall
    {
        private const ulong PAGE_SIZE = 0x1000;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            if (Helper.ProgramBreakBase == 0)
            {
                ulong initialBreak = Helper.ProgramBreak;
                if (initialBreak == 0)
                    initialBreak = Instance.AlignToPageSize(Instance._binary.EntryPoint);

                Helper.ProgramBreakBase = initialBreak;
                Helper.ProgramBreak = initialBreak;
            }

            ulong requestedBreak = Context.Arg0;
            ulong currentBreak = Helper.ProgramBreak;

            if (requestedBreak == 0)
            {
                Helper.SetReturnValue(Instance, Context, currentBreak);
                return;
            }

            if (requestedBreak < Helper.ProgramBreakBase)
            {
                Helper.SetReturnValue(Instance, Context, currentBreak);
                return;
            }

            ulong currentAligned = Instance.AlignToPageSize(currentBreak);
            ulong requestedAligned = Instance.AlignToPageSize(requestedBreak);

            if (requestedAligned > currentAligned)
            {
                for (ulong page = currentAligned; page < requestedAligned; page += PAGE_SIZE)
                {
                    if (Instance.IsRegionMapped(page, PAGE_SIZE))
                    {
                        Helper.SetReturnValue(Instance, Context, currentBreak);
                        return;
                    }
                }

                ulong mappedUntil = currentAligned;
                while (mappedUntil < requestedAligned)
                {
                    if (Instance.MapMemoryRegion(mappedUntil, PAGE_SIZE, MemoryProtection.ReadWrite) == 0)
                    {
                        for (ulong rollback = currentAligned; rollback < mappedUntil; rollback += PAGE_SIZE)
                            Instance.UnmapMemoryRegion(rollback);

                        Helper.SetReturnValue(Instance, Context, currentBreak);
                        return;
                    }

                    mappedUntil += PAGE_SIZE;
                }
            }
            else if (requestedAligned < currentAligned)
            {
                for (ulong page = currentAligned; page > requestedAligned; page -= PAGE_SIZE)
                {
                    if (!Instance.UnmapMemoryRegion(page - PAGE_SIZE))
                    {
                        Helper.SetReturnValue(Instance, Context, currentBreak);
                        return;
                    }
                }
            }

            Helper.ProgramBreak = requestedBreak;
            Helper.SetReturnValue(Instance, Context, requestedBreak);
        }
    }
}
