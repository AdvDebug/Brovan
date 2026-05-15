using System;

namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Mremap : ILinuxSyscall
    {
        private const uint MREMAP_MAYMOVE = 0x1;
        private const uint MREMAP_FIXED = 0x2;
        private const uint MREMAP_DONTUNMAP = 0x4;
        private const int COPY_CHUNK_SIZE = 0x100000;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong OldAddress = Context.Arg0;
            ulong OldSize = Context.Arg1;
            ulong NewSize = Context.Arg2;
            uint Flags = (uint)Context.Arg3;
            ulong NewAddress = Context.Arg4;

            if (!Instance.IsAlignedToPageSize(OldAddress))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if ((Flags & ~(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP)) != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (NewSize == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if ((Flags & MREMAP_FIXED) != 0 && (Flags & MREMAP_MAYMOVE) == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if ((Flags & MREMAP_DONTUNMAP) != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (OldSize == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            ulong OldAlignedSize = Instance.AlignToPageSize(OldSize);
            ulong NewAlignedSize = Instance.AlignToPageSize(NewSize);
            if (OldAlignedSize == 0 || NewAlignedSize == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (OldAddress > ulong.MaxValue - OldAlignedSize)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (!Instance.TryFindMemoryRegionByBase(OldAddress, out int SourceIndex, out MemoryRegion SourceRegion))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }
            ulong SourceAlignedSize = Instance.AlignToPageSize(SourceRegion.Size);
            if (OldAlignedSize != SourceAlignedSize)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            if ((Flags & MREMAP_FIXED) != 0)
            {
                if (!Instance.IsAlignedToPageSize(NewAddress) || NewAddress > ulong.MaxValue - NewAlignedSize)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
                }

                if (RangesOverlap(OldAddress, OldAlignedSize, NewAddress, NewAlignedSize))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
                }
            }

            if (NewAlignedSize == OldAlignedSize)
            {
                if ((Flags & MREMAP_FIXED) != 0 && NewAddress != OldAddress)
                {
                    if (!TryMoveRegion(Instance, Helper, SourceIndex, SourceRegion, OldAddress, OldAlignedSize, NewAddress, NewSize, true, out ulong FixedAddress))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOMEM);
                        return;
                    }

                    Helper.SetReturnValue(Instance, Context, FixedAddress);
                    return;
                }

                SourceRegion.Size = NewSize;
                UpdatePoisonedMemory(ref SourceRegion, OldAddress, NewSize, NewAlignedSize);
                Instance.SetMemoryRegion(SourceIndex, SourceRegion);
                Helper.SetReturnValue(Instance, Context, OldAddress);
                return;
            }

            if (NewAlignedSize < OldAlignedSize)
            {
                ulong TailAddress = OldAddress + NewAlignedSize;
                ulong TailSize = OldAlignedSize - NewAlignedSize;
                if (TailSize != 0)
                {
                    if (!Instance._emulator.UnmapMemory(TailAddress, TailSize))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                        return;
                    }

                    Instance.AddFreedRegion(TailAddress, TailSize);
                }

                SourceRegion.Size = NewSize;
                UpdatePoisonedMemory(ref SourceRegion, OldAddress, NewSize, NewAlignedSize);
                Instance.SetMemoryRegion(SourceIndex, SourceRegion);
                Helper.SetReturnValue(Instance, Context, OldAddress);
                return;
            }

            ulong ExtensionAddress = OldAddress + OldAlignedSize;
            ulong ExtensionSize = NewAlignedSize - OldAlignedSize;
            if ((Flags & MREMAP_FIXED) == 0 && !Instance.IsRegionMapped(ExtensionAddress, ExtensionSize))
            {
                if (Instance._emulator.MapMemory(ExtensionAddress, ExtensionSize, SourceRegion.Protections))
                {
                    SourceRegion.Size = NewSize;
                    UpdatePoisonedMemory(ref SourceRegion, OldAddress, NewSize, NewAlignedSize);
                    Instance.SetMemoryRegion(SourceIndex, SourceRegion);
                    Helper.SetReturnValue(Instance, Context, OldAddress);
                    return;
                }
            }

            if ((Flags & MREMAP_MAYMOVE) == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOMEM);
                return;
            }

            ulong DestinationAddress = (Flags & MREMAP_FIXED) != 0 ? NewAddress : 0;
            if (!TryMoveRegion(Instance, Helper, SourceIndex, SourceRegion, OldAddress, OldAlignedSize, DestinationAddress, NewSize, (Flags & MREMAP_FIXED) != 0, out ulong ResultAddress))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOMEM);
                return;
            }

            Helper.SetReturnValue(Instance, Context, ResultAddress);
        }

        private static bool TryMoveRegion(BinaryEmulator Instance, LinuxSyscallsHelper Helper, int SourceIndex, MemoryRegion SourceRegion, ulong OldAddress, ulong OldAlignedSize, ulong NewAddress, ulong NewSize, bool FixedAddress, out ulong ResultAddress)
        {
            ResultAddress = 0;
            ulong NewAlignedSize = Instance.AlignToPageSize(NewSize);

            if (FixedAddress)
            {
                if (Instance.IsRegionMapped(NewAddress, NewAlignedSize))
                    return false;

                if (!Instance._emulator.MapMemory(NewAddress, NewAlignedSize, SourceRegion.Protections))
                    return false;

                MemoryRegion PlaceholderRegion = SourceRegion;
                PlaceholderRegion.BaseAddress = NewAddress;
                PlaceholderRegion.Size = NewSize;
                UpdatePoisonedMemory(ref PlaceholderRegion, NewAddress, NewSize, NewAlignedSize);
                Instance.AddMemoryRegion(PlaceholderRegion);
                ResultAddress = NewAddress;
            }
            else
            {
                ResultAddress = Instance.MapMemoryRegion(0, NewSize, SourceRegion.Protections);
                if (ResultAddress == 0)
                    return false;
            }

            if (!Instance.TryFindMemoryRegionByBase(ResultAddress, out int DestinationIndex, out _))
            {
                if (FixedAddress)
                    Instance._emulator.UnmapMemory(ResultAddress, NewAlignedSize);
                else
                    Instance.UnmapMemoryRegion(ResultAddress, true);
                return false;
            }

            ulong CopySize = Math.Min(OldAlignedSize, NewAlignedSize);
            if (!TryCopyMemory(Instance, Helper, OldAddress, ResultAddress, CopySize))
            {
                RollbackDestination(Instance, DestinationIndex);
                return false;
            }

            if (!Instance._emulator.UnmapMemory(OldAddress, OldAlignedSize))
            {
                RollbackDestination(Instance, DestinationIndex);
                return false;
            }

            Instance.AddFreedRegion(OldAddress, OldAlignedSize);
            Instance.RemoveMemoryRegionAt(SourceIndex);

            MemoryRegion DestinationRegion = SourceRegion;
            DestinationRegion.BaseAddress = ResultAddress;
            DestinationRegion.Size = NewSize;
            UpdatePoisonedMemory(ref DestinationRegion, ResultAddress, NewSize, NewAlignedSize);
            Instance.SetMemoryRegion(DestinationIndex > SourceIndex ? DestinationIndex - 1 : DestinationIndex, DestinationRegion);
            return true;
        }

        private static void RollbackDestination(BinaryEmulator Instance, int DestinationIndex)
        {
            if (DestinationIndex < 0 || DestinationIndex >= Instance._memory.Count)
                return;

            MemoryRegion DestinationRegion = Instance._memory[DestinationIndex];
            ulong DestinationAlignedSize = Instance.AlignToPageSize(DestinationRegion.Size);
            Instance._emulator.UnmapMemory(DestinationRegion.BaseAddress, DestinationAlignedSize);
            Instance.RemoveMemoryRegionAt(DestinationIndex);
        }

        private static bool TryCopyMemory(BinaryEmulator Instance, LinuxSyscallsHelper Helper, ulong SourceAddress, ulong DestinationAddress, ulong Size)
        {
            ulong Copied = 0;
            while (Copied < Size)
            {
                uint ChunkSize = (uint)Math.Min((ulong)COPY_CHUNK_SIZE, Size - Copied);
                Span<byte> Transfer = Helper.Shared.GetSpan(ChunkSize);
                if (!Instance.ReadMemory(SourceAddress + Copied, Transfer))
                    return false;

                if (!Instance.WriteMemory(DestinationAddress + Copied, Transfer))
                    return false;

                Copied += ChunkSize;
            }

            return true;
        }

        private static void UpdatePoisonedMemory(ref MemoryRegion Region, ulong BaseAddress, ulong RequestedSize, ulong AlignedSize)
        {
            Region.PoisonedMemory = default;
            if (RequestedSize < AlignedSize)
                Region.PoisonedMemory = (BaseAddress + RequestedSize, BaseAddress + AlignedSize);
        }

        private static bool RangesOverlap(ulong LeftAddress, ulong LeftSize, ulong RightAddress, ulong RightSize)
        {
            ulong LeftEnd = LeftAddress + LeftSize;
            ulong RightEnd = RightAddress + RightSize;
            return LeftAddress < RightEnd && RightAddress < LeftEnd;
        }
    }
}
