using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Mmap : ILinuxSyscall
    {
        private const ulong PAGE_SIZE = 0x1000;
        private const int FILE_COPY_CHUNK_SIZE = 0x100000;

        private struct RemapRegion
        {
            public MemoryRegion Region;
            public byte[] Data;
        }

        private struct MappedSegment
        {
            public ulong Address;
            public ulong Size;
        }

        private struct MappingReservation
        {
            public ulong Address;
            public List<RemapRegion> RemovedRegions;
            public List<MappedSegment> AddedSegments;
        }

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong addr = Context.Arg0;
            ulong length = Context.Arg1;
            uint prot = (uint)Context.Arg2;
            MEMFLAGS flags = (MEMFLAGS)(uint)Context.Arg3;
            ulong fd = Context.Arg4;
            ulong offset = Context.Arg5;
            uint MapType = (uint)flags & (uint)MEMFLAGS.MAP_TYPE;
            bool IsAnonymous = ((uint)flags & (uint)MEMFLAGS.MAP_ANONYMOUS) != 0;
            bool IsNoReplace = ((uint)flags & (uint)MEMFLAGS.MAP_FIXED_NOREPLACE) != 0;
            bool IsFixed = ((uint)flags & (uint)MEMFLAGS.MAP_FIXED) != 0 || IsNoReplace;
            bool IsPrivate = MapType == (uint)MEMFLAGS.MAP_PRIVATE;
            bool IsShared = MapType == (uint)MEMFLAGS.MAP_SHARED || MapType == (uint)MEMFLAGS.MAP_SHARED_VALIDATE;

            if (length == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (length > ulong.MaxValue - (PAGE_SIZE - 1))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if ((offset & (PAGE_SIZE - 1)) != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (!IsPrivate && !IsShared)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            ulong AlignedLength = Instance.AlignToPageSize(length);
            ulong OffsetPages = offset >> 12;
            ulong LengthPages = AlignedLength >> 12;
            if (OffsetPages + LengthPages < OffsetPages)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EOVERFLOW);
                return;
            }

            FileObject FileDesc = null;
            long FileMapLength = 0;

            if (!IsAnonymous)
            {
                FileDescriptorEntry Entry = Helper.DescriptorTable.GetEntry(fd);
                if (Entry == null)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                    return;
                }

                FileDesc = Entry.Object as FileObject;
                if (FileDesc == null)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                    return;
                }

                if (FileDesc.IsDirectory)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EACCES);
                    return;
                }

                if (FileDesc.IsSpecialPath || string.IsNullOrWhiteSpace(FileDesc.HostPath) || !File.Exists(FileDesc.HostPath))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENODEV);
                    return;
                }

                int AccessMode = FileDesc.StatusFlags & 0x3;
                bool CanRead = AccessMode == 0 || AccessMode == 2;
                bool CanWrite = AccessMode == 1 || AccessMode == 2;

                if (!CanRead)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EACCES);
                    return;
                }

                if (IsShared && (prot & 0x2) != 0 && !CanWrite)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EACCES);
                    return;
                }

                try
                {
                    FileMapLength = new FileInfo(FileDesc.HostPath).Length;
                }
                catch (UnauthorizedAccessException)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EACCES);
                    return;
                }
                catch (IOException)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EIO);
                    return;
                }
                catch
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
                }

                if (offset > long.MaxValue)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
                }
            }

            MemoryProtection Protection = Helper.TranslateLinuxMemToNative(prot);
            MappingReservation Reservation;

            if (IsNoReplace)
            {
                if (!IsPageAligned(addr) || WouldOverflow(addr, AlignedLength))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
                }

                if (Instance.IsRegionMapped(addr, AlignedLength))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EEXIST);
                    return;
                }

                if (!TryMapExactNoReplace(Instance, addr, length, AlignedLength, Protection, out Reservation))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOMEM);
                    return;
                }
            }
            else if (IsFixed)
            {
                if (!IsPageAligned(addr) || WouldOverflow(addr, AlignedLength))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
                }

                if (!TryMapFixed(Instance, addr, length, AlignedLength, Protection, out Reservation))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOMEM);
                    return;
                }
            }
            else
            {
                if (!TryMapNonFixed(Instance, addr, length, AlignedLength, Protection, out Reservation))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOMEM);
                    return;
                }
            }

            if (!PopulateFileMapping(Instance, Helper, Context, Reservation, length, FileDesc, offset, FileMapLength))
                return;

            LinuxGuest Linux = Instance.Guest as LinuxGuest;
            if (Linux != null && FileDesc != null)
                Linux.RegisterMappedFileModule(FileDesc.Path, FileDesc.HostPath, Reservation.Address, AlignedLength, offset);

            Helper.SetReturnValue(Instance, Context, Reservation.Address);
        }

        private bool TryMapNonFixed(BinaryEmulator Instance, ulong AddressHint, ulong RequestedLength, ulong AlignedLength, MemoryProtection Protection, out MappingReservation Reservation)
        {
            Reservation = default;

            if (AddressHint != 0)
            {
                ulong Candidate = AlignAddressDown(AddressHint);
                if (!WouldOverflow(Candidate, AlignedLength) && !Instance.IsRegionMapped(Candidate, AlignedLength))
                {
                    ulong HintAddress = Instance.MapMemoryRegion(Candidate, RequestedLength, Protection);
                    if (HintAddress != 0)
                    {
                        Reservation = CreateSimpleReservation(HintAddress, AlignedLength);
                        return true;
                    }
                }
            }

            ulong Address = Instance.MapMemoryRegion(0, RequestedLength, Protection);
            if (Address == 0)
                return false;

            Reservation = CreateSimpleReservation(Address, AlignedLength);
            return true;
        }

        private MappingReservation CreateSimpleReservation(ulong Address, ulong Size)
        {
            return new MappingReservation()
            {
                Address = Address,
                AddedSegments = new List<MappedSegment>()
                {
                    new MappedSegment()
                    {
                        Address = Address,
                        Size = Size,
                    }
                },
                RemovedRegions = new List<RemapRegion>()
            };
        }

        private bool TryMapExactNoReplace(BinaryEmulator Instance, ulong Address, ulong RequestedLength, ulong AlignedLength, MemoryProtection Protection, out MappingReservation Reservation)
        {
            Reservation = default;

            if (!Instance._emulator.MapMemory(Address, AlignedLength, Protection))
                return false;

            MemoryRegion Region = new MemoryRegion()
            {
                BaseAddress = Address,
                Size = RequestedLength,
                InitialProtections = Protection,
                Protections = Protection,
            };

            if (RequestedLength < AlignedLength)
            {
                Region.PoisonedMemory = (Address + RequestedLength, Address + AlignedLength);
            }

            Instance.AddMemoryRegion(Region);
            Reservation = CreateSimpleReservation(Address, AlignedLength);
            return true;
        }

        private bool PopulateFileMapping(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, MappingReservation Reservation, ulong Length, FileObject FileDesc, ulong Offset, long FileMapLength)
        {
            if (FileDesc == null)
                return true;

            long ReadOffset = checked((long)Offset);
            if (ReadOffset >= FileMapLength)
                return true;

            ulong AvailableLength = (ulong)(FileMapLength - ReadOffset);
            ulong CopyLength = Math.Min(Length, AvailableLength);
            if (CopyLength == 0)
                return true;

            try
            {
                Span<byte> Buffer = Helper.Shared.GetSpan((ulong)FILE_COPY_CHUNK_SIZE);
                using FileStream Stream = new FileStream(FileDesc.HostPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                Stream.Seek(ReadOffset, SeekOrigin.Begin);

                ulong CurrentAddress = Reservation.Address;
                ulong Remaining = CopyLength;

                while (Remaining > 0)
                {
                    int RequestedRead = (int)Math.Min((ulong)Buffer.Length, Remaining);
                    int TotalRead = 0;

                    while (TotalRead < RequestedRead)
                    {
                        int BytesRead = Stream.Read(Buffer.Slice(TotalRead, RequestedRead - TotalRead));
                        if (BytesRead <= 0)
                            break;

                        TotalRead += BytesRead;
                    }

                    if (TotalRead <= 0)
                        break;

                    if (!Instance.WriteMemory(CurrentAddress, Buffer.Slice(0, TotalRead)))
                    {
                        RollbackReservation(Instance, Reservation);
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EIO);
                        return false;
                    }

                    CurrentAddress += (ulong)TotalRead;
                    Remaining -= (ulong)TotalRead;

                    if (TotalRead < RequestedRead)
                        break;
                }
            }
            catch (UnauthorizedAccessException)
            {
                RollbackReservation(Instance, Reservation);
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EACCES);
                return false;
            }
            catch (IOException)
            {
                RollbackReservation(Instance, Reservation);
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EIO);
                return false;
            }
            catch
            {
                RollbackReservation(Instance, Reservation);
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return false;
            }

            return true;
        }

        private bool TryMapFixed(BinaryEmulator Instance, ulong Address, ulong RequestedLength, ulong AlignedLength, MemoryProtection Protection, out MappingReservation Reservation)
        {
            Reservation = new MappingReservation()
            {
                Address = Address,
                AddedSegments = new List<MappedSegment>(),
                RemovedRegions = new List<RemapRegion>()
            };

            ulong MapEnd = Address + AlignedLength;
            List<RemapRegion> Overlaps = new List<RemapRegion>();

            List<MemoryRegion> OverlappingRegions = new List<MemoryRegion>();
            Instance.AddOverlappingMemoryRegions(Address, AlignedLength, OverlappingRegions);

            foreach (MemoryRegion Region in OverlappingRegions)
            {
                ulong RegionStart = Region.BaseAddress;
                ulong RegionSize = Instance.AlignToPageSize(Region.Size);
                byte[] Data = Instance._emulator.ReadMemory(RegionStart, RegionSize);
                Overlaps.Add(new RemapRegion()
                {
                    Region = Region,
                    Data = Data,
                });
            }

            foreach (RemapRegion Overlap in Overlaps)
            {
                ulong RegionStart = Overlap.Region.BaseAddress;
                ulong RegionSize = Instance.AlignToPageSize(Overlap.Region.Size);

                if (!Instance._emulator.UnmapMemory(RegionStart, RegionSize))
                {
                    RestoreMappings(Instance, Reservation.RemovedRegions);
                    return false;
                }

                Instance.RemoveMemoryRegion(Overlap.Region);
                Reservation.RemovedRegions.Add(Overlap);
            }

            if (!Instance._emulator.MapMemory(Address, AlignedLength, Protection))
            {
                RestoreMappings(Instance, Reservation.RemovedRegions);
                return false;
            }

            MemoryRegion NewRegion = new MemoryRegion()
            {
                BaseAddress = Address,
                Size = RequestedLength,
                InitialProtections = Protection,
                Protections = Protection,
            };

            if (RequestedLength < AlignedLength)
            {
                NewRegion.PoisonedMemory = (Address + RequestedLength, Address + AlignedLength);
            }

            Instance.AddMemoryRegion(NewRegion);
            Reservation.AddedSegments.Add(new MappedSegment()
            {
                Address = Address,
                Size = AlignedLength,
            });

            foreach (RemapRegion Overlap in Overlaps)
            {
                ulong RegionStart = Overlap.Region.BaseAddress;
                ulong RegionSize = Instance.AlignToPageSize(Overlap.Region.Size);
                ulong RegionEnd = RegionStart + RegionSize;

                if (RegionStart < Address)
                {
                    ulong PrefixSize = Address - RegionStart;
                    if (!TryRestoreSegment(Instance, Overlap.Region, Overlap.Data, RegionStart, PrefixSize, 0))
                    {
                        RollbackReservation(Instance, Reservation);
                        return false;
                    }

                    Reservation.AddedSegments.Add(new MappedSegment()
                    {
                        Address = RegionStart,
                        Size = PrefixSize,
                    });
                }

                if (RegionEnd > MapEnd)
                {
                    ulong SuffixStart = MapEnd;
                    ulong SuffixSize = RegionEnd - SuffixStart;
                    int DataOffset = checked((int)(SuffixStart - RegionStart));
                    if (!TryRestoreSegment(Instance, Overlap.Region, Overlap.Data, SuffixStart, SuffixSize, DataOffset))
                    {
                        RollbackReservation(Instance, Reservation);
                        return false;
                    }

                    Reservation.AddedSegments.Add(new MappedSegment()
                    {
                        Address = SuffixStart,
                        Size = SuffixSize,
                    });
                }
            }

            return true;
        }

        private void RollbackReservation(BinaryEmulator Instance, MappingReservation Reservation)
        {
            if (Reservation.AddedSegments != null)
            {
                foreach (MappedSegment Segment in Reservation.AddedSegments)
                {
                    Instance._emulator.UnmapMemory(Segment.Address, Segment.Size);
                    Instance.RemoveMemoryRegions(x => x.BaseAddress == Segment.Address && Instance.AlignToPageSize(x.Size) == Segment.Size);
                }
            }

            if (Reservation.RemovedRegions != null && Reservation.RemovedRegions.Count > 0)
            {
                RestoreMappings(Instance, Reservation.RemovedRegions);
            }
        }

        private void RestoreMappings(BinaryEmulator Instance, List<RemapRegion> Regions)
        {
            foreach (RemapRegion Region in Regions)
            {
                ulong RegionStart = Region.Region.BaseAddress;
                ulong RegionSize = Instance.AlignToPageSize(Region.Region.Size);
                Instance._emulator.MapMemory(RegionStart, RegionSize, Region.Region.Protections);
                Instance._emulator.WriteMemory(RegionStart, Region.Data);

                if (!Instance.TryFindMemoryRegionByBase(Region.Region.BaseAddress, out _, out MemoryRegion ExistingRegion) || ExistingRegion.Size != Region.Region.Size)
                {
                    Instance.AddMemoryRegion(Region.Region);
                }
            }
        }

        private bool TryRestoreSegment(BinaryEmulator Instance, MemoryRegion OriginalRegion, byte[] Data, ulong SegmentStart, ulong SegmentSize, int DataOffset)
        {
            if (!Instance._emulator.MapMemory(SegmentStart, SegmentSize, OriginalRegion.Protections))
                return false;

            if (!Instance._emulator.WriteMemory(SegmentStart, Data, DataOffset, checked((int)SegmentSize)))
            {
                Instance._emulator.UnmapMemory(SegmentStart, SegmentSize);
                return false;
            }

            MemoryRegion Region = OriginalRegion;
            Region.BaseAddress = SegmentStart;
            Region.Size = SegmentSize;
            Region.PoisonedMemory = default;

            Instance.AddMemoryRegion(Region);
            return true;
        }

        private bool IsPageAligned(ulong Address)
        {
            return (Address & (PAGE_SIZE - 1)) == 0;
        }

        private ulong AlignAddressDown(ulong Address)
        {
            return Address & ~(PAGE_SIZE - 1);
        }

        private bool WouldOverflow(ulong Address, ulong Size)
        {
            return Address > ulong.MaxValue - Size;
        }
    }
}
