using System;
using System.Buffers.Binary;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryVirtualMemory : IWinSyscall
    {
        private const ulong MemCommit = 0x00001000UL;
        private const ulong MemReserve = 0x00002000UL;
        private const ulong MemFree = 0x00010000UL;

        private const ulong MemPrivate = 0x00020000UL;
        private const ulong MemImage = 0x01000000UL;

        private const ulong PageGuard = 0x00000100UL;

        private static ulong AlignDownPage(ulong Address)
        {
            return Address & ~0xFFFUL;
        }

        private static bool IsCurrentProcess(BinaryEmulator Instance, ulong ProcessHandle)
        {
            if (ProcessHandle == ulong.MaxValue)
                return true;

            WinProcess Proc = Instance.WinHelper.HandleManager.GetObjectByHandle<WinProcess>(ProcessHandle);
            if (Proc != null && Proc.PID == Instance.WinHelper.PID)
                return true;

            return false;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
                ulong Address = Instance.WinHelper.GetArg64(1);
                MEMORY_INFORMATION_CLASS MemoryInformationClass = (MEMORY_INFORMATION_CLASS)Instance.WinHelper.GetArg64(2);
                ulong MemoryInformation = Instance.WinHelper.GetArg64(3);
                ulong MemoryInformationLength = Instance.WinHelper.GetArg64(4);
                ulong ReturnLength = Instance.WinHelper.GetArg64(5);

                if (!IsCurrentProcess(Instance, ProcessHandle))
                    return Instance.WinUnimplemented;

                if (MemoryInformation == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (ReturnLength != 0 && !Instance.IsRegionMapped(ReturnLength, 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (MemoryInformationClass == MEMORY_INFORMATION_CLASS.MemoryBasicInformation || MemoryInformationClass == MEMORY_INFORMATION_CLASS.MemoryPrivilegedBasicInformation)
                {
                    ulong RequiredLength = (ulong)StructSerializer.GetStructSize<MEMORY_BASIC_INFORMATION>(Instance);

                    if (ReturnLength != 0)
                    {
                        if (!Instance._emulator.WriteMemory(ReturnLength, RequiredLength))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                    if (MemoryInformationLength < RequiredLength)
                        return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                    if (!Instance.IsRegionMapped(MemoryInformation, RequiredLength))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    ulong QueryAddress = AlignDownPage(Address);

                    bool HasRegion = Instance.TryFindMemoryRegion(QueryAddress, out MemoryRegion Region);

                    MemoryRegion Freed = default;
                    bool HasFreed = false;

                    if (!HasRegion)
                    {
                        Freed = Instance._freedmemory.FirstOrDefault(R => QueryAddress >= R.BaseAddress && QueryAddress < (R.BaseAddress + R.Size));
                        HasFreed = Freed.BaseAddress != 0;
                    }

                    MEMORY_BASIC_INFORMATION Info = new MEMORY_BASIC_INFORMATION();

                    if (HasRegion)
                    {
                        bool IsImage = Region.Flags.HasFlag(AllocationType.Image);

                        bool IsCommitted =
                            Region.IsCommitted ||
                            Region.Flags.HasFlag(AllocationType.Commited) ||
                            IsImage ||
                            Region.Protections != MemoryProtection.None;

                        bool IsReserved =
                            Region.IsReserved ||
                            Region.Flags.HasFlag(AllocationType.Reserved) ||
                            (!IsCommitted && Region.BaseAddress != 0);

                        Info.BaseAddress = Region.BaseAddress;

                        ulong AllocationBase = Region.AllocationBase != 0 ? Region.AllocationBase : Region.BaseAddress;
                        Info.AllocationBase = AllocationBase;

                        ulong AllocationProtect = Region.AllocationProtect != 0 ? Region.AllocationProtect : Instance.WinHelper.ConvertInternalToWinProtect(Region.InitialProtections);

                        Info.AllocationProtect = (uint)AllocationProtect;

                        Info.PartitionId = 0;
                        Info.RegionSize = Region.Size;

                        if (IsCommitted)
                            Info.State = (uint)MemCommit;
                        else if (IsReserved)
                            Info.State = (uint)MemReserve;
                        else
                            Info.State = 0;

                        if (IsCommitted)
                        {
                            ulong Protect = Instance.WinHelper.ConvertInternalToWinProtect(Region.Protections);
                            if (Region.SpecialProtections.HasFlag(SpecialProtections.Guard))
                                Protect |= PageGuard;

                            Info.Protect = (uint)Protect;
                        }
                        else
                        {
                            Info.Protect = 0;
                        }

                        Info.Type = IsImage ? (uint)MemImage : (uint)MemPrivate;
                    }
                    else
                    {
                        ulong FreeBase;
                        ulong FreeSize;

                        if (HasFreed)
                        {
                            FreeBase = Freed.BaseAddress;
                            FreeSize = Freed.Size;
                        }
                        else
                        {
                            ulong Next = ulong.MaxValue;

                            if (Instance.TryFindNextMemoryRegionBase(QueryAddress, out ulong NextMapped) && NextMapped < Next)
                                Next = NextMapped;

                            foreach (var R in Instance._freedmemory)
                            {
                                if (R.BaseAddress > QueryAddress && R.BaseAddress < Next)
                                    Next = R.BaseAddress;
                            }

                            FreeBase = QueryAddress;
                            FreeSize = (Next == ulong.MaxValue) ? 0x1000UL : (Next - FreeBase);
                            if (FreeSize == 0)
                                FreeSize = 0x1000UL;
                        }

                        Info.BaseAddress = FreeBase;
                        Info.AllocationBase = 0;
                        Info.AllocationProtect = 0;
                        Info.PartitionId = 0;
                        Info.RegionSize = FreeSize;
                        Info.State = (uint)MemFree;
                        Info.Protect = 0;
                        Info.Type = 0;
                    }

                    Span<byte> Data = Instance.WinHelper.Shared.GetSpan(RequiredLength);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x00, 8), Info.BaseAddress);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x08, 8), Info.AllocationBase);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x10, 4), Info.AllocationProtect);
                    BinaryPrimitives.WriteUInt16LittleEndian(Data.Slice(0x14, 2), Info.PartitionId);
                    BinaryPrimitives.WriteUInt16LittleEndian(Data.Slice(0x16, 2), Info.Reserved);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x18, 8), Info.RegionSize);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x20, 4), Info.State);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x24, 4), Info.Protect);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x28, 4), Info.Type);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x2C, 4), Info.Reserved2);

                    if (!Instance.WriteMemory(MemoryInformation, Data.Slice(0, (int)RequiredLength)))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    return NTSTATUS.STATUS_SUCCESS;
                }


                if (MemoryInformationClass == MEMORY_INFORMATION_CLASS.MemoryMappedFilenameInformation)
                {
                    if (!Instance.IsRegionMapped(MemoryInformation, MemoryInformationLength))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    WinModule Module = Instance.WinHelper.FindMappedImageViewByAddress(Address);
                    if (Module == null)
                        return NTSTATUS.STATUS_INVALID_ADDRESS;

                    string Path = !string.IsNullOrEmpty(Module.Path) ? Module.Path : Module.Name;
                    if (string.IsNullOrEmpty(Path))
                        Path = Module.CanonicalImagePath;

                    if (string.IsNullOrEmpty(Path))
                        return NTSTATUS.STATUS_INVALID_ADDRESS;

                    if (!Path.StartsWith("\\", StringComparison.Ordinal))
                        Path = "\\??\\" + Path;

                    int StringByteCount = Encoding.Unicode.GetByteCount(Path) + 2;
                    Span<byte> StringData = Instance.WinHelper.Shared.GetSpan((uint)StringByteCount);
                    Encoding.Unicode.GetBytes(Path.AsSpan(), StringData);
                    StringData[StringByteCount - 2] = 0;
                    StringData[StringByteCount - 1] = 0;
                    ulong RequiredLength = 0x10UL + (ulong)StringByteCount;

                    if (ReturnLength != 0)
                    {
                        if (!Instance._emulator.WriteMemory(ReturnLength, RequiredLength))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                    if (MemoryInformationLength < RequiredLength)
                        return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                    ulong Buffer = MemoryInformation + 0x10;
                    ushort Length = (ushort)(StringByteCount - 2);
                    ushort MaximumLength = (ushort)StringByteCount;

                    if (!Instance._emulator.WriteMemory(MemoryInformation + 0x0, Length, 2))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(MemoryInformation + 0x2, MaximumLength, 2))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(MemoryInformation + 0x4, 0u, 4))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(MemoryInformation + 0x8, Buffer, 8))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance.WriteMemory(Buffer, StringData.Slice(0, StringByteCount)))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    return NTSTATUS.STATUS_SUCCESS;
                }

                if (MemoryInformationClass == MEMORY_INFORMATION_CLASS.MemoryWorkingSetExInformation)
                {
                    ulong ElementSize = (ulong)StructSerializer.GetStructSize<MEMORY_WORKING_SET_EX_INFORMATION>(Instance);

                    if (ReturnLength != 0)
                    {
                        if (!Instance._emulator.WriteMemory(ReturnLength, MemoryInformationLength))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                    if (MemoryInformationLength < ElementSize)
                        return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                    if ((MemoryInformationLength % ElementSize) != 0)
                        return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                    if (!Instance.IsRegionMapped(MemoryInformation, MemoryInformationLength))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    ulong BuildFlags(bool Valid, ulong Win32Protect, bool Shared)
                    {
                        ulong Flags = 0;

                        if (!Valid)
                            return 0;

                        ulong ShareCount = Shared ? 1UL : 0UL;

                        Flags |= 1UL; // Valid
                        Flags |= (ShareCount & 0x7UL) << 1;
                        Flags |= (Win32Protect & 0x7FFUL) << 4;
                        Flags |= (Shared ? 1UL : 0UL) << 15;
                        Flags |= 0UL << 16; // Node
                        Flags |= 0UL << 22; // Locked
                        Flags |= 0UL << 23; // LargePage
                        Flags |= 0UL << 24; // Priority
                        Flags |= 0UL << 27; // Reserved
                        Flags |= (Shared ? 1UL : 0UL) << 30; // SharedOriginal
                        Flags |= 0UL << 31; // Bad
                        return Flags;
                    }

                    ulong Count = MemoryInformationLength / ElementSize;
                    for (ulong i = 0; i < Count; i++)
                    {
                        ulong Entry = MemoryInformation + (i * ElementSize);
                        ulong Va = Instance._emulator.ReadMemoryULong(Entry + 0x0);

                        ulong PageVa = AlignDownPage(Va);

                        bool HasRegion = Instance.TryFindMemoryRegion(PageVa, out MemoryRegion Region);
                        bool IsImage = HasRegion && Region.Flags.HasFlag(AllocationType.Image);

                        bool IsCommitted =
                            HasRegion &&
                            (Region.IsCommitted ||
                             Region.Flags.HasFlag(AllocationType.Commited) ||
                             IsImage ||
                             Region.Protections != MemoryProtection.None);

                        ulong Protect = 0;
                        if (IsCommitted)
                        {
                            Protect = Instance.WinHelper.ConvertInternalToWinProtect(Region.Protections);
                            if (Region.SpecialProtections.HasFlag(SpecialProtections.Guard))
                                Protect |= PageGuard;
                        }

                        ulong Flags = BuildFlags(IsCommitted, Protect, IsImage);

                        if (!Instance._emulator.WriteMemory(Entry + 0x8, Flags))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                    return NTSTATUS.STATUS_SUCCESS;
                }

                if (MemoryInformationClass == MEMORY_INFORMATION_CLASS.MemoryImageExtensionInformation)
                {
                    ulong RequiredLength = (ulong)StructSerializer.GetStructSize<MEMORY_IMAGE_EXTENSION_INFORMATION>(Instance);

                    if (ReturnLength != 0)
                    {
                        if (!Instance._emulator.WriteMemory(ReturnLength, RequiredLength))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                    if (MemoryInformationLength < RequiredLength)
                        return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                    if (!Instance.IsRegionMapped(MemoryInformation, RequiredLength))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    ulong QueryAddress = AlignDownPage(Address);

                    if (!Instance.TryFindMemoryRegion(QueryAddress, out MemoryRegion Region) || !Region.Flags.HasFlag(AllocationType.Image))
                        return NTSTATUS.STATUS_INVALID_ADDRESS;

                    uint RequestedType = Instance._emulator.ReadMemoryUInt(MemoryInformation + 0x0);
                    if (RequestedType > 1)
                        RequestedType = 0;

                    MEMORY_IMAGE_EXTENSION_INFORMATION Info = new MEMORY_IMAGE_EXTENSION_INFORMATION
                    {
                        ExtensionType = (MEMORY_IMAGE_EXTENSION_TYPE)RequestedType,
                        Flags = 0,
                        ExtensionImageBaseRva = 0,
                        ExtensionSize = 0
                    };

                    Span<byte> Data = Instance.WinHelper.Shared.GetSpan(RequiredLength);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x00, 4), (uint)Info.ExtensionType);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x04, 4), Info.Flags);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x08, 8), Info.ExtensionImageBaseRva);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x10, 8), Info.ExtensionSize);

                    if (!Instance.WriteMemory(MemoryInformation, Data.Slice(0, (int)RequiredLength)))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    return NTSTATUS.STATUS_SUCCESS;
                }

                if (MemoryInformationClass == MEMORY_INFORMATION_CLASS.MemoryRegionInformation)
                {
                    ulong RequiredLength = (ulong)StructSerializer.GetStructSize<MEMORY_REGION_INFORMATION>(Instance);

                    if (ReturnLength != 0)
                    {
                        if (!Instance._emulator.WriteMemory(ReturnLength, RequiredLength))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                    if (MemoryInformationLength < RequiredLength)
                        return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                    if (!Instance.IsRegionMapped(MemoryInformation, RequiredLength))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    ulong QueryAddress = AlignDownPage(Address);

                    if (!Instance.TryFindMemoryRegion(QueryAddress, out MemoryRegion Region))
                        return NTSTATUS.STATUS_INVALID_ADDRESS;

                    ulong GetAllocBase(MemoryRegion R)
                    {
                        if (R.AllocationBase != 0)
                            return R.AllocationBase;
                        return R.BaseAddress;
                    }

                    ulong AllocationBase = GetAllocBase(Region);

                    ulong MaxEnd = 0;
                    ulong CommitSize = 0;
                    bool AnyImage = false;

                    foreach (var R in Instance._memory)
                    {
                        if (GetAllocBase(R) != AllocationBase)
                            continue;

                        ulong End = R.BaseAddress + R.Size;
                        if (End > MaxEnd)
                            MaxEnd = End;

                        bool IsImage = R.Flags.HasFlag(AllocationType.Image);
                        AnyImage |= IsImage;

                        bool IsCommitted = R.IsCommitted || R.Flags.HasFlag(AllocationType.Commited) || IsImage || R.Protections != MemoryProtection.None;

                        if (IsCommitted)
                            CommitSize += R.Size;
                    }

                    if (MaxEnd <= AllocationBase)
                        MaxEnd = AllocationBase + Region.Size;

                    ulong AllocationProtect = Region.AllocationProtect != 0 ? Region.AllocationProtect : Instance.WinHelper.ConvertInternalToWinProtect(Region.InitialProtections);

                    uint RegionType = 0;
                    if (AnyImage)
                    {
                        RegionType |= (1u << 2); // MappedImage
                    }
                    else
                    {
                        RegionType |= 1u; // Private
                    }

                    MEMORY_REGION_INFORMATION Info = new MEMORY_REGION_INFORMATION
                    {
                        AllocationBase = AllocationBase,
                        AllocationProtect = (uint)AllocationProtect,
                        RegionType = RegionType,
                        RegionSize = MaxEnd - AllocationBase,
                        CommitSize = CommitSize,
                        PartitionId = 0,
                        NodePreference = ulong.MaxValue
                    };

                    Span<byte> Data = Instance.WinHelper.Shared.GetSpan(RequiredLength);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x00, 8), Info.AllocationBase);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x08, 4), Info.AllocationProtect);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x0C, 4), Info.RegionType);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x10, 8), Info.RegionSize);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x18, 8), Info.CommitSize);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x20, 8), Info.PartitionId);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x28, 8), Info.NodePreference);

                    if (!Instance.WriteMemory(MemoryInformation, Data.Slice(0, (int)RequiredLength)))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    return NTSTATUS.STATUS_SUCCESS;
                }

                if (MemoryInformationClass == MEMORY_INFORMATION_CLASS.MemoryImageInformation)
                {
                    ulong RequiredLength = (ulong)StructSerializer.GetStructSize<MEMORY_IMAGE_INFORMATION>(Instance);

                    if (ReturnLength != 0)
                    {
                        if (!Instance._emulator.WriteMemory(ReturnLength, RequiredLength))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                    if (MemoryInformationLength < RequiredLength)
                        return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                    if (!Instance.IsRegionMapped(MemoryInformation, RequiredLength))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    WinModule Module = Instance.WinHelper.FindMappedImageViewByAddress(Address);

                    if (Module == null)
                        return NTSTATUS.STATUS_INVALID_ADDRESS;

                    MEMORY_IMAGE_INFORMATION Info = new MEMORY_IMAGE_INFORMATION
                    {
                        ImageBase = Module.MappedBase,
                        SizeOfImage = Module.SizeOfImage,
                        Flags = 0
                    };

                    Span<byte> Data = Instance.WinHelper.Shared.GetSpan(RequiredLength);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x00, 8), Info.ImageBase);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x08, 8), Info.SizeOfImage);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x10, 8), Info.Flags);

                    if (!Instance.WriteMemory(MemoryInformation, Data.Slice(0, (int)RequiredLength)))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    return NTSTATUS.STATUS_SUCCESS;
                }

                Instance.TriggerEventMessage($"[-] NtQueryVirtualMemory was called with an unsupported class: 0x{MemoryInformationClass:X} ({MemoryInformationClass}).", LogFlags.Important);
            }
            else if (Instance._binary.Architecture == BinaryArchitecture.x86)
            {

            }
            return Instance.WinUnimplemented;
        }
    }
}