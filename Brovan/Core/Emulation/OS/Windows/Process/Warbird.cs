using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    // Kernel side of SystemControlFlowTransition (WbDispatchOperation). The kernel decrypts image segments in place and
    // encrypts them again, or runs a decrypted copy of code from an executable heap.
    internal sealed class Warbird
    {
        private const uint DecryptOperation = 1;
        private const uint EncryptOperation = 2;
        private const uint HeapExecuteCallOperation = 3;
        private const uint HeapExecuteReturnOperation = 4;
        private const uint RemoveProcessOperation = 7;
        private const uint HeapExecuteSettingsOperation = 8;
        private const uint UnloadModuleOperation = 9;

        private const uint SegmentRequestBytes = 0x10;
        private const uint HeapCallRequestBytes = 0x18;
        private const uint HeapCallSecondaryRequestBytes = 0x20;
        private const uint HeapCallArgumentsOffset = 0x10;
        private const uint HeapCallSecondaryOffset = 0x18;
        private const uint HeapExecuteSettingsBytes = 0x18;
        private const uint UnloadModuleBytes = 0x10;

        private const uint RvaMask = 0x0FFFFFFF;
        private const uint RelocationHighLow = 3;
        private const uint RelocationDir64 = 10;

        // The syscall return adds the length of the syscall instruction to a RIP that a handler wrote.
        private const ulong SyscallInstructionBytes = 2;

        private const int HashBytes = 0x20;
        private const int VersionOffset = 0x24;
        private const int DescriptorRvaOffset = 0x28;
        private const int RelocationRvaOffset = 0x2C;
        private const int RelocationCountOffset = 0x30;
        private const int PreferredBaseOffset = 0x38;
        private const int ImageIdOffset = 0x40;
        private const int KeyOffset = 0x48;
        private const int RoundsOffset = 0x50;
        private const int RoundCount = 10;
        private const int SegmentCountOffset = 0xF0;
        private const int MarkerOffset = 0xF4;
        private const int HeaderBytesV0 = 0xF4;
        private const int HeaderBytesV1 = 0xF8;
        private const int EntryBytesV0 = 12;
        private const int EntryBytesV1 = 16;

        private const int StackBytesOffset = 0x2C;
        private const int CodeRvaOffset = 0x34;
        private const int CodeBytesOffset = 0x38;
        private const int SplitRvaOffset = 0x3C;
        private const int SplitBytesOffset = 0x40;
        private const int FirstDwordOffset = 0xF0;
        private const int HeapDescriptorBytesV0 = 0xF0;
        private const int HeapDescriptorBytesV1 = 0xF8;
        private const uint MinimumStackBytes = 0x1000;
        private const uint BlockHeaderBytes = 0x10;
        private const uint MaximumBlockBytes = 0x10000;
        private const ulong HeapRegionBytes = 0x10000;
        private const int HeapUnitBytes = 64;
        private const int HeapUnits = (int)(HeapRegionBytes / HeapUnitBytes);
        private const uint MaximumBlockLimit = 60;

        private const uint SkipFirstDecrypt = 1;
        private const uint DataSegment = 2;

        private readonly Dictionary<(ulong ImageBase, uint Id), SegmentSet> Sets = new();
        private readonly Dictionary<ulong, HeapBlock> Blocks = new();
        private readonly LinkedList<HeapBlock> RecentBlocks = new();
        private readonly List<HeapRegion> Regions = new();
        private readonly Dictionary<uint, List<CallFrame>> Calls = new();
        private uint BlockLimit = MaximumBlockLimit;

        internal static NTSTATUS Query(BinaryEmulator Instance, ulong Buffer, uint Length, ulong ReturnLengthPtr)
        {
            // ExpQuerySystemInformation probes the buffer for write with 4-byte alignment.
            if (Length != 0)
            {
                if ((Buffer & 3) != 0)
                    return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

                if (!Instance.IsMemoryRangeMapped(Buffer, Length))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if (ReturnLengthPtr != 0 && !Instance.IsMemoryRangeMapped(ReturnLengthPtr, sizeof(uint)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = Dispatch(Instance, Buffer, Length);

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] Warbird request at 0x{Buffer:X} (0x{Length:X} bytes): {Status}", LogFlags.Syscall);

            if (ReturnLengthPtr != 0 && !Instance.WinHelper.WriteUInt32(ReturnLengthPtr, 0))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return Status;
        }

        private static NTSTATUS Dispatch(BinaryEmulator Instance, ulong Buffer, uint Length)
        {
            Span<byte> Request = stackalloc byte[(int)SegmentRequestBytes];
            uint Operation = HeapExecuteReturnOperation;
            if (Buffer != 0)
            {
                if (Length < sizeof(ulong))
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.ReadMemory(Buffer, Request.Slice(0, (int)Math.Min(Length, SegmentRequestBytes))))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Operation = BinaryPrimitives.ReadUInt32LittleEndian(Request);
            }

            WinSysHelper Helper = Instance.WinHelper;
            if (Operation == RemoveProcessOperation)
            {
                if (Helper.Warbird == null)
                    return NTSTATUS.STATUS_NO_MATCH;

                Helper.Warbird.ReleaseState(Instance);
                Helper.Warbird = null;
                return NTSTATUS.STATUS_SUCCESS;
            }

            Warbird Process = Helper.Warbird ??= new Warbird();
            ulong Argument = BinaryPrimitives.ReadUInt64LittleEndian(Request.Slice(8));

            switch (Operation)
            {
                case DecryptOperation:
                case EncryptOperation:
                    if (Length < SegmentRequestBytes)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    return Process.TransformSegments(Instance, Argument, Operation == DecryptOperation);

                case HeapExecuteCallOperation:
                    return Process.HeapExecuteCall(Instance, Buffer, Length, Argument);

                case HeapExecuteReturnOperation when Buffer == 0:
                    return Process.HeapExecuteReturn(Instance);

                case HeapExecuteSettingsOperation:
                    {
                        NTSTATUS Status = ReadModuleRequest(Instance, Request, Length, HeapExecuteSettingsBytes, out uint Limit, out _);
                        if (Status == NTSTATUS.STATUS_SUCCESS && Process.BlockLimit != 0)
                            Process.BlockLimit = Math.Min(Limit, MaximumBlockLimit);

                        return Status;
                    }

                case UnloadModuleOperation:
                    {
                        NTSTATUS Status = ReadModuleRequest(Instance, Request, Length, UnloadModuleBytes, out _, out ulong ImageBase);
                        if (Status == NTSTATUS.STATUS_SUCCESS)
                            Process.Unload(ImageBase);

                        return Status;
                    }

                case 5:
                case 6:
                    return NTSTATUS.STATUS_NOT_IMPLEMENTED;

                default:
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
            }
        }

        private static NTSTATUS ReadModuleRequest(BinaryEmulator Instance, ReadOnlySpan<byte> Request, uint Length, uint RecordBytes, out uint Value, out ulong ImageBase)
        {
            Value = 0;
            ImageBase = 0;
            uint Operation = BinaryPrimitives.ReadUInt32LittleEndian(Request);
            if (Length < SegmentRequestBytes || BinaryPrimitives.ReadUInt64LittleEndian(Request) != Operation)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Record = stackalloc byte[(int)HeapExecuteSettingsBytes];
            if (!Instance.ReadMemory(BinaryPrimitives.ReadUInt64LittleEndian(Request.Slice(8)), Record.Slice(0, (int)RecordBytes)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (BinaryPrimitives.ReadUInt32LittleEndian(Record) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Value = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(4));
            ImageBase = BinaryPrimitives.ReadUInt64LittleEndian(Record.Slice(8));
            return NTSTATUS.STATUS_SUCCESS;
        }

        private void Unload(ulong ImageBase)
        {
            for (LinkedListNode<HeapBlock>? Node = RecentBlocks.First; Node != null;)
            {
                LinkedListNode<HeapBlock>? Next = Node.Next;
                if (Node.Value.ImageBase == ImageBase)
                    Forget(Node.Value);

                Node = Next;
            }

            foreach ((ulong ImageBase, uint Id) Key in Sets.Keys)
            {
                if (Key.ImageBase == ImageBase)
                    Sets.Remove(Key);
            }
        }

        internal void ReleaseThread(uint ThreadId)
        {
            if (!Calls.Remove(ThreadId, out List<CallFrame>? Frames))
                return;

            foreach (CallFrame Frame in Frames)
                Release(Frame.Block);
        }

        // The heap regions stay mapped while a thread still runs in one of their blocks.
        private void ReleaseState(BinaryEmulator Instance)
        {
            while (RecentBlocks.First != null)
                Forget(RecentBlocks.First.Value);

            foreach (List<CallFrame> Frames in Calls.Values)
            {
                if (Frames.Count != 0)
                    return;
            }

            foreach (HeapRegion Region in Regions)
                Instance.ReleaseMemory(Region.Base);

            Regions.Clear();
        }

        private NTSTATUS TransformSegments(BinaryEmulator Instance, ulong Descriptor, bool Decrypt)
        {
            Span<byte> Header = stackalloc byte[HeaderBytesV1];
            if (!Instance.ReadMemory(Descriptor, Header.Slice(0, HeaderBytesV0)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint Version = Header[VersionOffset] & 0xFu;
            if (Version > 1)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            int HeaderBytes = Version == 0 ? HeaderBytesV0 : HeaderBytesV1;
            if (Version == 1 && !Instance.ReadMemory(Descriptor + HeaderBytesV0, Header.Slice(HeaderBytesV0)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong ImageBase = Descriptor - (BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(DescriptorRvaOffset)) & RvaMask);
            uint Id = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(ImageIdOffset));

            if (!Sets.TryGetValue((ImageBase, Id), out SegmentSet? Set))
            {
                NTSTATUS Status = SegmentSet.Create(Instance, Descriptor, Header.Slice(0, HeaderBytes), Version, out Set);
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;

                Sets.Add((ImageBase, Id), Set!);
            }

            return Decrypt ? Set!.Decrypt(Instance) : Set!.Encrypt(Instance);
        }

        // NT checks the signing level of the image. Memory outside an image has none, and Brovan passes every image.
        private static NTSTATUS CheckImageRange(BinaryEmulator Instance, ulong Address, uint Size, bool ExecuteRead)
        {
            NTSTATUS Status = NtQueryVirtualMemory.QueryImageView(Instance, Address, out WinModule? Module);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Module == null)
                return NTSTATUS.STATUS_INVALID_IMAGE_HASH;

            return ExecuteRead ? CheckExecuteRead(Instance, Address, Size) : NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS CheckExecuteRead(BinaryEmulator Instance, ulong Address, uint Size)
        {
            NTSTATUS Status = NtQueryVirtualMemory.BuildBasicInformation(Instance, Address, out MEMORY_BASIC_INFORMATION Info);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Address < Info.BaseAddress || Address + Size > Info.BaseAddress + Info.RegionSize || Info.Protect != WinSysHelper.PAGE_EXECUTE_READ)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool HashMatches(ReadOnlySpan<byte> Descriptor)
        {
            Span<byte> Hash = stackalloc byte[HashBytes];
            SHA256.HashData(Descriptor.Slice(HashBytes), Hash);
            return Hash.SequenceEqual(Descriptor.Slice(0, HashBytes));
        }

        private static NTSTATUS UnsupportedHeapExecution(BinaryEmulator Instance)
        {
            if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                Instance.TriggerEventMessage("[!] Warbird heap execution in a WOW64 process is not implemented.", LogFlags.Issues);
            return Instance.WinUnimplemented;
        }

        // The block runs on the caller's stack with a pointer to the request arguments in its first slot. Operation 4
        // ends it and resumes the caller after this system call.
        private NTSTATUS HeapExecuteCall(BinaryEmulator Instance, ulong Request, uint Length, ulong Descriptor)
        {
            if (Length < HeapCallRequestBytes)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsX64Guest)
                return UnsupportedHeapExecution(Instance);

            Span<byte> Header = stackalloc byte[HeapDescriptorBytesV1];
            if (!Instance.ReadMemory(Descriptor, Header.Slice(0, HeapDescriptorBytesV0)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint Version = Header[VersionOffset] & 0xFu;
            if (Version > 1)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Version == 1 && !Instance.ReadMemory(Descriptor + HeapDescriptorBytesV0, Header.Slice(HeapDescriptorBytesV0)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ReadOnlySpan<byte> Copy = Header.Slice(0, Version == 0 ? HeapDescriptorBytesV0 : HeapDescriptorBytesV1);
            if ((BinaryPrimitives.ReadUInt32LittleEndian(Copy.Slice(CodeBytesOffset)) & RvaMask) == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            HeapLayout Layout = new HeapLayout(Descriptor, Copy, Version);
            NTSTATUS Status = GetBlock(Instance, Descriptor, Copy, Layout, out HeapBlock? Block);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            EmulatedThread? Thread = Instance.CurrentThread;
            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            ulong SyscallRip = Instance.WinHelper.GetSyscallRip();
            ulong Rsp = Instance.ReadRegister(Registers.UC_X86_REG_RSP);
            ulong EFlags = Instance.ReadRegister(Registers.UC_X86_REG_EFLAGS);

            if (!Calls.TryGetValue(Thread.ThreadId, out List<CallFrame>? Frames))
            {
                Frames = new List<CallFrame>();
                Calls.Add(Thread.ThreadId, Frames);
            }

            // NT keeps the frame when the steps below fail.
            Frames.Add(new CallFrame(Block!, SyscallRip, Rsp, EFlags));
            Block!.References++;

            if (Block.Secondary != 0 && Length < HeapCallSecondaryRequestBytes)
                return NTSTATUS.STATUS_BUFFER_OVERFLOW;

            ulong ProbeBase = Rsp - ((ulong)(Layout.StackBytes >> 10) << 10);
            if (ProbeBase > Rsp || !Instance.WinHelper.TryMapUserFrame(ProbeBase, Rsp + sizeof(ulong) - ProbeBase, out _))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong BlockRsp = ((Rsp - 32) & 0xF) != 0 ? Rsp - 48 : Rsp - 40;
            if (!Instance.WinHelper.WritePointer(BlockRsp, Request + HeapCallArgumentsOffset))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Block.Secondary != 0 && !Instance.WinHelper.WritePointer(Request + HeapCallSecondaryOffset, Block.Secondary))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance.WriteRegister(Registers.UC_X86_REG_RSP, BlockRsp);
            if ((EFlags & (ulong)CPUFlags.TF) != 0)
                Instance.WriteRegister(Registers.UC_X86_REG_EFLAGS, EFlags & ~(ulong)CPUFlags.TF);
            Instance.WriteRegister(Registers.UC_X86_REG_RIP, Block.Code - SyscallInstructionBytes);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS HeapExecuteReturn(BinaryEmulator Instance)
        {
            if (!Instance.IsX64Guest)
                return UnsupportedHeapExecution(Instance);

            EmulatedThread? Thread = Instance.CurrentThread;
            if (Thread == null || !Calls.TryGetValue(Thread.ThreadId, out List<CallFrame>? Frames) || Frames.Count == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            CallFrame Frame = Frames[Frames.Count - 1];
            Frames.RemoveAt(Frames.Count - 1);

            Instance.WriteRegister(Registers.UC_X86_REG_RSP, Frame.Rsp);
            Instance.WriteRegister(Registers.UC_X86_REG_EFLAGS, Frame.EFlags);
            Instance.WriteRegister(Registers.UC_X86_REG_RIP, Frame.SyscallRip);
            Release(Frame.Block);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS GetBlock(BinaryEmulator Instance, ulong Descriptor, ReadOnlySpan<byte> Copy, in HeapLayout Layout, out HeapBlock? Block)
        {
            for (int Excess = Blocks.Count - (int)BlockLimit; Excess > 0 && RecentBlocks.First != null; Excess--)
                Forget(RecentBlocks.First.Value);

            if (Blocks.TryGetValue(Layout.Source, out Block))
            {
                RecentBlocks.Remove(Block.Recent);
                RecentBlocks.AddLast(Block.Recent);
                return NTSTATUS.STATUS_SUCCESS;
            }

            NTSTATUS Status = CreateBlock(Instance, Descriptor, Copy, Layout, out Block);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Blocks.Add(Layout.Source, Block!);
            RecentBlocks.AddLast(Block!.Recent);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS CreateBlock(BinaryEmulator Instance, ulong Descriptor, ReadOnlySpan<byte> Copy, in HeapLayout Layout, out HeapBlock? Block)
        {
            Block = null;
            if (!HashMatches(Copy))
                return NTSTATUS.STATUS_INVALID_IMAGE_HASH;

            NTSTATUS Status = CheckImageRange(Instance, Descriptor, (uint)Copy.Length, true);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Layout.TotalBytes > MaximumBlockBytes)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Status = AllocateBlock(Instance, Layout.TotalBytes, out HeapRegion? Region, out int FirstUnit, out int Units);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            ulong Base = Region!.Base + (ulong)(FirstUnit * HeapUnitBytes);
            ulong Code = Base + BlockHeaderBytes;
            Span<byte> Data = Instance.WinHelper.Shared.GetSpan(Layout.TotalBytes);

            Cipher Keys = new Cipher(Copy);
            Status = LoadCode(Instance, in Keys, Layout.Source, Layout.SourceRva, Data.Slice((int)BlockHeaderBytes, (int)Layout.SourceBytes),
                Layout.Version, Layout.SourceFirstDword);
            if (Status == NTSTATUS.STATUS_SUCCESS && Layout.Secondary != 0)
                Status = LoadCode(Instance, in Keys, Layout.Secondary, Layout.SecondaryRva,
                    Data.Slice((int)Layout.SecondaryOffset, (int)Layout.SecondaryBytes), Layout.Version, Layout.SecondaryFirstDword);

            if (Status != NTSTATUS.STATUS_SUCCESS)
            {
                Region.Free(FirstUnit, Units);
                return Status;
            }

            // NT puts the distance from the code back to its source and the service number of this call in the block
            // header. The block returns through that service (WbCreateHeapExecutedBlock).
            BinaryPrimitives.WriteUInt64LittleEndian(Data, unchecked(Layout.Source - Code));
            BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(sizeof(ulong)), (uint)Instance.ReadRegister(Registers.UC_X86_REG_RAX));
            if (!Instance.WriteMemory(Base, Data))
            {
                Region.Free(FirstUnit, Units);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            Instance._emulator.InvalidateCodeRange(Base, Layout.TotalBytes);
            Block = new HeapBlock(Layout.Source, Layout.ImageBase, Region, FirstUnit, Units, Code,
                Layout.Secondary != 0 ? Base + Layout.SecondaryOffset : 0);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS LoadCode(BinaryEmulator Instance, in Cipher Keys, ulong Source, uint Rva, Span<byte> Target, uint Version, uint FirstDword)
        {
            if (!Instance.ReadMemory(Source, Target))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Version == 1)
            {
                if (Target.Length < sizeof(uint))
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                BinaryPrimitives.WriteUInt32LittleEndian(Target, FirstDword);
            }

            Keys.Transform(Target, Rva, true);
            return CheckImageRange(Instance, Source, (uint)Target.Length, true);
        }

        private NTSTATUS AllocateBlock(BinaryEmulator Instance, uint Bytes, out HeapRegion? Region, out int FirstUnit, out int Units)
        {
            Region = null;
            FirstUnit = 0;
            Units = (int)((Bytes + HeapUnitBytes - 1) / HeapUnitBytes);
            if (Units + 1 > HeapUnits)
                return NTSTATUS.STATUS_INTEGER_OVERFLOW;

            foreach (HeapRegion Existing in Regions)
            {
                if (Existing.TryReserve(Units, out FirstUnit))
                {
                    Region = Existing;
                    return NTSTATUS.STATUS_SUCCESS;
                }
            }

            ulong Base = 0;
            ulong Size = HeapRegionBytes;
            NTSTATUS Status = NtAllocateVirtualMemory.Allocate(Instance, ref Base, ref Size, NtAllocateVirtualMemory.MemCommit | NtAllocateVirtualMemory.MemReserve,
                WinSysHelper.PAGE_EXECUTE_READ, NtAllocateVirtualMemory.AddressRequirements.None);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Instance.SecureMemoryRegion(Base);
            Region = new HeapRegion(Base);
            Regions.Add(Region);
            Region.TryReserve(Units, out FirstUnit);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private void Forget(HeapBlock Block)
        {
            if (!Blocks.Remove(Block.Source))
                return;

            RecentBlocks.Remove(Block.Recent);
            Release(Block);
        }

        private static void Release(HeapBlock Block)
        {
            if (--Block.References == 0)
                Block.Region.Free(Block.FirstUnit, Block.Units);
        }

        private readonly struct HeapLayout
        {
            public readonly uint Version;
            public readonly ulong ImageBase;
            public readonly uint StackBytes;
            public readonly ulong Source;
            public readonly uint SourceRva;
            public readonly uint SourceBytes;
            public readonly uint SourceFirstDword;
            public readonly ulong Secondary;
            public readonly uint SecondaryRva;
            public readonly uint SecondaryBytes;
            public readonly uint SecondaryFirstDword;

            // A split descriptor runs the code at its second range and keeps the first range after it in the block.
            public HeapLayout(ulong Descriptor, ReadOnlySpan<byte> Copy, uint DescriptorVersion)
            {
                uint CodeRva = BinaryPrimitives.ReadUInt32LittleEndian(Copy.Slice(CodeRvaOffset)) & RvaMask;
                uint CodeBytes = BinaryPrimitives.ReadUInt32LittleEndian(Copy.Slice(CodeBytesOffset)) & RvaMask;
                uint SplitRva = BinaryPrimitives.ReadUInt32LittleEndian(Copy.Slice(SplitRvaOffset)) & RvaMask;
                uint SplitBytes = BinaryPrimitives.ReadUInt32LittleEndian(Copy.Slice(SplitBytesOffset)) & RvaMask;
                bool Split = SplitRva != 0;

                Version = DescriptorVersion;
                ImageBase = Descriptor - (BinaryPrimitives.ReadUInt32LittleEndian(Copy.Slice(DescriptorRvaOffset)) & RvaMask);
                StackBytes = Math.Max(MinimumStackBytes, BinaryPrimitives.ReadUInt32LittleEndian(Copy.Slice(StackBytesOffset)));
                SourceRva = Split ? SplitRva : CodeRva;
                SourceBytes = Split ? SplitBytes : CodeBytes;
                Source = ImageBase + SourceRva;
                SecondaryRva = Split ? CodeRva : 0;
                SecondaryBytes = Split ? CodeBytes : 0;
                Secondary = Split ? ImageBase + CodeRva : 0;

                uint First = DescriptorVersion == 1 ? BinaryPrimitives.ReadUInt32LittleEndian(Copy.Slice(FirstDwordOffset)) : 0;
                uint Second = DescriptorVersion == 1 ? BinaryPrimitives.ReadUInt32LittleEndian(Copy.Slice(FirstDwordOffset + 4)) : 0;
                SourceFirstDword = Split ? Second : First;
                SecondaryFirstDword = Split ? First : 0;
            }

            public uint SecondaryOffset => BlockHeaderBytes + SourceBytes;

            public uint TotalBytes => SecondaryBytes + BlockHeaderBytes + SourceBytes;
        }

        private sealed class HeapRegion
        {
            public readonly ulong Base;
            private readonly bool[] Used = new bool[HeapUnits];

            public HeapRegion(ulong RegionBase)
            {
                Base = RegionBase;
            }

            // NT never hands out the last unit of a region.
            public bool TryReserve(int Units, out int FirstUnit)
            {
                for (FirstUnit = 0; FirstUnit + Units < HeapUnits; FirstUnit++)
                {
                    int Run = 0;
                    while (Run < Units && !Used[FirstUnit + Run])
                        Run++;

                    if (Run == Units)
                    {
                        Array.Fill(Used, true, FirstUnit, Units);
                        return true;
                    }

                    FirstUnit += Run;
                }

                return false;
            }

            public void Free(int FirstUnit, int Units) => Array.Fill(Used, false, FirstUnit, Units);
        }

        private sealed class HeapBlock
        {
            public readonly ulong Source;
            public readonly ulong ImageBase;
            public readonly HeapRegion Region;
            public readonly int FirstUnit;
            public readonly int Units;
            public readonly ulong Code;
            public readonly ulong Secondary;
            public readonly LinkedListNode<HeapBlock> Recent;
            public int References = 1;

            public HeapBlock(ulong BlockSource, ulong BlockImageBase, HeapRegion BlockRegion, int BlockFirstUnit, int BlockUnits, ulong BlockCode, ulong BlockSecondary)
            {
                Source = BlockSource;
                ImageBase = BlockImageBase;
                Region = BlockRegion;
                FirstUnit = BlockFirstUnit;
                Units = BlockUnits;
                Code = BlockCode;
                Secondary = BlockSecondary;
                Recent = new LinkedListNode<HeapBlock>(this);
            }
        }

        private readonly record struct CallFrame(HeapBlock Block, ulong SyscallRip, ulong Rsp, ulong EFlags);

        private struct Segment
        {
            public uint Flags;
            public uint Rva;
            public uint Size;
            public uint FirstDword;
        }

        private sealed class SegmentSet
        {
            private readonly uint Version;
            private readonly ulong ImageBase;
            private readonly ulong PreferredBase;
            private readonly Cipher Keys;
            private readonly uint Marker;
            private readonly Segment[] Segments;
            private readonly uint[] Relocations;
            private ulong References;
            private int Decrypted;
            private int EverDecrypted;

            private SegmentSet(ReadOnlySpan<byte> Descriptor, ulong SetImageBase, uint SetVersion, Segment[] SetSegments, uint[] SetRelocations)
            {
                Version = SetVersion;
                ImageBase = SetImageBase;
                PreferredBase = BinaryPrimitives.ReadUInt64LittleEndian(Descriptor.Slice(PreferredBaseOffset));
                Keys = new Cipher(Descriptor);
                Marker = SetVersion == 1 ? BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice(MarkerOffset)) : 0;
                Segments = SetSegments;
                Relocations = SetRelocations;
            }

            public static NTSTATUS Create(BinaryEmulator Instance, ulong Descriptor, ReadOnlySpan<byte> Header, uint DescriptorVersion, out SegmentSet? Set)
            {
                Set = null;
                uint Count = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(SegmentCountOffset));
                int EntryBytes = DescriptorVersion == 0 ? EntryBytesV0 : EntryBytesV1;
                ulong TotalBytes = (ulong)Count * (ulong)EntryBytes + (ulong)Header.Length;
                if (TotalBytes > uint.MaxValue)
                    return NTSTATUS.STATUS_INTEGER_OVERFLOW;

                if (TotalBytes > Settings.MemoryBudget.PooledIoBytes)
                    return NTSTATUS.STATUS_NO_MEMORY;

                ReadOnlySpan<byte> Data = Instance.WinHelper.ReadMemorySpan(Descriptor, (uint)TotalBytes);
                if (Data.IsEmpty)
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                NTSTATUS Status = CheckImageRange(Instance, Descriptor, (uint)TotalBytes, true);
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;

                if (!HashMatches(Data))
                    return NTSTATUS.STATUS_INVALID_IMAGE_HASH;

                if (!Header.SequenceEqual(Data.Slice(0, Header.Length)))
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                ulong Base = Descriptor - (BinaryPrimitives.ReadUInt32LittleEndian(Data.Slice(DescriptorRvaOffset)) & RvaMask);
                uint RelocationCount = BinaryPrimitives.ReadUInt32LittleEndian(Data.Slice(RelocationCountOffset));
                uint[] RelocationTable = Array.Empty<uint>();
                if (RelocationCount != 0)
                {
                    ulong RelocationBytes = (ulong)RelocationCount * sizeof(uint);
                    if (RelocationBytes > uint.MaxValue)
                        return NTSTATUS.STATUS_INTEGER_OVERFLOW;

                    if (RelocationBytes > Settings.MemoryBudget.PooledIoBytes)
                        return NTSTATUS.STATUS_NO_MEMORY;

                    RelocationTable = new uint[RelocationCount];
                    ulong Table = Base + (BinaryPrimitives.ReadUInt32LittleEndian(Data.Slice(RelocationRvaOffset)) & RvaMask);
                    if (!Instance.ReadMemory(Table, MemoryMarshal.AsBytes(RelocationTable.AsSpan())))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                Segment[] Entries = new Segment[Count];
                for (int i = 0; i < Entries.Length; i++)
                {
                    ReadOnlySpan<byte> Entry = Data.Slice(Header.Length + i * EntryBytes, EntryBytes);
                    Entries[i].Flags = BinaryPrimitives.ReadUInt32LittleEndian(Entry);
                    Entries[i].Rva = BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(4)) & RvaMask;
                    Entries[i].Size = BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(8)) & RvaMask;
                    if (DescriptorVersion == 1)
                        Entries[i].FirstDword = BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(12));
                }

                Set = new SegmentSet(Data, Base, DescriptorVersion, Entries, RelocationTable);
                return NTSTATUS.STATUS_SUCCESS;
            }

            public NTSTATUS Decrypt(BinaryEmulator Instance)
            {
                if (References == ulong.MaxValue || ++References != 1)
                    return NTSTATUS.STATUS_SUCCESS;

                WinModule? Image = Instance.WinHelper.FindMappedImageViewByAddress(ImageBase);
                NTSTATUS Status = NTSTATUS.STATUS_SUCCESS;
                while (Decrypted < Segments.Length)
                {
                    bool First = Decrypted >= EverDecrypted;
                    Status = DecryptSegment(Instance, Image, Segments[Decrypted], First);
                    if (Status != NTSTATUS.STATUS_SUCCESS)
                        break;

                    Decrypted++;
                    if (First)
                        EverDecrypted++;
                }

                return Status;
            }

            public NTSTATUS Encrypt(BinaryEmulator Instance)
            {
                if (References == 0 || --References != 0)
                    return NTSTATUS.STATUS_SUCCESS;

                WinModule? Image = Instance.WinHelper.FindMappedImageViewByAddress(ImageBase);
                while (Decrypted > 0)
                {
                    NTSTATUS Status = EncryptSegment(Instance, Image, Segments[Decrypted - 1]);
                    if (Status != NTSTATUS.STATUS_SUCCESS)
                        return Status;

                    Decrypted--;
                }

                return NTSTATUS.STATUS_SUCCESS;
            }

            // The image was relocated over the ciphertext, so the first decryption takes the relocations out first and
            // puts them back into the plaintext.
            private NTSTATUS DecryptSegment(BinaryEmulator Instance, WinModule? Image, in Segment Entry, bool First)
            {
                if (First && (Entry.Flags & SkipFirstDecrypt) != 0)
                    return NTSTATUS.STATUS_SUCCESS;

                ulong Address = ImageBase + Entry.Rva;
                bool Code = (Entry.Flags & DataSegment) == 0;
                NTSTATUS Status = OpenSegment(Instance, Image, Address, Entry.Size, Code);
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;

                if (First && (Status = Relocate(Instance, Entry, unchecked(PreferredBase - ImageBase))) != NTSTATUS.STATUS_SUCCESS)
                    return Status;

                if (Version == 1 && Code)
                {
                    if (Entry.Size < sizeof(uint))
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (!Instance.WinHelper.WriteUInt32(Address, Entry.FirstDword))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                if (!Keys.Transform(Instance, Address, Entry.Size, Entry.Rva, true))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (First && (Status = Relocate(Instance, Entry, unchecked(ImageBase - PreferredBase))) != NTSTATUS.STATUS_SUCCESS)
                    return Status;

                Instance._emulator.InvalidateCodeRange(Address, Entry.Size);
                return NTSTATUS.STATUS_SUCCESS;
            }

            private NTSTATUS EncryptSegment(BinaryEmulator Instance, WinModule? Image, in Segment Entry)
            {
                ulong Address = ImageBase + Entry.Rva;
                bool Code = (Entry.Flags & DataSegment) == 0;
                NTSTATUS Status = OpenSegment(Instance, Image, Address, Entry.Size, Code);
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;

                if (!Keys.Transform(Instance, Address, Entry.Size, Entry.Rva, false))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (Version == 1 && Code)
                {
                    if (Entry.Size < sizeof(uint))
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (!Instance.WinHelper.WriteUInt32(Address, Marker))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                Instance._emulator.InvalidateCodeRange(Address, Entry.Size);
                return NTSTATUS.STATUS_SUCCESS;
            }

            // NT makes data segments PAGE_READWRITE before it writes them, and locks code segments without a change.
            private static NTSTATUS OpenSegment(BinaryEmulator Instance, WinModule? Image, ulong Address, uint Size, bool Code)
            {
                NTSTATUS Status;
                if (Image != null && Address - Image.MappedBase < Image.SizeOfImage)
                    Status = Code ? CheckExecuteRead(Instance, Address, Size) : NTSTATUS.STATUS_SUCCESS;
                else
                    Status = CheckImageRange(Instance, Address, Size, Code);

                if (Status != NTSTATUS.STATUS_SUCCESS || Code)
                    return Status;

                ulong ProtectBase = Address;
                ulong ProtectSize = Size;
                return NtProtectVirtualMemory.Protect(Instance, ref ProtectBase, ref ProtectSize, WinSysHelper.PAGE_READWRITE, out _);
            }

            private NTSTATUS Relocate(BinaryEmulator Instance, in Segment Entry, ulong Delta)
            {
                uint End = unchecked(Entry.Rva + Entry.Size);
                Span<byte> Value = stackalloc byte[sizeof(ulong)];
                for (int Index = FirstRelocation(Entry.Rva); Index < Relocations.Length; Index++)
                {
                    uint Relocation = Relocations[Index];
                    if ((Relocation & RvaMask) >= End)
                        break;

                    int Width = (Relocation >> 28) switch
                    {
                        RelocationHighLow => sizeof(uint),
                        RelocationDir64 => sizeof(ulong),
                        _ => 0,
                    };
                    if (Width == 0)
                        continue;

                    ulong Target = ImageBase + (Relocation & RvaMask);
                    Span<byte> Slot = Value.Slice(0, Width);
                    if (!Instance.ReadMemory(Target, Slot))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (Width == sizeof(uint))
                        BinaryPrimitives.WriteUInt32LittleEndian(Slot, unchecked(BinaryPrimitives.ReadUInt32LittleEndian(Slot) + (uint)Delta));
                    else
                        BinaryPrimitives.WriteUInt64LittleEndian(Slot, unchecked(BinaryPrimitives.ReadUInt64LittleEndian(Slot) + Delta));

                    if (!Instance.WriteMemory(Target, Slot))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                return NTSTATUS.STATUS_SUCCESS;
            }

            private int FirstRelocation(uint Rva)
            {
                int Low = 0;
                int High = Relocations.Length - 1;
                while (Low <= High)
                {
                    int Middle = (Low + High) / 2;
                    uint Value = Relocations[Middle] & RvaMask;
                    if (Rva < Value)
                        High = Middle - 1;
                    else if (Rva > Value)
                        Low = Middle + 1;
                    else
                        return Middle;
                }

                return Low;
            }
        }

        private struct Chain
        {
            public uint PlainLow;
            public uint PlainHigh;
            public uint CipherLow;
            public uint CipherHigh;
        }

        private readonly struct RoundKey
        {
            public readonly uint Type;
            public readonly uint Wa;
            public readonly uint Wb1;
            public readonly uint Wb2;
            public readonly uint Dd;
            public readonly uint DwordThis;
            public readonly uint DwordPrevious;
            public readonly int Shift15;
            public readonly int Shift7;
            public readonly int Shift31;
            public readonly int Last15;
            public readonly int Last31;
            public readonly int First15;

            public RoundKey(ReadOnlySpan<byte> Descriptor, ulong Key, int Round)
            {
                ReadOnlySpan<byte> Parameters = Descriptor.Slice(RoundsOffset + Round * 4 * sizeof(uint));
                uint P1 = BinaryPrimitives.ReadUInt32LittleEndian(Parameters.Slice(4));
                uint P2 = BinaryPrimitives.ReadUInt32LittleEndian(Parameters.Slice(8));
                uint P3 = BinaryPrimitives.ReadUInt32LittleEndian(Parameters.Slice(12));

                Type = BinaryPrimitives.ReadUInt32LittleEndian(Parameters);
                Wa = Word(Key, Round);
                Wb1 = Word(Key, (int)(P1 % 3) + Round + 1);
                Wb2 = Word(Key, (int)(P2 % 3) + Round + 1);
                Dd = Dword(Key, (Round >> 1) - 1);
                DwordThis = Dword(Key, Round);
                DwordPrevious = Dword(Key, Round - 1);
                Shift15 = (int)(P2 % 15 + 1);
                Shift7 = (int)(P2 % 7 + 1);
                Shift31 = (int)(P2 % 31 + 1);
                Last15 = (int)(P3 % 15 + 1);
                Last31 = (int)(P3 % 31 + 1);
                First15 = (int)(P1 % 15 + 1);
            }

            private static uint Word(ulong Key, int Index) => (ushort)(Key >> (16 * (Index & 3)));

            private static uint Dword(ulong Key, int Index) => (uint)(Key >> (32 * (Index & 1)));
        }

        [InlineArray(RoundCount)]
        private struct RoundKeys
        {
            private RoundKey Element;
        }

        // The ntoskrnl cipher is a 10-round Feistel network over 8-byte blocks, chained through the previous plaintext
        // and ciphertext and seeded with the RVA. A head shorter than a block takes a key stream.
        private readonly struct Cipher
        {
            private readonly RoundKeys Rounds;

            public Cipher(ReadOnlySpan<byte> Descriptor)
            {
                ulong Key = BinaryPrimitives.ReadUInt64LittleEndian(Descriptor.Slice(KeyOffset));
                for (int Round = 0; Round < RoundCount; Round++)
                    Rounds[Round] = new RoundKey(Descriptor, Key, Round);
            }

            public void Transform(Span<byte> Data, uint Rva, bool Decrypt)
            {
                int Head = Data.Length & 7;
                Chain State = Begin(Data.Slice(0, Head), Rva, Decrypt);
                Continue(ref State, Data.Slice(Head), Decrypt);
            }

            public bool Transform(BinaryEmulator Instance, ulong Address, uint Size, uint Rva, bool Decrypt)
            {
                Span<byte> Chunk = Instance.WinHelper.Shared.GetSpan(Math.Min(Size, (uint)NtReadFile.IoChunkBytes));
                int Head = (int)(Size & 7);
                Span<byte> HeadBytes = Chunk.Slice(0, Head);
                if (Head != 0 && !Instance.ReadMemory(Address, HeadBytes))
                    return false;

                Chain State = Begin(HeadBytes, Rva, Decrypt);
                if (Head != 0 && !Instance.WriteMemory(Address, HeadBytes))
                    return false;

                ulong Offset = (ulong)Head;
                while (Offset < Size)
                {
                    int Bytes = (int)Math.Min((ulong)Chunk.Length, Size - Offset);
                    Span<byte> Data = Chunk.Slice(0, Bytes);
                    if (!Instance.ReadMemory(Address + Offset, Data))
                        return false;

                    Continue(ref State, Data, Decrypt);
                    if (!Instance.WriteMemory(Address + Offset, Data))
                        return false;

                    Offset += (ulong)Bytes;
                }

                return true;
            }

            private Chain Begin(Span<byte> Head, uint Rva, bool Decrypt)
            {
                if (Head.IsEmpty)
                    return new Chain { CipherLow = ~Rva, CipherHigh = Rva };

                Span<byte> Block = stackalloc byte[sizeof(ulong)];
                Head.CopyTo(Block);

                uint InputLow = BinaryPrimitives.ReadUInt32LittleEndian(Block);
                uint InputHigh = BinaryPrimitives.ReadUInt32LittleEndian(Block.Slice(4));
                KeyStream(Rva, out uint StreamLow, out uint StreamHigh);
                BinaryPrimitives.WriteUInt32LittleEndian(Block, InputLow ^ StreamLow);
                BinaryPrimitives.WriteUInt32LittleEndian(Block.Slice(4), InputHigh ^ StreamHigh);
                Block.Slice(Head.Length).Clear();
                Block.Slice(0, Head.Length).CopyTo(Head);

                uint OutputLow = BinaryPrimitives.ReadUInt32LittleEndian(Block);
                uint OutputHigh = BinaryPrimitives.ReadUInt32LittleEndian(Block.Slice(4));
                return Decrypt
                    ? new Chain { PlainLow = OutputLow, PlainHigh = OutputHigh, CipherLow = InputLow, CipherHigh = InputHigh }
                    : new Chain { PlainLow = InputLow, PlainHigh = InputHigh, CipherLow = OutputLow, CipherHigh = OutputHigh };
            }

            private void Continue(ref Chain State, Span<byte> Data, bool Decrypt)
            {
                for (int Block = 0; Block < Data.Length; Block += sizeof(ulong))
                {
                    Span<byte> Bytes = Data.Slice(Block, sizeof(ulong));
                    ulong Value = BinaryPrimitives.ReadUInt64LittleEndian(Bytes);
                    uint Low = (uint)Value;
                    uint High = (uint)(Value >> 32);
                    if (Decrypt)
                        DecryptBlock(ref State, ref Low, ref High);
                    else
                        EncryptBlock(ref State, ref Low, ref High);

                    BinaryPrimitives.WriteUInt64LittleEndian(Bytes, ((ulong)High << 32) | Low);
                }
            }

            private void KeyStream(uint Rva, out uint Low, out uint High)
            {
                uint A = ~Rva;
                uint B = Rva;
                for (int Round = RoundCount - 1; Round >= 0; Round--)
                {
                    uint Next = A ^ RoundFunction(Round, B);
                    A = B;
                    B = Next;
                }

                Low = A;
                High = B;
            }

            private void DecryptBlock(ref Chain State, ref uint Low, ref uint High)
            {
                uint A = High ^ State.PlainHigh;
                uint B = Low ^ RoundFunction(RoundCount - 1, A) ^ State.PlainLow;
                for (int Round = RoundCount - 2; Round >= 1; Round--)
                {
                    uint Next = A ^ RoundFunction(Round, B);
                    A = B;
                    B = Next;
                }

                uint PlainLow = State.CipherLow ^ B;
                uint PlainHigh = State.CipherHigh ^ A ^ RoundFunction(0, B);
                State = new Chain { PlainLow = PlainLow, PlainHigh = PlainHigh, CipherLow = Low, CipherHigh = High };
                Low = PlainLow;
                High = PlainHigh;
            }

            private void EncryptBlock(ref Chain State, ref uint Low, ref uint High)
            {
                uint A = Low ^ State.CipherLow;
                uint B = High ^ RoundFunction(0, A) ^ State.CipherHigh;
                for (int Round = 1; Round <= RoundCount - 2; Round++)
                {
                    uint Next = A ^ RoundFunction(Round, B);
                    A = B;
                    B = Next;
                }

                uint CipherLow = State.PlainLow ^ A ^ RoundFunction(RoundCount - 1, B);
                uint CipherHigh = State.PlainHigh ^ B;
                State = new Chain { PlainLow = Low, PlainHigh = High, CipherLow = CipherLow, CipherHigh = CipherHigh };
                Low = CipherLow;
                High = CipherHigh;
            }

            private uint RoundFunction(int Round, uint X)
            {
                ref readonly RoundKey Key = ref Rounds[Round];
                uint Wa = Key.Wa;
                uint Wb1 = Key.Wb1;
                uint Wb2 = Key.Wb2;
                uint Dd = Key.Dd;
                int Shift15 = Key.Shift15;
                int Shift7 = Key.Shift7;
                int Shift31 = Key.Shift31;
                int Last15 = Key.Last15;
                int Last31 = Key.Last31;

                unchecked
                {
                    return Key.Type switch
                    {
                        0x00 => (X >> Shift15) + Wa * (X ^ Wb1),
                        0x01 => Wa * (X - Wb1) - (X >> Shift15),
                        0x02 => (X >> Shift15) ^ (Wa * (X ^ Wb1)),
                        0x03 => BitOperations.RotateRight(X, Shift15) + Wa * (X ^ Wb1),
                        0x04 => Wa * (X ^ Wb1) - BitOperations.RotateRight(X, Shift15),
                        0x05 => BitOperations.RotateRight(X, Shift15) ^ (Wa * (X ^ Wb1)),
                        0x06 => (X >> Last15) + Wa * BitOperations.RotateLeft(X ^ Wb1, Shift7),
                        0x07 => Wa * BitOperations.RotateLeft(Dd ^ X, Shift7) - (X >> Last15),
                        0x08 => (X >> Last15) ^ (Wa * BitOperations.RotateLeft(X - Wb1, Shift7)),
                        0x09 => BitOperations.RotateRight(X, Last31) + Wa * BitOperations.RotateLeft(X ^ Wb1, Shift7),
                        0x0A => Wa * BitOperations.RotateLeft(X ^ Wb1, Shift7) - BitOperations.RotateRight(X, Last31),
                        0x0B => BitOperations.RotateRight(X, Last31) ^ (Wa * BitOperations.RotateLeft(X ^ Wb1, Shift7)),
                        0x0C => BitOperations.RotateRight(X, Last31) + Wa * BitOperations.RotateRight(X + Dd, Shift31),
                        0x0D => BitOperations.RotateRight(X, Last31) + Wa * BitOperations.RotateRight(Dd - X, Shift31),
                        0x0E => BitOperations.RotateRight(X, Last31) + Wa * BitOperations.RotateRight(Dd ^ X, Shift31),
                        0x0F => Wa * BitOperations.RotateRight(X + Dd, Shift31) - BitOperations.RotateRight(X, Last31),
                        0x10 => Wa * BitOperations.RotateRight(Dd - X, Shift31) - BitOperations.RotateRight(X, Last31),
                        0x11 => Wa * BitOperations.RotateRight(Dd ^ X, Shift31) - BitOperations.RotateRight(X, Last31),
                        0x12 or 0x17 => BitOperations.RotateRight(X, Last31) ^ (Wa * BitOperations.RotateRight(X - Dd, Shift31)),
                        0x13 => BitOperations.RotateRight(X, Last31) ^ (Wa * BitOperations.RotateRight(Dd - X, Shift31)),
                        0x14 => BitOperations.RotateRight(X, Last31) ^ (Wa * BitOperations.RotateRight(Dd ^ X, Shift31)),
                        0x15 => BitOperations.RotateRight(X, Last31) + Wa * BitOperations.RotateRight(X - Dd, Shift31),
                        0x16 => Wa * BitOperations.RotateRight(X - Dd, Shift31) - BitOperations.RotateRight(X, Last31),
                        0x18 => (Wa + BitOperations.RotateRight(~X, Key.First15)) * Wb2,
                        0x19 => (BitOperations.RotateRight(X, Key.First15) - Wa) * Wb2,
                        0x1A => (Wa ^ BitOperations.RotateRight(X, Key.First15)) * Wb2,
                        0x1B => Key.DwordPrevious - (Key.DwordThis ^ X),
                        0x1C => X ^ Key.DwordThis ^ Key.DwordPrevious,
                        0x1D => Dd ^ (X - Wa),
                        0x1E => X - Dd - Wa,
                        _ => 0,
                    };
                }
            }
        }
    }
}
