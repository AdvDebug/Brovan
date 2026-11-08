using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using Brovan.Core.Emulation.Guests;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal readonly record struct StackFrameRecord(ulong Ip, ulong Sp, bool Unwound);

    internal static class PeStackUnwinder
    {
        private const int MaxFrameCount = 128;

        private const uint ExceptionDataDirectoryIndex = 3;
        private const int RuntimeFunctionSize = 12;
        private const uint RuntimeFunctionIndirect = 1;
        private const int UnwindInfoHeaderSize = 4;
        private const int MaxUnwindCodes = 255;
        private const int UnwindCodeBufferSize = (MaxUnwindCodes + 1) * 2 + RuntimeFunctionSize;
        private const byte UnwindFlagChainInfo = 4;
        private const int MaxChainLinks = 32;
        private const int MaxScanSlots = 1024;
        private const int ScanChunkSlots = 64;
        private const int RegisterCount = 16;
        private const int StackPointerIndex = 4;

        private const int OpPushNonvol = 0;
        private const int OpAllocLarge = 1;
        private const int OpAllocSmall = 2;
        private const int OpSetFpreg = 3;
        private const int OpSaveNonvol = 4;
        private const int OpSaveNonvolFar = 5;
        private const int OpPushMachframe = 10;

        // The slot count of each unwind code matches NT (RtlpUnwindOpSlotTable).
        private static ReadOnlySpan<byte> OpSlots => new byte[] { 1, 2, 1, 1, 2, 3, 2, 3, 2, 3, 1 };

        internal static void Walk(BinaryEmulator Emulator, EmulatedThread Thread, CpuContext Context, int MaxFrames, List<StackFrameRecord> Frames)
        {
            Frames.Clear();
            MaxFrames = Math.Min(MaxFrames, MaxFrameCount);
            WinSysHelper Helper = Emulator.WinHelper;
            if (MaxFrames <= 0 || Helper == null || Context == null || !TryGetStackBounds(Helper, Thread, out ulong Low, out ulong High))
                return;

            Span<ulong> Registers = stackalloc ulong[RegisterCount];
            Span<ulong> Next = stackalloc ulong[RegisterCount];
            Registers[0] = Context.RAX;
            Registers[1] = Context.RCX;
            Registers[2] = Context.RDX;
            Registers[3] = Context.RBX;
            Registers[4] = Context.RSP;
            Registers[5] = Context.RBP;
            Registers[6] = Context.RSI;
            Registers[7] = Context.RDI;
            Registers[8] = Context.R8;
            Registers[9] = Context.R9;
            Registers[10] = Context.R10;
            Registers[11] = Context.R11;
            Registers[12] = Context.R12;
            Registers[13] = Context.R13;
            Registers[14] = Context.R14;
            Registers[15] = Context.R15;

            Span<byte> UnwindCodes = stackalloc byte[UnwindCodeBufferSize];
            StackWalker Stack = new(Emulator, Helper, Low, High, UnwindCodes);

            ulong Ip = Context.RIP;
            Frames.Add(new StackFrameRecord(Ip, Registers[StackPointerIndex], true));

            if (Helper.PointerSize == 8)
            {
                while (Frames.Count < MaxFrames && Stack.TryUnwindFrame(Ip, Registers, Next, Frames.Count == 1, out ulong CallerIp))
                {
                    if (CallerIp == 0)
                        return;

                    Next.CopyTo(Registers);
                    Ip = CallerIp;
                    Frames.Add(new StackFrameRecord(Ip, Registers[StackPointerIndex], true));
                }
            }

            Stack.Scan(Registers[StackPointerIndex], MaxFrames, Frames);
        }

        private static bool TryGetStackBounds(WinSysHelper Helper, EmulatedThread Thread, out ulong Low, out ulong High)
        {
            Low = 0;
            High = 0;
            ulong Teb = WinEmulatedThread.TryGetState(Thread)?.Teb ?? 0;
            bool Wide = Helper.PointerSize == 8;
            return Teb != 0
                && Helper.TryReadPointer(Teb + (Wide ? WindowsGuest.TebStackBaseOffset64 : WindowsGuest.TebStackBaseOffset32), out High)
                && Helper.TryReadPointer(Teb + (Wide ? WindowsGuest.TebDeallocationStackOffset64 : WindowsGuest.TebDeallocationStackOffset32), out Low)
                && Low < High && High - Low >= 8;
        }

        private static int SlotCount(byte OpByte)
        {
            int Op = OpByte & 0xF;
            if (Op >= OpSlots.Length)
                return 0;

            return Op == OpAllocLarge && (OpByte >> 4) != 0 ? 3 : OpSlots[Op];
        }

        // NT uses the frame register once the prolog has run past UWOP_SET_FPREG.
        private static bool UsesFrameRegister(byte PrologSize, ReadOnlySpan<byte> Codes, int Count, uint PrologOffset, bool Chained)
        {
            if (PrologOffset >= PrologSize || Chained)
                return true;

            for (int Index = 0; Index < Count;)
            {
                if ((Codes[Index * 2 + 1] & 0xF) == OpSetFpreg)
                    return PrologOffset >= Codes[Index * 2];

                int Slots = SlotCount(Codes[Index * 2 + 1]);
                if (Slots == 0)
                    return false;

                Index += Slots;
            }

            return false;
        }

        private ref struct StackWalker
        {
            private readonly BinaryEmulator Emulator;
            private readonly WinSysHelper Helper;
            private readonly ulong Low;
            private readonly ulong High;
            private readonly Span<byte> UnwindCodes;

            private WinModule Module;
            private MappedImage Image;
            private bool DirectoryRead;
            private uint Directory;
            private uint DirectorySize;

            internal StackWalker(BinaryEmulator Emulator, WinSysHelper Helper, ulong Low, ulong High, Span<byte> UnwindCodes)
            {
                this.Emulator = Emulator;
                this.Helper = Helper;
                this.Low = Low;
                this.High = High;
                this.UnwindCodes = UnwindCodes;
            }

            internal bool TryUnwindFrame(ulong Ip, ReadOnlySpan<ulong> Registers, Span<ulong> Next, bool First, out ulong CallerIp)
            {
                CallerIp = 0;
                ulong Sp = Registers[StackPointerIndex];
                if (Sp < Low || Sp >= High)
                    return false;

                Registers.CopyTo(Next);
                bool MachineFrame = false;
                bool Leaf = true;
                if (SelectModule(Ip) && TryFindFunction((uint)(Ip - Module.MappedBase), out uint Begin, out uint UnwindData))
                {
                    Leaf = false;
                    if (!TryUnwindFunction((uint)(Ip - Module.MappedBase), Begin, UnwindData, Next, ref CallerIp, ref MachineFrame))
                        return false;
                }
                else if (!First)
                {
                    return false;
                }

                if (!MachineFrame)
                {
                    if (!TryReadStackValue(Next[StackPointerIndex], out CallerIp))
                        return false;
                    Next[StackPointerIndex] += 8;
                }

                if (Next[StackPointerIndex] <= Sp || Next[StackPointerIndex] > High)
                    return false;

                // NT treats a frame with no function entry as a leaf, and rejects a return address equal to the IP.
                return !Leaf || (CallerIp != Ip && IsReturnAddress(CallerIp));
            }

            internal void Scan(ulong From, int MaxFrames, List<StackFrameRecord> Frames)
            {
                ulong Limit = From >= Low && From < High ? High : ulong.MaxValue;
                int PointerSize = Helper.PointerSize;
                Span<byte> Chunk = stackalloc byte[ScanChunkSlots * 8];

                for (int First = 0; First < MaxScanSlots && Frames.Count < MaxFrames; First += ScanChunkSlots)
                {
                    ulong Address = From + (ulong)(First * PointerSize);
                    if (Address < From || Address >= Limit)
                        return;

                    int Slots = (int)Math.Min(ScanChunkSlots, (Limit - Address) / (ulong)PointerSize);
                    Span<byte> Bytes = Chunk.Slice(0, Slots * PointerSize);
                    if (Slots == 0 || !Emulator._emulator.ReadMemory(Address, Bytes))
                        return;

                    for (int Index = 0; Index < Slots && Frames.Count < MaxFrames; Index++)
                    {
                        ulong Value = PointerSize == 8
                            ? BinaryPrimitives.ReadUInt64LittleEndian(Bytes.Slice(Index * 8))
                            : BinaryPrimitives.ReadUInt32LittleEndian(Bytes.Slice(Index * 4));
                        if (IsReturnAddress(Value))
                            Frames.Add(new StackFrameRecord(Value, Address + (ulong)((Index + 1) * PointerSize), false));
                    }
                }
            }

            private bool SelectModule(ulong Address)
            {
                if (Module != null && Address >= Module.MappedBase && Address < Module.MappedBase + Module.SizeOfImage)
                    return true;

                WinModule Found = BinaryEmulator.FindModuleContaining(Helper, Address);
                if (Found == null)
                    return false;

                Module = Found;
                Image = new MappedImage(Emulator, Found.MappedBase);
                DirectoryRead = false;
                return true;
            }

            private bool IsReturnAddress(ulong Address)
            {
                return SelectModule(Address) && BinaryEmulator.TryFindSection(Module, Address, out PortableBinarySection Section) && IsExecutableSection(Section);
            }

            private bool TryFindFunction(uint Rva, out uint Begin, out uint UnwindData)
            {
                Begin = 0;
                UnwindData = 0;
                if (!DirectoryRead)
                {
                    DirectoryRead = true;
                    if (!ImageResources.TryGetDataDirectory(Image, ExceptionDataDirectoryIndex, out Directory, out DirectorySize)
                        || Directory == 0 || Directory >= Module.SizeOfImage || DirectorySize > Module.SizeOfImage - Directory)
                        DirectorySize = 0;
                }

                Span<byte> Entry = stackalloc byte[RuntimeFunctionSize];
                int Lower = 0;
                int Upper = (int)(DirectorySize / RuntimeFunctionSize) - 1;
                while (Lower <= Upper)
                {
                    int Middle = Lower + (Upper - Lower) / 2;
                    if (!Image.TryRead(Directory + (uint)Middle * RuntimeFunctionSize, Entry))
                        return false;

                    if (Rva < BinaryPrimitives.ReadUInt32LittleEndian(Entry))
                    {
                        Upper = Middle - 1;
                        continue;
                    }

                    if (Rva >= BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(4)))
                    {
                        Lower = Middle + 1;
                        continue;
                    }

                    UnwindData = BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(8));
                    if ((UnwindData & RuntimeFunctionIndirect) != 0)
                    {
                        if (UnwindData - 1 > Module.SizeOfImage - RuntimeFunctionSize || !Image.TryRead(UnwindData - 1, Entry))
                            return false;

                        UnwindData = BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(8));
                        if ((UnwindData & RuntimeFunctionIndirect) != 0)
                            return false;
                    }

                    Begin = BinaryPrimitives.ReadUInt32LittleEndian(Entry);
                    return UnwindData < Module.SizeOfImage;
                }

                return false;
            }

            private bool TryUnwindFunction(uint Rva, uint Begin, uint UnwindData, Span<ulong> Next, ref ulong CallerIp, ref bool MachineFrame)
            {
                Span<byte> Header = stackalloc byte[UnwindInfoHeaderSize];
                ulong FrameBase = 0;

                for (int Link = 0; Link <= MaxChainLinks; Link++)
                {
                    if (Link == MaxChainLinks || UnwindData > Module.SizeOfImage - UnwindInfoHeaderSize || !Image.TryRead(UnwindData, Header))
                        return false;

                    int Version = Header[0] & 7;
                    bool Chained = ((Header[0] >> 3) & UnwindFlagChainInfo) != 0;
                    int Count = Header[2];
                    int FrameRegister = Header[3] & 0xF;
                    ulong FrameOffset = (ulong)(Header[3] & 0xF0);
                    if (Version != 1 && Version != 2)
                        return false;

                    int CodeSlots = Chained ? (Count + 1) & ~1 : Count;
                    Span<byte> Codes = UnwindCodes.Slice(0, CodeSlots * 2 + (Chained ? RuntimeFunctionSize : 0));
                    if ((ulong)UnwindData + UnwindInfoHeaderSize + (ulong)Codes.Length > Module.SizeOfImage
                        || (Codes.Length != 0 && !Image.TryRead(UnwindData + UnwindInfoHeaderSize, Codes)))
                        return false;

                    uint PrologOffset = Rva - Begin;
                    if (Link == 0)
                    {
                        FrameBase = FrameRegister != 0 && UsesFrameRegister(Header[1], Codes, Count, PrologOffset, Chained)
                            ? Next[FrameRegister] - FrameOffset
                            : Next[StackPointerIndex];
                    }

                    for (int Index = 0; Index < Count;)
                    {
                        int CodeOffset = Codes[Index * 2];
                        int Op = Codes[Index * 2 + 1] & 0xF;
                        int Info = Codes[Index * 2 + 1] >> 4;
                        int Slots = SlotCount(Codes[Index * 2 + 1]);
                        if (Slots == 0 || Index + Slots > Count)
                            return false;

                        if (PrologOffset >= CodeOffset)
                        {
                            ushort Slot1 = Slots > 1 ? BinaryPrimitives.ReadUInt16LittleEndian(Codes.Slice(Index * 2 + 2)) : (ushort)0;
                            ushort Slot2 = Slots > 2 ? BinaryPrimitives.ReadUInt16LittleEndian(Codes.Slice(Index * 2 + 4)) : (ushort)0;
                            ulong Value;
                            switch (Op)
                            {
                                case OpPushNonvol:
                                    if (!TryReadStackValue(Next[StackPointerIndex], out Value))
                                        return false;
                                    Next[Info] = Value;
                                    Next[StackPointerIndex] += 8;
                                    break;
                                case OpAllocLarge:
                                    Next[StackPointerIndex] += Info == 0 ? Slot1 * 8UL : Slot1 | ((ulong)Slot2 << 16);
                                    break;
                                case OpAllocSmall:
                                    Next[StackPointerIndex] += (ulong)Info * 8 + 8;
                                    break;
                                case OpSetFpreg:
                                    Next[StackPointerIndex] = Next[FrameRegister] - FrameOffset;
                                    break;
                                case OpSaveNonvol:
                                case OpSaveNonvolFar:
                                    ulong Offset = Op == OpSaveNonvol ? Slot1 * 8UL : Slot1 | ((ulong)Slot2 << 16);
                                    if (!TryReadStackValue(FrameBase + Offset, out Value))
                                        return false;
                                    Next[Info] = Value;
                                    break;
                                case OpPushMachframe:
                                    ulong Frame = Next[StackPointerIndex] + (Info != 0 ? 8UL : 0);
                                    if (!TryReadStackValue(Frame, out CallerIp) || !TryReadStackValue(Frame + 24, out Value))
                                        return false;
                                    Next[StackPointerIndex] = Value;
                                    MachineFrame = true;
                                    break;
                            }
                        }

                        Index += Slots;
                    }

                    if (!Chained)
                        return true;

                    ReadOnlySpan<byte> Parent = Codes.Slice(CodeSlots * 2);
                    Begin = BinaryPrimitives.ReadUInt32LittleEndian(Parent);
                    UnwindData = BinaryPrimitives.ReadUInt32LittleEndian(Parent.Slice(8));
                }

                return false;
            }

            private readonly bool TryReadStackValue(ulong Address, out ulong Value)
            {
                Value = 0;
                return Address >= Low && Address <= High - 8 && Helper.TryReadUInt64(Address, out Value);
            }
        }
    }
}
