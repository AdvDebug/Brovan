using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using Brovan.Core.Emulation;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace Brovan.WinFacts.Readers
{
    // Runs small functions of an x64 image in Unicorn. Imports return 0, and a named callee can be replaced by a stub
    // written into the loaded copy.
    internal sealed unsafe class Machine : IDisposable
    {
        private const ulong PageSize = 0x1000;
        private const ulong HeapBase = 0x7FF000000000;
        private const ulong HeapSize = 0x1000000;
        private const ulong PoolBase = HeapBase + HeapSize / 2;
        private const ulong StackBase = 0x7FFE00000000;
        private const ulong StackSize = 0x100000;
        private const ulong StubSize = 0x40000;
        private const ulong StubAlignment = 0x10000;
        private const int JumpSize = 5;
        private const ulong InstructionBudget = 2_000_000;
        private const int ImportDirectoryIndex = 1;
        private const int DelayImportDirectoryIndex = 13;
        private const int MaxNameBytes = 128;
        // Unicorn's UC_CTL_WRITE(UC_CTL_TB_REMOVE_CACHE, 2), a write control with two arguments.
        private const int ControlRemoveCache = 9;
        private const int ControlWrite = 1;
        private const int TbRemoveCache = ControlRemoveCache | (2 << 26) | (ControlWrite << 30);
        private static readonly byte[] Halt = { 0xF4 };
        private static readonly Registers[] ArgumentRegisters = { Registers.UC_X86_REG_RCX, Registers.UC_X86_REG_RDX, Registers.UC_X86_REG_R8, Registers.UC_X86_REG_R9 };

        private readonly IntPtr Uc;
        private readonly PeImage Image;
        private readonly ulong StubBase;
        private readonly ulong Sentinel;
        private readonly ulong CursorSlot;
        private readonly ulong ZeroStub;
        private readonly Dictionary<string, List<ulong>> ImportSlots = new(StringComparer.Ordinal);
        private ulong HeapCursor = HeapBase;
        private ulong StubCursor;

        internal PdbPublics Publics { get; }

        private Machine(IntPtr Uc, PeImage Image, PdbPublics Publics, ulong StubBase)
        {
            this.Uc = Uc;
            this.Image = Image;
            this.Publics = Publics;
            this.StubBase = StubBase;
            Sentinel = StubBase;
            StubCursor = StubBase + 0x10;
            CursorSlot = Alloc(8);
            ZeroStub = Emit(Asm => { Asm.xor(eax, eax); Asm.ret(); });
            Write(Sentinel, Halt);
        }

        internal static void UseLibrary(string Path)
        {
            NativeLibrary.SetDllImportResolver(typeof(Machine).Assembly, (Name, Assembly, Search)
                => Name == "unicorn" ? NativeLibrary.Load(Path) : IntPtr.Zero);
        }

        internal static Machine Load(PeImage Image, PdbPublics Publics)
        {
            if (!Image.Is64)
                throw new FactException("the machine runs x64 images only");

            Check(uc_open(Arch.X86, Mode.MODE_64, out IntPtr Uc), "uc_open");
            Machine Machine = null;
            try
            {
                ulong ImageSize = (Image.SizeOfImage + PageSize - 1) & ~(PageSize - 1);
                // Stubs sit right after the image so that a five-byte jump reaches them from any patched function.
                ulong StubBase = (Image.ImageBase + ImageSize + 2 * StubAlignment - 1) & ~(StubAlignment - 1);
                Check(uc_mem_map(Uc, Image.ImageBase, (UIntPtr)ImageSize, MemoryProtection.All), "map image");
                Check(uc_mem_map(Uc, HeapBase, (UIntPtr)HeapSize, MemoryProtection.ReadWrite), "map heap");
                Check(uc_mem_map(Uc, StackBase, (UIntPtr)StackSize, MemoryProtection.ReadWrite), "map stack");
                Check(uc_mem_map(Uc, StubBase, (UIntPtr)StubSize, MemoryProtection.All), "map stubs");

                Machine = new Machine(Uc, Image, Publics, StubBase);
                foreach (PeSection Section in Image.Sections)
                    Machine.Write(Image.ImageBase + Section.VirtualAddress, Image.ReadSection(Section));

                Machine.StubImports();
                Machine.StubPoolAllocations();
                Machine.PatchByPrefix("_guard_dispatch_icall", Asm => Asm.jmp(rax));
                Machine.PatchByPrefix("_guard_check_icall", Asm => Asm.ret());
                Machine.PatchByPrefix("__security_check_cookie", Asm => Asm.ret());
                return Machine;
            }
            catch
            {
                uc_close(Uc);
                throw;
            }
        }

        internal ulong Va(uint Rva) => Image.ImageBase + Rva;

        internal ulong Alloc(int Size)
        {
            ulong Address = HeapCursor;
            HeapCursor += ((ulong)Size + 15) & ~15UL;
            if (HeapCursor > PoolBase)
                throw new FactException("machine heap exhausted");

            return Address;
        }

        internal void Write(ulong Address, ReadOnlySpan<byte> Bytes)
        {
            fixed (byte* Pointer = Bytes)
                Check(uc_mem_write(Uc, Address, Pointer, (UIntPtr)Bytes.Length), "write");
        }

        internal void WriteUInt64(ulong Address, ulong Value)
        {
            Span<byte> Bytes = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64LittleEndian(Bytes, Value);
            Write(Address, Bytes);
        }

        internal byte[] Read(ulong Address, int Count)
        {
            byte[] Bytes = new byte[Count];
            Read(Address, Bytes);
            return Bytes;
        }

        private void Read(ulong Address, Span<byte> Destination)
        {
            fixed (byte* Pointer = Destination)
                Check(uc_mem_read(Uc, Address, Pointer, (UIntPtr)Destination.Length), "read");
        }

        internal uint ReadUInt32(ulong Address)
        {
            Span<byte> Bytes = stackalloc byte[sizeof(uint)];
            Read(Address, Bytes);
            return BinaryPrimitives.ReadUInt32LittleEndian(Bytes);
        }

        internal ulong ReadUInt64(ulong Address)
        {
            Span<byte> Bytes = stackalloc byte[sizeof(ulong)];
            Read(Address, Bytes);
            return BinaryPrimitives.ReadUInt64LittleEndian(Bytes);
        }

        internal void Patch(uint Rva, Action<Assembler> Body)
        {
            if (Publics.NextAfter(Rva) - Rva < JumpSize)
                throw new FactException($"0x{Rva:X} is too short to patch");

            ulong Stub = Emit(Body);
            Assembler Jump = new(64);
            Jump.jmp(Stub);
            Write(Va(Rva), Assemble(Jump, Va(Rva)));
        }

        internal void PatchReturn(uint Rva, ulong Value) => Patch(Rva, Returning(Value));

        internal void PatchByPrefix(string Prefix, Action<Assembler> Body)
        {
            foreach (uint Rva in Publics.NamesStartingWith(Prefix).Select(Symbol => Symbol.Rva).Distinct())
                Patch(Rva, Body);
        }

        internal void PatchImport(string Name, Action<Assembler> Body)
        {
            if (!ImportSlots.TryGetValue(Name, out List<ulong> Slots))
                return;

            ulong Stub = Emit(Body);
            foreach (ulong Slot in Slots)
                WriteUInt64(Slot, Stub);
        }

        internal void PatchImportReturn(string Name, ulong Value) => PatchImport(Name, Returning(Value));

        private static Action<Assembler> Returning(ulong Value) => Asm => { Asm.mov(rax, Value); Asm.ret(); };

        internal ulong Call(uint Rva, params ulong[] Args)
        {
            UCErrors Error = Run(Rva, Sentinel, Args);
            ulong Pc = ReadRegister(Registers.UC_X86_REG_RIP);
            if (Error != UCErrors.UC_ERR_OK || Pc != Sentinel)
                throw Stopped(Rva, Error, Pc);

            return ReadRegister(Registers.UC_X86_REG_RAX);
        }

        // Unicorn checks the stop address only in code translated while it was the stop, so the run drops the cached code
        // at Address and at the return address. The hlt at the return address ends a run that returns first.
        internal bool Reaches(uint Rva, ulong Address, params ulong[] Args)
        {
            DropTranslations(Address);
            UCErrors Error = Run(Rva, Address, Args);
            ulong Pc = ReadRegister(Registers.UC_X86_REG_RIP);
            DropTranslations(Address);
            DropTranslations(Sentinel);
            if (Error == UCErrors.UC_ERR_OK && Pc == Address)
                return true;

            if (Error == UCErrors.UC_ERR_OK && (Pc == Sentinel || Pc == Sentinel + (ulong)Halt.Length))
                return false;

            throw Stopped(Rva, Error, Pc);
        }

        private static FactException Stopped(uint Rva, UCErrors Error, ulong Pc)
            => new(Error != UCErrors.UC_ERR_OK ? $"run of 0x{Rva:X} stopped at 0x{Pc:X}: {Error}" : $"run of 0x{Rva:X} did not return within the budget (at 0x{Pc:X})");

        private void DropTranslations(ulong Address) => Check(uc_ctl(Uc, TbRemoveCache, Address, Address + 1), "drop translations");

        private UCErrors Run(uint Rva, ulong Until, ulong[] Args)
        {
            ulong Stack = StackBase + StackSize - 0x1000;
            ulong StackArgs = (ulong)Math.Max(0, Args.Length - 4) * 8;
            Stack -= StackArgs + 0x20 + 8;
            Stack &= ~0xFUL;
            Stack -= 8;
            WriteUInt64(Stack, Sentinel);
            for (int i = 4; i < Args.Length; i++)
                WriteUInt64(Stack + 8 + 0x20 + (ulong)(i - 4) * 8, Args[i]);

            for (int i = 0; i < Math.Min(ArgumentRegisters.Length, Args.Length); i++)
                WriteRegister(ArgumentRegisters[i], Args[i]);

            WriteRegister(Registers.UC_X86_REG_RSP, Stack);
            WriteRegister(Registers.UC_X86_REG_RAX, 0);
            return uc_emu_start(Uc, Va(Rva), Until, UIntPtr.Zero, (UIntPtr)InstructionBudget);
        }

        // The memory a run can change: the writable sections of the image and the used part of the heap.
        internal sealed record Snapshot(List<(ulong Address, byte[] Bytes)> Regions, ulong PoolCursor);

        internal Snapshot Save()
        {
            List<(ulong, byte[])> Regions = new();
            foreach (PeSection Section in Image.Sections)
            {
                if (Section.IsWritable)
                    Regions.Add((Va(Section.VirtualAddress), Read(Va(Section.VirtualAddress), (int)Math.Max(Section.VirtualSize, Section.RawSize))));
            }

            Regions.Add((HeapBase, Read(HeapBase, (int)(HeapCursor - HeapBase))));
            ulong PoolCursor = ReadUInt64(CursorSlot);
            Regions.Add((PoolBase, Read(PoolBase, (int)(PoolCursor - PoolBase))));
            return new Snapshot(Regions, PoolCursor);
        }

        internal void Restore(Snapshot State)
        {
            ulong PoolCursor = ReadUInt64(CursorSlot);
            if (PoolCursor > State.PoolCursor)
                Write(State.PoolCursor, new byte[PoolCursor - State.PoolCursor]);

            foreach ((ulong Address, byte[] Bytes) in State.Regions)
                Write(Address, Bytes);
        }

        internal ulong? TryCall(uint Rva, params ulong[] Args)
        {
            try
            {
                return Call(Rva, Args);
            }
            catch (FactException)
            {
                return null;
            }
        }

        public void Dispose() => uc_close(Uc);

        // Pool allocations come from a bump allocator over the machine heap: zeroed memory of the size in rdx.
        private void StubPoolAllocations()
        {
            WriteUInt64(CursorSlot, PoolBase);
            void Allocator(Assembler Asm)
            {
                Asm.mov(rax, CursorSlot);
                Asm.mov(rcx, __qword_ptr[rax]);
                Asm.lea(r8, __qword_ptr[rcx + rdx + 0x40F]);
                Asm.and(r8, -0x400);
                Asm.mov(__qword_ptr[rax], r8);
                Asm.mov(rax, rcx);
                Asm.ret();
            }

            foreach (string Name in new[] { "ExAllocatePool2", "ExAllocatePoolWithTag", "ExAllocatePoolZero", "ExAllocatePoolWithQuotaTag", "ExAllocatePool3" })
                PatchImport(Name, Allocator);
        }

        private void StubImports()
        {
            foreach ((int Directory, int DescriptorSize, int IatOffset, int IntOffset) in new[] { (ImportDirectoryIndex, 20, 16, 0), (DelayImportDirectoryIndex, 32, 12, 16) })
            {
                (uint Rva, uint Size) = Image.Directory(Directory);
                for (uint Descriptor = Rva; Size != 0 && Descriptor + DescriptorSize <= Rva + Size; Descriptor += (uint)DescriptorSize)
                {
                    uint Iat = Image.ReadUInt32(Descriptor + (uint)IatOffset);
                    uint Names = Image.ReadUInt32(Descriptor + (uint)IntOffset);
                    if (Iat == 0)
                        break;

                    uint Thunks = Names != 0 ? Names : Iat;
                    for (uint Slot = 0; ; Slot += 8)
                    {
                        ulong Thunk = Image.ReadUInt64(Thunks + Slot);
                        if (Thunk == 0)
                            break;

                        WriteUInt64(Va(Iat + Slot), ZeroStub);
                        if ((Thunk & (1UL << 63)) != 0)
                            continue;

                        string Name = ReadAscii((uint)Thunk + 2);
                        if (!ImportSlots.TryGetValue(Name, out List<ulong> List))
                            ImportSlots[Name] = List = new List<ulong>();

                        List.Add(Va(Iat + Slot));
                    }
                }
            }
        }

        private string ReadAscii(uint Rva)
        {
            byte[] Bytes = Image.ReadRva(Rva, MaxNameBytes);
            int End = Array.IndexOf(Bytes, (byte)0);
            return Encoding.ASCII.GetString(Bytes, 0, End < 0 ? Bytes.Length : End);
        }

        private ulong Emit(Action<Assembler> Body)
        {
            Assembler Asm = new(64);
            Body(Asm);
            byte[] Code = Assemble(Asm, StubCursor);
            ulong Address = StubCursor;
            if (Address + (ulong)Code.Length > StubBase + StubSize)
                throw new FactException("machine stub area exhausted");

            Write(Address, Code);
            StubCursor += ((ulong)Code.Length + 15) & ~15UL;
            return Address;
        }

        private static byte[] Assemble(Assembler Asm, ulong Address)
        {
            using MemoryStream Stream = new();
            Asm.Assemble(new StreamCodeWriter(Stream), Address);
            return Stream.ToArray();
        }

        private void WriteRegister(Registers Register, ulong Value) => Check(uc_reg_write(Uc, (int)Register, &Value), "reg write");

        private ulong ReadRegister(Registers Register)
        {
            ulong Value = 0;
            Check(uc_reg_read(Uc, (int)Register, &Value), "reg read");
            return Value;
        }

        private static void Check(UCErrors Error, string What)
        {
            if (Error != UCErrors.UC_ERR_OK)
                throw new FactException($"unicorn {What}: {Error}");
        }

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        private static extern UCErrors uc_open(Arch Arch, Mode Mode, out IntPtr Uc);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        private static extern UCErrors uc_close(IntPtr Uc);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        private static extern UCErrors uc_mem_map(IntPtr Uc, ulong Address, UIntPtr Size, MemoryProtection Protection);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        private static extern UCErrors uc_mem_write(IntPtr Uc, ulong Address, byte* Bytes, UIntPtr Size);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        private static extern UCErrors uc_mem_read(IntPtr Uc, ulong Address, byte* Bytes, UIntPtr Size);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        private static extern UCErrors uc_reg_write(IntPtr Uc, int Register, ulong* Value);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        private static extern UCErrors uc_reg_read(IntPtr Uc, int Register, ulong* Value);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        private static extern UCErrors uc_ctl(IntPtr Uc, int Control, ulong Begin, ulong End);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        private static extern UCErrors uc_emu_start(IntPtr Uc, ulong Begin, ulong Until, UIntPtr Timeout, UIntPtr Count);
    }
}
