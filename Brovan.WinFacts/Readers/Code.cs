using Iced.Intel;

namespace Brovan.WinFacts.Readers
{
    // The instructions of one function, found by following its branches from the entry. Calls are not followed, a jump
    // to the start of another public symbol is a tail call, and a jump table is followed through each of its entries.
    internal sealed class Function
    {
        private const int MaxInstructions = 50000;
        private const int MaxTableEntries = 1024;

        private readonly SortedList<ulong, Instruction> ByAddress = new();

        internal ulong Address { get; }
        internal string Name { get; }
        internal IList<Instruction> Instructions => ByAddress.Values;
        internal List<JumpTable> Tables { get; } = new();

        private Function(ulong Address, string Name)
        {
            this.Address = Address;
            this.Name = Name;
        }

        internal static Function Decode(PeImage Image, PdbPublics Publics, uint Rva)
        {
            Function Function = new(Image.ImageBase + Rva, Publics.NameAt(Rva));
            ImageCodeReader Reader = new(Image);
            Decoder Decoder = Decoder.Create(Image.Is64 ? 64 : 32, Reader);
            Stack<ulong> Pending = new();
            Pending.Push(Function.Address);
            while (Pending.Count > 0)
            {
                ulong Ip = Pending.Pop();
                while (!Function.ByAddress.ContainsKey(Ip))
                {
                    if (Function.ByAddress.Count >= MaxInstructions)
                        throw new FactException($"{Function.Name}: more than {MaxInstructions} instructions");

                    Reader.Position = Ip - Image.ImageBase;
                    Decoder.IP = Ip;
                    Instruction Instruction = Decoder.Decode();
                    if (Instruction.IsInvalid)
                        throw new FactException($"{Function.Name}: invalid instruction at 0x{Ip - Image.ImageBase:X}");

                    Function.ByAddress.Add(Ip, Instruction);
                    Ip = Instruction.NextIP;
                    FlowControl Flow = Instruction.FlowControl;
                    if (Flow is FlowControl.Return or FlowControl.Interrupt or FlowControl.Exception)
                        break;

                    if (Flow == FlowControl.ConditionalBranch)
                    {
                        Pending.Push(Instruction.NearBranchTarget);
                        continue;
                    }

                    if (Flow == FlowControl.UnconditionalBranch)
                    {
                        ulong Target = Instruction.NearBranchTarget;
                        if (Target != Function.Address && Publics.NameAt((uint)(Target - Image.ImageBase)) != null)
                            break;

                        Ip = Target;
                        continue;
                    }

                    if (Flow == FlowControl.IndirectBranch)
                    {
                        if (Instruction.Op0Kind == OpKind.Register && Function.TryReadTable(Image, Instruction, out JumpTable Table))
                        {
                            Function.Tables.Add(Table);
                            foreach (ulong Target in Table.Targets)
                                Pending.Push(Target);
                        }

                        break;
                    }

                    if (Instruction.Mnemonic == Mnemonic.Int3)
                        break;
                }
            }

            return Function;
        }

        internal bool TryGet(ulong Address, out Instruction Instruction) => ByAddress.TryGetValue(Address, out Instruction);

        internal int IndexOf(ulong Address) => ByAddress.IndexOfKey(Address);

        // MSVC x64: cmp idx, n / ja default / lea base, [__ImageBase] / mov r32, [base + idx*4 + table] / add r, base / jmp r.
        private bool TryReadTable(PeImage Image, in Instruction Jump, out JumpTable Table)
        {
            Table = null;
            int Index = ByAddress.IndexOfKey(Jump.IP);
            Register Target = Jump.Op0Register;
            Register Base = Register.None;
            Register Case = Register.None;
            uint TableRva = 0;
            for (int i = Index - 1; i >= Math.Max(0, Index - 8); i--)
            {
                Instruction Previous = ByAddress.Values[i];
                if (Previous.Mnemonic == Mnemonic.Add && Previous.Op0Kind == OpKind.Register && Previous.Op0Register == Target &&
                    Previous.Op1Kind == OpKind.Register)
                {
                    Base = Previous.Op1Register;
                    continue;
                }

                if (Base != Register.None && Previous.Op0Kind == OpKind.Register &&
                    Previous.Op0Register.GetFullRegister() == Target.GetFullRegister() && Previous.Op1Kind == OpKind.Memory &&
                    Previous.MemoryBase == Base && Previous.MemoryIndexScale == 4)
                {
                    Case = Previous.MemoryIndex;
                    TableRva = (uint)Previous.MemoryDisplacement64;
                    break;
                }
            }

            if (Case == Register.None)
                return false;

            uint? Count = null;
            for (int i = Index - 1; i >= Math.Max(0, Index - 12); i--)
            {
                Instruction Previous = ByAddress.Values[i];
                if (Previous.Mnemonic == Mnemonic.Cmp && Previous.Op0Kind == OpKind.Register &&
                    Previous.Op0Register.GetFullRegister() == Case.GetFullRegister() && Previous.Op1Kind.IsImmediate())
                {
                    Count = (uint)Previous.GetImmediate(1) + 1;
                    break;
                }
            }

            if (Count is not uint Entries || Entries > MaxTableEntries)
                return false;

            List<ulong> Targets = new((int)Entries);
            for (uint i = 0; i < Entries; i++)
                Targets.Add(Image.ImageBase + Image.ReadUInt32(TableRva + i * 4));

            Table = new JumpTable(Jump.IP, Case, Targets);
            return true;
        }
    }

    internal sealed record JumpTable(ulong Jump, Register Case, List<ulong> Targets);

    internal static class InstructionExtensions
    {
        internal static bool IsImmediate(this OpKind Kind)
            => Kind is OpKind.Immediate8 or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate64 or OpKind.Immediate8to16 or
                OpKind.Immediate8to32 or OpKind.Immediate8to64 or OpKind.Immediate32to64;
    }

    internal sealed class ImageCodeReader : CodeReader
    {
        private const int PageSize = 0x1000;

        private readonly PeImage Image;
        private readonly Dictionary<ulong, byte[]> Pages = new();

        internal ulong Position;

        internal ImageCodeReader(PeImage Image)
        {
            this.Image = Image;
        }

        public override int ReadByte()
        {
            ulong Page = Position & ~(ulong)(PageSize - 1);
            if (!Pages.TryGetValue(Page, out byte[] Bytes))
            {
                Bytes = new byte[PageSize];
                if (Page > uint.MaxValue || !Image.TryReadRva((uint)Page, Bytes))
                    Bytes = null;

                Pages[Page] = Bytes;
            }

            if (Bytes == null)
                return -1;

            return Bytes[(int)(Position++ - Page)];
        }
    }
}
