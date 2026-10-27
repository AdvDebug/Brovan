using Iced.Intel;

namespace Brovan.WinFacts.Readers
{
    // A value's case is the first block that does work besides the dispatch. Only unsigned conditions are read, so past
    // the sum of the dispatch's constants every value takes the default's path, and only values up to that sum are tried.
    internal sealed class Switch
    {
        private const int MaxSteps = 4096;
        private const uint MaxValue = 4096;
        private static readonly uint[] FarValues = { 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF };

        internal List<ulong> Cases { get; }
        internal ulong Default { get; }

        internal HashSet<Register> Written { get; }

        private Switch(List<ulong> Cases, ulong Default, HashSet<Register> Written)
        {
            this.Cases = Cases;
            this.Default = Default;
            this.Written = Written;
        }

        internal static Switch Read(Function Function, ulong Start, Register Selector)
        {
            Evaluation Evaluation = new(Function, Selector);
            List<ulong> Cases = new();
            for (uint Value = 0; Value <= Evaluation.ConstantSum + 1; Value++)
            {
                if (Value > MaxValue)
                    throw new FactException($"{Function.Name}: the switch at 0x{Start:X} tests values past {MaxValue}");

                Cases.Add(Evaluation.Case(Start, Value));
            }

            ulong Default = Cases[^1];
            foreach (uint Value in FarValues)
            {
                if (Evaluation.Case(Start, Value) != Default)
                    throw new FactException($"{Function.Name}: the switch at 0x{Start:X} sends 0x{Value:X} past its default");
            }

            int Count = Cases.FindLastIndex(Case => Case != Default) + 1;
            Cases.RemoveRange(Count, Cases.Count - Count);
            return new Switch(Cases, Default, Evaluation.Written);
        }

        // Known values derive from the selector. Tainted registers derive from it through instructions not evaluated here.
        private sealed class Evaluation
        {
            private readonly Function Function;
            private readonly Register Selector;
            private readonly InstructionInfoFactory Info = new();
            private readonly Dictionary<ulong, ulong> Constants = new();
            private readonly Dictionary<Register, ulong> Known = new();
            private readonly HashSet<Register> Tainted = new();
            private bool? Carry;
            private bool? Zero;
            private bool FlagsTainted;

            internal ulong ConstantSum { get; private set; }
            internal HashSet<Register> Written { get; } = new();

            internal Evaluation(Function Function, Register Selector)
            {
                this.Function = Function;
                this.Selector = Selector.GetFullRegister();
            }

            internal ulong Case(ulong Start, uint Value)
            {
                Known.Clear();
                Tainted.Clear();
                Known[Selector] = Value;
                Carry = Zero = null;
                FlagsTainted = false;
                ulong Block = Start;
                int Steps = 0;
                while (true)
                {
                    bool Other = false;
                    ulong Ip = Block;
                    Instruction End;
                    while (true)
                    {
                        if (++Steps > MaxSteps)
                            throw Fail(Block, $"the switch runs more than {MaxSteps} instructions");

                        if (!Function.TryGet(Ip, out End))
                            throw Fail(Ip, "no decoded instruction");

                        if (End.FlowControl != FlowControl.Next)
                            break;

                        Other |= !Evaluate(End);
                        Ip = End.NextIP;
                    }

                    switch (End.FlowControl)
                    {
                        case FlowControl.ConditionalBranch:
                            if (FlagsTainted)
                                throw Fail(End.IP, "a branch on flags the switch does not evaluate");

                            if (Taken(End) is bool Jump)
                                Block = Jump ? End.NearBranchTarget : End.NextIP;
                            else if (Other)
                                return Block;
                            else
                                throw Fail(End.IP, "a branch on flags the switch does not set");

                            break;
                        case FlowControl.UnconditionalBranch when !Other && Function.Successors(End.IP).Count == 1:
                            Block = End.NearBranchTarget;
                            break;
                        case FlowControl.IndirectBranch when Function.Tables.Find(Table => Table.Jump == End.IP) is JumpTable Table:
                            if (!Known.TryGetValue(Table.Case.GetFullRegister(), out ulong Index))
                                throw Fail(End.IP, $"a jump table on {Table.Case}, which the switch does not evaluate");

                            if (Index >= (ulong)Table.Targets.Count)
                                throw Fail(End.IP, $"index {Index} past the {Table.Targets.Count} entries of the jump table");

                            Block = Table.Targets[(int)Index];
                            break;
                        case FlowControl.IndirectBranch when !Other:
                            throw Fail(End.IP, "an indirect jump the switch cannot follow");
                        default:
                            return Block;
                    }
                }
            }

            // False when the instruction does work outside the dispatch.
            private bool Evaluate(in Instruction Instruction)
            {
                InstructionInfo Used = Info.GetInfo(Instruction);
                bool ReadsFlags = Instruction.RflagsRead != RflagsBits.None;
                bool ReadsKnown = ReadsFlags && (Carry != null || Zero != null);
                bool ReadsTainted = ReadsFlags && FlagsTainted;
                foreach (UsedRegister Register in Used.GetUsedRegisters())
                {
                    if (Register.Access is OpAccess.Read or OpAccess.ReadWrite or OpAccess.CondRead or OpAccess.ReadCondWrite)
                    {
                        ReadsKnown |= Known.ContainsKey(Register.Register.GetFullRegister());
                        ReadsTainted |= Tainted.Contains(Register.Register.GetFullRegister());
                    }
                }

                bool Zeroing = Instruction.Mnemonic == Mnemonic.Xor && Instruction.Op0Kind == OpKind.Register && Instruction.Op1Kind == OpKind.Register &&
                               Instruction.Op0Register == Instruction.Op1Register;
                if (ReadsKnown && !ReadsTainted && !Zeroing && TryStep(Instruction))
                    return true;

                bool Taint = (ReadsKnown || ReadsTainted) && !Zeroing;
                foreach (UsedRegister Register in Used.GetUsedRegisters())
                {
                    if (Register.Access is not (OpAccess.Write or OpAccess.ReadWrite or OpAccess.CondWrite or OpAccess.ReadCondWrite))
                        continue;

                    Register Full = Register.Register.GetFullRegister();
                    Known.Remove(Full);
                    if (Taint)
                        Tainted.Add(Full);
                    else
                        Tainted.Remove(Full);
                }

                if (Instruction.RflagsModified != RflagsBits.None)
                {
                    Carry = Zero = null;
                    FlagsTainted = Taint;
                }

                return false;
            }

            private bool TryStep(in Instruction Instruction)
            {
                switch (Instruction.Mnemonic)
                {
                    case Mnemonic.Mov when Instruction.Op0Kind == OpKind.Memory && Instruction.Op1Kind == OpKind.Register &&
                                           !Involves(Instruction.MemoryBase) && !Involves(Instruction.MemoryIndex):
                        return true;
                    case Mnemonic.Mov when Instruction.Op0Kind == OpKind.Register && Instruction.Op1Kind == OpKind.Register &&
                                           TryRead(Instruction.Op1Register, out ulong Source):
                        Write(Instruction.Op0Register, Source);
                        return true;
                    case Mnemonic.Cmp when TryOperands(Instruction, out ulong Left, out ulong Right, out ulong Mask):
                        SetFlags(Left < Right, ((Left - Right) & Mask) == 0);
                        return true;
                    case Mnemonic.Sub when TryOperands(Instruction, out ulong Left, out ulong Right, out ulong Mask):
                        SetFlags(Left < Right, ((Left - Right) & Mask) == 0);
                        Write(Instruction.Op0Register, Left - Right);
                        return true;
                    case Mnemonic.Add when TryOperands(Instruction, out ulong Left, out ulong Right, out ulong Mask):
                        SetFlags(((Left + Right) & Mask) < Left, ((Left + Right) & Mask) == 0);
                        Write(Instruction.Op0Register, Left + Right);
                        return true;
                    case Mnemonic.Dec or Mnemonic.Inc when Instruction.Op0Kind == OpKind.Register && TryRead(Instruction.Op0Register, out ulong Value):
                        AddConstant(Instruction.IP, 1);
                        ulong Result = (Instruction.Mnemonic == Mnemonic.Dec ? Value - 1 : Value + 1) & Mask(Instruction.Op0Register);
                        SetFlags(Carry, Result == 0);
                        Write(Instruction.Op0Register, Result);
                        return true;
                    case Mnemonic.Test when Instruction.Op0Kind == OpKind.Register && Instruction.Op1Kind == OpKind.Register &&
                                            Instruction.Op0Register == Instruction.Op1Register && TryRead(Instruction.Op0Register, out ulong Tested):
                        SetFlags(false, Tested == 0);
                        return true;
                    default:
                        return false;
                }
            }

            private bool TryOperands(in Instruction Instruction, out ulong Left, out ulong Right, out ulong Mask)
            {
                Left = Right = Mask = 0;
                if (Instruction.Op0Kind != OpKind.Register || !TryRead(Instruction.Op0Register, out Left))
                    return false;

                Mask = Evaluation.Mask(Instruction.Op0Register);
                if (Instruction.Op1Kind.IsImmediate())
                {
                    Right = Instruction.GetImmediate(1) & Mask;
                    AddConstant(Instruction.IP, Math.Min(Right, Mask - Right + 1));
                    return true;
                }

                return Instruction.Op1Kind == OpKind.Register && TryRead(Instruction.Op1Register, out Right);
            }

            private void AddConstant(ulong Ip, ulong Constant)
            {
                if (Constants.TryAdd(Ip, Constant))
                    ConstantSum += Constant;
            }

            private bool Involves(Register Register)
                => Register != Register.None && (Known.ContainsKey(Register.GetFullRegister()) || Tainted.Contains(Register.GetFullRegister()));

            private bool TryRead(Register Register, out ulong Value)
            {
                Value = 0;
                if (Register.GetSize() is not (4 or 8) || !Known.TryGetValue(Register.GetFullRegister(), out ulong Full))
                    return false;

                Value = Full & Mask(Register);
                return true;
            }

            private void Write(Register Register, ulong Value)
            {
                Register Full = Register.GetFullRegister();
                Known[Full] = Value & Mask(Register);
                Tainted.Remove(Full);
                Written.Add(Full);
            }

            private void SetFlags(bool? Carry, bool Zero)
            {
                this.Carry = Carry;
                this.Zero = Zero;
                FlagsTainted = false;
            }

            private bool? Taken(in Instruction Branch) => Branch.ConditionCode switch
            {
                ConditionCode.e => Zero,
                ConditionCode.ne => !Zero,
                ConditionCode.b => Carry,
                ConditionCode.ae => !Carry,
                ConditionCode.be => Carry == true || Zero == true ? true : Carry == false && Zero == false ? false : null,
                ConditionCode.a => Carry == true || Zero == true ? false : Carry == false && Zero == false ? true : null,
                _ => Carry != null || Zero != null ? throw Fail(Branch.IP, $"a {Branch.ConditionCode} branch, which tests a sign or parity") : null,
            };

            private static ulong Mask(Register Register) => Register.GetSize() == 4 ? uint.MaxValue : ulong.MaxValue;

            private FactException Fail(ulong Ip, string What) => new($"{Function.Name}: {What} at 0x{Ip:X}");
        }
    }
}
