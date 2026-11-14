using System.Text;
using System.Text.Json;
using Brovan.WinFacts.Readers;
using Iced.Intel;

namespace Brovan.WinFacts.Rules
{
    internal sealed record CompositionNameFact(string Name, string Class, string Setter, uint Id, int Bytes, string Compare = null);

    // The names come from dcomp's property descriptors, because win32kbase cannot tell properties of one size apart.
    internal sealed class CompositionNamesGroup : FactGroup
    {
        // A descriptor holds the name, the property ID, -1, the value type, the setter kind and the value size.
        // Build 28000 drops the -1, which moves the type and the kind up four bytes.
        private const uint OffsetName = 0;
        private const uint OffsetId = 8;
        private const uint OffsetMarker = 12;
        private const uint OffsetKind = 20;
        private const uint OffsetKindWithoutMarker = 16;
        private const uint OffsetBytes = 32;
        private const uint Marker = 0xFFFFFFFF;
        private const int MaxNameChars = 64;
        private const string DcompNamespace = "@Composition@UI@Windows@@";
        private const ulong MaxCallId = 0x10000;
        private const uint AbsentId = 0xFFFFFFFF;

        // A name with no descriptor takes its ID from the first call to Callee in Caller that passes a buffer of Bytes.
        private sealed record NameRule(string Name, string[] DcompClasses, string Property, string KernelClass, CallSource Call = null, string Compare = null);

        private sealed record CallSource(string Caller, string Callee, int Bytes);

        private static readonly string[] VisualClasses = { "VisualCommon", "Visual" };
        private static readonly string[] ColorBrushClasses = { "CompositionColorBrush" };

        // These stay in the order of the generated CompositionName enum.
        private static readonly NameRule[] Names =
        {
            new("VisualOffset", VisualClasses, "Offset", "Visual"),
            new("VisualSize", VisualClasses, "Size", "Visual"),
            new("VisualOpacity", VisualClasses, "Opacity", "Visual"),
            new("VisualIsVisible", VisualClasses, "IsVisible", "Visual"),
            new("ColorBrushColor", ColorBrushClasses, "Color", "ColorBrush"),
            new("SurfaceBrushSourceRect", null, null, "SurfaceBrush",
                new CallSource("?BindToSurfaceBrush@CCompositionSurface@DirectComposition@@", "?SetBufferProperty@CResourceProxy@DirectComposition@@", 16), "None"),
        };

        private static readonly (uint Kind, string Setter, int[] Bytes)[] Kinds =
        {
            (0, "Float", new[] { 4 }),
            (1, "Buffer", null),
            (4, "Integer", new[] { 1, 4 }),
        };

        internal override string Name => "composition-names";

        internal override string KeyFile => "dcomp.dll";

        internal override string OutputPath => "Brovan/Core/Emulation/OS/Windows/Win32k/CompositionNames.Generated.cs";

        protected override string Namespace => "Brovan.Core.Emulation.OS.Windows.Win32k";

        protected override string SetClass => "CompositionNameSet";

        protected override string UnknownVersion => "null";

        protected override (ushort Build, ushort Revision)[] RunVersions { get; } = { };

        internal override string Extract(VersionInputs Inputs)
        {
            List<CompositionNameFact> Facts = new();
            foreach (NameRule Rule in Names)
            {
                if (Rule.Call != null)
                {
                    Facts.Add(ReadCallName(Inputs, Rule));
                    continue;
                }

                List<uint> Found = new();
                foreach (string Class in Rule.DcompClasses)
                {
                    if (Inputs.Publics.TryFind($"?sc_{Rule.Property}@{Class}{DcompNamespace}", "", out uint Rva))
                        Found.Add(Rva);
                }

                string Described = $"sc_{Rule.Property} of {string.Join(" or ", Rule.DcompClasses)}";
                if (Found.Count != 1)
                    throw new FactException($"{Described}: {Found.Count} descriptors");

                uint Descriptor = Found[0];
                ulong NameVa = Inputs.Image.ReadUInt64(Descriptor + OffsetName);
                string Text = NameVa >= Inputs.Image.ImageBase ? ReadName(Inputs.Image, (uint)(NameVa - Inputs.Image.ImageBase)) : null;
                bool Marked = Inputs.Image.ReadUInt32(Descriptor + OffsetMarker) == Marker;
                if (Text != Rule.Property || !Marked && Inputs.Image.ReadUInt32(Descriptor + OffsetKind) != 0)
                    throw new FactException($"{Described} is not a descriptor of that name");

                uint Kind = Inputs.Image.ReadUInt32(Descriptor + (Marked ? OffsetKind : OffsetKindWithoutMarker));
                int Bytes = (int)Inputs.Image.ReadUInt32(Descriptor + OffsetBytes);
                (uint Kind, string Setter, int[] Bytes) Setter = Kinds.FirstOrDefault(Entry => Entry.Kind == Kind);
                if (Setter.Setter == null || Bytes <= 0 || Setter.Bytes != null && !Setter.Bytes.Contains(Bytes))
                    throw new FactException($"{Described}: kind {Kind}, {Bytes} bytes");

                Facts.Add(new CompositionNameFact(Rule.Name, Rule.KernelClass, Setter.Setter, Inputs.Image.ReadUInt32(Descriptor + OffsetId),
                    Setter.Setter == "Buffer" ? Bytes : 0));
            }

            return JsonSerializer.Serialize(Facts);
        }

        // CCompositionSurface::BindToSurfaceBrush sets the surface, its atlas flag, its RECT in the atlas and then a RECT of
        // its own size, so the source is the first 16-byte buffer.
        private static CompositionNameFact ReadCallName(VersionInputs Inputs, NameRule Rule)
        {
            if (!Inputs.Publics.NamesStartingWith(Rule.Call.Caller).Any())
                return new CompositionNameFact(Rule.Name, Rule.KernelClass, "Buffer", AbsentId, Rule.Call.Bytes, Rule.Compare);

            uint Caller = FindPrefix(Inputs, Rule.Call.Caller);
            uint Callee = FindPrefix(Inputs, Rule.Call.Callee);
            List<(ulong? Id, ulong? Bytes)> Calls = ReadCallArguments(Inputs, Caller, Callee);
            int Index = Calls.FindIndex(Call => Call.Bytes == (ulong)Rule.Call.Bytes);
            if (Index < 0 || Calls[Index].Id is not ulong Id || Id >= MaxCallId)
                throw new FactException($"{Rule.Name}: no call of {Rule.Call.Callee} with {Rule.Call.Bytes} bytes and a constant ID in {Rule.Call.Caller}");

            return new CompositionNameFact(Rule.Name, Rule.KernelClass, "Buffer", (uint)Id, Rule.Call.Bytes, Rule.Compare);
        }

        private static uint FindPrefix(VersionInputs Inputs, string Prefix)
        {
            uint[] Found = Inputs.Publics.NamesStartingWith(Prefix).Select(Symbol => Symbol.Rva).Distinct().ToArray();
            return Found.Length == 1 ? Found[0] : throw new FactException($"{Prefix}: {Found.Length} functions");
        }

        // rdx and r9 follow moves, register copies and register-plus-offset loads, and any other write makes them unknown.
        private static List<(ulong? Id, ulong? Bytes)> ReadCallArguments(VersionInputs Inputs, uint Caller, uint Callee)
        {
            Function Function = Readers.Function.Decode(Inputs.Image, Inputs.Publics, Caller);
            Dictionary<Register, ulong> Known = new();
            List<(ulong? Id, ulong? Bytes)> Calls = new();
            ulong? Get(Register Register) => Known.TryGetValue(Register.GetFullRegister(), out ulong Value) ? Value : null;
            foreach (Instruction Instruction in Function.Instructions.OrderBy(Instruction => Instruction.IP))
            {
                if (Instruction.FlowControl is FlowControl.Call or FlowControl.IndirectCall)
                {
                    if (Instruction.Op0Kind == OpKind.NearBranch64 && Instruction.NearBranchTarget == Inputs.Image.ImageBase + Callee)
                        Calls.Add((Get(Register.RDX), Get(Register.R9)));

                    foreach (Register Clobbered in CompositionGroup.VolatileRegisters)
                        Known.Remove(Clobbered);

                    continue;
                }

                if (Instruction.Op0Kind != OpKind.Register || !Instruction.Op0Register.IsGPR())
                    continue;

                Register Target = Instruction.Op0Register;
                ulong? Value = Instruction.Mnemonic switch
                {
                    Mnemonic.Mov when Instruction.Op1Kind.IsImmediate() => Instruction.GetImmediate(1),
                    Mnemonic.Mov when Instruction.Op1Kind == OpKind.Register => Get(Instruction.Op1Register),
                    Mnemonic.Lea when Instruction.MemoryIndex == Register.None && Instruction.MemoryBase != Register.RIP && Instruction.MemoryBase != Register.None
                        => Get(Instruction.MemoryBase) is ulong Base ? Base + Instruction.MemoryDisplacement64 : null,
                    Mnemonic.Xor when Instruction.Op1Kind == OpKind.Register && Instruction.Op1Register == Target => 0,
                    _ => null,
                };

                if (Value is ulong Known32 && Target.GetSize() == 4)
                    Value = Known32 & 0xFFFFFFFF;

                if (Value is ulong Set && Target.GetSize() >= 4)
                    Known[Target.GetFullRegister()] = Set;
                else
                    Known.Remove(Target.GetFullRegister());
            }

            return Calls;
        }

        private static string ReadName(PeImage Image, uint Rva)
        {
            byte[] Bytes = new byte[MaxNameChars * 2];
            if (!Image.TryReadRva(Rva, Bytes))
                return null;

            string Text = Encoding.Unicode.GetString(Bytes);
            int End = Text.IndexOf('\0');
            return End < 0 ? null : Text.Substring(0, End);
        }

        protected override void WriteTypes(SourceWriter Code)
        {
            Code.Line("    internal enum CompositionName : byte");
            Code.Line("    {");
            foreach (NameRule Rule in Names)
                Code.Line($"        {Rule.Name},");

            Code.Line("    }");
            Code.Line();
        }

        protected override void WriteMembers(SourceWriter Code)
        {
            Code.Line("        // Bytes is the size of a buffer value, 0 for the other setters. Compare is the kind the kernel rule must have, null for any.");
            Code.Line("        internal readonly (CompositionName Name, CompositionClass Class, CompositionSlots Setter, uint Id, int Bytes, CompositionCompare? Compare)[] Names;");
            Code.Line();
            Code.Line("        private CompositionNameSet((CompositionName Name, CompositionClass Class, CompositionSlots Setter, uint Id, int Bytes, CompositionCompare? Compare)[] Names)");
            Code.Line("        {");
            Code.Line("            this.Names = Names;");
            Code.Line("        }");
        }

        protected override void WriteSet(SourceWriter Code, string Json)
        {
            CompositionNameFact[] Facts = JsonSerializer.Deserialize<CompositionNameFact[]>(Json);
            if (!Facts.Select(Fact => Fact.Name).SequenceEqual(Names.Select(Rule => Rule.Name)))
                throw new InvalidDataException("the facts do not list the names in the order of CompositionName");

            Code.Line("            new (CompositionName, CompositionClass, CompositionSlots, uint, int, CompositionCompare?)[]");
            Code.Line("            {");
            foreach (CompositionNameFact Fact in Facts)
                Code.Line($"                (CompositionName.{Fact.Name}, CompositionClass.{Fact.Class}, CompositionSlots.{Fact.Setter}, 0x{Fact.Id:X}u, {Fact.Bytes}, " +
                          $"{(Fact.Compare == null ? "null" : "CompositionCompare." + Fact.Compare)}),");

            Code.Line("            });");
        }
    }
}
