using System.Buffers.Binary;
using System.Text.Json;
using Brovan.WinFacts.Readers;
using Iced.Intel;

namespace Brovan.WinFacts.Rules
{
    internal sealed record CompositionFacts(
        string[] Commands,
        int[] RecordSizes,
        uint MaxType,
        int[] Parents,
        string[] TypeClasses,
        CompositionPropertyFact[] Properties,
        CompositionOwnPropertiesFact[] OwnProperties);

    // Base is the type a reference property requires of its target, 0 for other properties.
    internal sealed record CompositionPropertyFact(string Name, uint Id, uint Base);

    internal sealed record CompositionOwnPropertiesFact(string Class, string Setter, uint[] Properties);

    internal sealed class CompositionGroup : FactGroup
    {
        private const string NtNamespace = "DirectComposition";
        private const string Iterator = "?ProcessCommandBufferIterator@CApplicationChannel@DirectComposition@@";
        private const string Factory = "?CreatePrivateMarshaler@CApplicationChannel@DirectComposition@@";
        private const string ChannelConstructor = "??0CApplicationChannel@DirectComposition@@";
        private const string IsDerived = "?IsDerivedResourceType@CResourceMarshaler@DirectComposition@@";
        private const string SessionState = "W32GetUserSessionState";
        private const string ChannelWrapper = "?SetResource";
        private const string InlinedInputSink = "?EnsureWriteableInteraction@CVisualMarshaler@DirectComposition@@";
        private const string LeakTrackingAllocator = "?gpLeakTrackingAllocator@@";
        private const string BaseClass = "CResourceMarshaler";
        private const string PropertyChangeClass = "CPropertyChangeResourceMarshaler";
        private const string VisualClass = "CVisualMarshaler";

        private const uint StatusSuccess = 0;
        private const uint StatusInvalidParameter = 0xC000000D;
        private const uint StatusNotSupported = 0xC00000BB;
        private const uint BaseMarker = 0x7EADBEEF;
        private const ulong UnmappedTarget = 0x500000000000;
        private const int SessionStateBytes = 0x20000;
        private const int ObjectBytes = 0x4000;
        private const int MaxLoadDistance = 16;
        private const int MaxSizeCheckDistance = 16;
        private const int OpcodeBytes = 4;
        private const int CreateHandle = 1;
        private const int MaxWrapperDepth = 2;
        private const int MaxVtableBytes = 0x800;
        private const uint MaxScanProperty = 0x10000;
        private const uint WideMaskProperty = 0xFFFF;
        private const int ColorBytes = 16;

        private const string SetInteger = "SetIntegerProperty";
        private const string SetBuffer = "SetBufferProperty";
        private const string SetReference = "SetReferenceProperty";
        private const string SetCallbackId = "SetCallbackId";
        private static readonly string[] SlotMethods = { SetInteger, SetBuffer, SetReference, SetCallbackId };
        private static readonly Register[] VolatileRegisters = { Register.RAX, Register.RCX, Register.RDX, Register.R8, Register.R9, Register.R10, Register.R11 };

        // The record fields (offset, bytes) must match what Brovan.Core's CompositionBatchParser reads.
        private static readonly CommandRule[] Commands =
        {
            new("CreateResource", new[] { Factory }, 16, new[] { (4, 4), (8, 4), (12, 4) }, null),
            new("ReleaseResource", new[] { "?ReleaseResource@CApplicationChannel@DirectComposition@@" }, 8, new[] { (4, 4) }, null),
            new("SetCallbackId", new[] { "?" + SetCallbackId + "@" }, 12, new[] { (4, 4), (8, 4) }, SetCallbackId),
            new("SetInteger", new[] { "?" + SetInteger + "@" }, 24, new[] { (4, 4), (8, 4), (16, 8) }, SetInteger),
            new("SetBuffer", new[] { "?" + SetBuffer + "@" }, 16, new[] { (4, 4), (8, 4), (12, 4) }, SetBuffer),
            new("SetReference", new[] { "?" + SetReference + "@" }, 16, new[] { (4, 4), (8, 4), (12, 4) }, SetReference),
            new("SetVisualInputSink", new[] { "?SetVisualInputSink@CApplicationChannel@DirectComposition@@", InlinedInputSink }, 16, new[] { (4, 4), (8, 8) }, null),
        };

        private static readonly CommandRule CreateRule = Commands[0];

        // Each setter slot holds CResourceMarshaler's stub (Base), any other function (Own), or the named function.
        private static readonly ClassRule[] Classes =
        {
            new("BlurredWallpaperBackdropBrush", "CBlurredWallpaperBackdropBrushMarshaler", Base, Base, Base, Base),
            new("ColorBrush", "CColorBrushMarshaler", Base, "CColorBrushMarshaler", Base, Base),
            new("ComponentTransform3D", "CComponentTransform3DMarshaler", "CPropertyChangeResourceMarshaler", Own, Base, "CNotificationResourceMarshaler"),
            new("Visual", "CVisualMarshaler", "CVisualMarshaler", Own, "CVisualMarshaler", "CNotificationResourceMarshaler"),
        };

        private const string Base = "<base>";
        private const string Own = "<own>";

        // These stay in the order of the generated CompositionProperty enum.
        private const string PropertyChangeMask = "PropertyChangeMask";
        private const string VisualTransform = "VisualTransform";
        private static readonly string[] Properties = { PropertyChangeMask, VisualTransform };

        private sealed record CommandRule(string Name, string[] Markers, int Size, (int Offset, int Bytes)[] Fields, string Method);

        private sealed record CreateCase(uint Opcode, ulong Call, uint MaxType);

        private sealed record ClassRule(string Name, string NtClass, string Integer, string Buffer, string Reference, string CallbackId);

        internal override string Name => "composition";

        internal override string KeyFile => "win32kbase.sys";

        internal override string OutputPath => "Brovan/Core/Emulation/OS/Windows/Win32k/CompositionTables.Generated.cs";

        protected override string Namespace => "Brovan.Core.Emulation.OS.Windows.Win32k";

        protected override string SetClass => "CompositionTableSet";

        protected override string UnknownVersion => "null";

        protected override (ushort Build, ushort Revision)[] RunVersions { get; } = { (26100, 1), (26100, 9711) };

        internal override string Extract(VersionInputs Inputs)
        {
            if (!Inputs.Publics.TryFind(Factory, "", out _))
                throw new FactException("no CApplicationChannel::CreatePrivateMarshaler to run");

            Dictionary<string, uint> Slots = ReadSlots(Inputs);
            (string[] CommandMap, int[] Sizes, CreateCase Create) = ReadCommands(Inputs, Slots);
            uint MaxType = Create.MaxType;
            int[] Parents = ReadParents(Inputs);
            if (MaxType + 1 != Parents.Length)
                throw new FactException($"create accepts types up to 0x{MaxType:X} but the parent table ends at 0x{Parents.Length:X}");

            string[] TypeClasses = ReadTypeClasses(Inputs, MaxType);
            CheckClassSlots(Inputs, Slots);
            CheckBaseAnswers(Inputs, TypeClasses);
            uint Mask = ReadPropertyChangeMask(Inputs, TypeClasses);
            uint[] OwnIntegers = ReadVisualOwnIntegers(Inputs, TypeClasses, Mask);
            (uint Transform, uint TransformBase, uint[] OwnReferences) = ReadVisualReferences(Inputs, TypeClasses, Parents);

            CompositionPropertyFact[] PropertyFacts = { new(PropertyChangeMask, Mask, 0), new(VisualTransform, Transform, TransformBase) };
            CompositionOwnPropertiesFact[] OwnFacts =
            {
                new("Visual", "Integer", OwnIntegers),
                new("Visual", "Reference", OwnReferences),
            };
            CompositionFacts Facts = new(CommandMap, Sizes, MaxType, Parents, TypeClasses, PropertyFacts, OwnFacts);
            return JsonSerializer.Serialize(Facts);
        }

        // The vtable offset of each setter, from the vtables whose entry at that offset is a function of only that name.
        private static Dictionary<string, uint> ReadSlots(VersionInputs Inputs)
        {
            Dictionary<string, SortedSet<uint>> Found = SlotMethods.ToDictionary(Method => Method, _ => new SortedSet<uint>());
            HashSet<string> Methods = new(StringComparer.Ordinal);
            foreach ((string Name, uint Rva) in Inputs.Publics.NamesStartingWith("??_7C"))
            {
                if (!Name.Contains("Marshaler@" + NtNamespace + "@@6B", StringComparison.Ordinal))
                    continue;

                uint End = Math.Min(Inputs.Publics.NextAfter(Rva), Rva + MaxVtableBytes);
                for (uint Offset = 0; Rva + Offset + 8 <= End; Offset += 8)
                {
                    ulong Entry = Inputs.Image.ReadUInt64(Rva + Offset);
                    if (Entry < Inputs.Image.ImageBase || Entry - Inputs.Image.ImageBase >= Inputs.Image.SizeOfImage)
                        break;

                    Methods.Clear();
                    foreach (string Function in Inputs.Publics.NamesAt((uint)(Entry - Inputs.Image.ImageBase)))
                    {
                        if (Function.StartsWith('?') && Function.Contains("@" + NtNamespace + "@@", StringComparison.Ordinal))
                            Methods.Add(Function.Substring(1, Function.IndexOf('@') - 1));
                    }

                    if (Methods.Count == 1 && Found.TryGetValue(Methods.First(), out SortedSet<uint> Offsets))
                        Offsets.Add(Offset);
                }
            }

            Dictionary<string, uint> Slots = new(StringComparer.Ordinal);
            foreach ((string Method, SortedSet<uint> Offsets) in Found)
            {
                if (Offsets.Count != 1)
                    throw new FactException($"{Method} slot: offsets {string.Join(", ", Offsets.Select(Offset => $"0x{Offset:X}"))}");

                Slots[Method] = Offsets.Min;
            }

            return Slots;
        }

        private static (string[] Commands, int[] Sizes, CreateCase Create) ReadCommands(VersionInputs Inputs, Dictionary<string, uint> Slots)
        {
            uint IteratorRva = Inputs.Publics.Find(CompositionGroup.Iterator);
            Function Iterator = Function.Decode(Inputs.Image, Inputs.Publics, IteratorRva);
            (Instruction Load, Register Remaining, HashSet<Register> Aliases) = ReadOpcodeLoad(Iterator);
            Switch Dispatch = Switch.Read(Iterator, Load.NextIP, Load.Op0Register);
            Aliases.ExceptWith(Dispatch.Written);

            string[] Names = new string[Dispatch.Cases.Count];
            int[] Sizes = new int[Dispatch.Cases.Count];
            CreateCase Create = null;
            for (int Wire = 0; Wire < Dispatch.Cases.Count; Wire++)
            {
                Names[Wire] = "";
                ulong Target = Dispatch.Cases[Wire];
                if (Target == Dispatch.Default)
                    continue;

                // The tail that every case shares says nothing about this case.
                HashSet<ulong> Own = Iterator.Dominated(Target);
                Sizes[Wire] = ReadSizeCheck(Iterator, Own, Target, Remaining, Wire);
                (List<Instruction> Path, CommandRule Rule, bool Wrapped) = FindCommand(Inputs, Iterator, Own, Target, Slots);
                if (Rule == null)
                    continue;

                if (Names.Contains(Rule.Name))
                    throw new FactException($"{Rule.Name}: more than one opcode");

                Names[Wire] = Rule.Name;
                if (Sizes[Wire] != Rule.Size)
                    throw new FactException($"{Rule.Name} (opcode {Wire}): record size {Sizes[Wire]}, Brovan reads {Rule.Size}");

                if (!PassesSizeCheck(Path, Remaining, Sizes[Wire]))
                    throw new FactException($"{Rule.Name} (opcode {Wire}): the path to its function does not pass the size check");

                string Fields = FormatFields(ReadRecordFields(Path, Aliases));
                string Expected = FormatFields(Rule.Fields);
                if (Fields != Expected)
                    throw new FactException($"{Rule.Name} (opcode {Wire}): reads fields {Fields}, Brovan reads {Expected}");

                if (Rule.Method != null && !Wrapped && !VirtualSlots(Path).Contains(Slots[Rule.Method]))
                    throw new FactException($"{Rule.Name} (opcode {Wire}): no call through vtable slot 0x{Slots[Rule.Method]:X}");

                if (Rule == CreateRule)
                    Create = new CreateCase((uint)Wire, Path[^1].IP, ReadTypeRangeCheck(Path, Wire));
            }

            foreach (CommandRule Rule in Commands)
            {
                if (!Names.Contains(Rule.Name))
                    throw new FactException($"{Rule.Name}: no opcode");
            }

            CheckRuns(Inputs, IteratorRva, Dispatch, Create);
            return (Names, Sizes, Create);
        }

        private static (Instruction Load, Register Remaining, HashSet<Register> Aliases) ReadOpcodeLoad(Function Iterator)
        {
            List<(Instruction, Register, HashSet<Register>)> Found = new();
            InstructionInfoFactory Info = new();
            foreach (Instruction Check in Iterator.Instructions)
            {
                if (!IsCompare(Check, 4) || !Iterator.TryGet(Check.NextIP, out Instruction Branch) || Branch.Mnemonic != Mnemonic.Jb)
                    continue;

                List<Instruction> Line = new();
                ulong Ip = Branch.NextIP;
                while (Line.Count < MaxLoadDistance && Iterator.TryGet(Ip, out Instruction Next) && Next.FlowControl == FlowControl.Next)
                {
                    Line.Add(Next);
                    Ip = Next.NextIP;
                }

                int Load = Line.FindIndex(Instruction => Instruction.Mnemonic == Mnemonic.Mov && Instruction.Op0Kind == OpKind.Register &&
                                                         Instruction.Op0Register.IsGPR32() && Instruction.Op1Kind == OpKind.Memory &&
                                                         Instruction.MemoryBase.IsGPR64() && Instruction.MemoryBase is not (Register.RSP or Register.RBP) &&
                                                         Instruction.MemoryIndex == Register.None && Instruction.MemoryDisplacement64 == 0);
                if (Load < 0)
                    continue;

                HashSet<Register> Aliases = new() { Line[Load].MemoryBase };
                foreach (Instruction Instruction in Line.Take(Load + 1))
                    TrackCopies(Aliases, Info, Instruction);

                Found.Add((Line[Load], Check.Op0Register.GetFullRegister(), Aliases));
            }

            return Found.Count == 1 ? Found[0] : throw new FactException($"command switch: {Found.Count} opcode loads");
        }

        private static void CheckRuns(VersionInputs Inputs, uint Iterator, Switch Dispatch, CreateCase Create)
        {
            uint[] Opcodes = Enumerable.Range(0, Dispatch.Cases.Count + 1).Select(Opcode => (uint)Opcode).Append(uint.MaxValue).ToArray();
            ulong CaseOf(uint Opcode) => Opcode < Dispatch.Cases.Count ? Dispatch.Cases[(int)Opcode] : Dispatch.Default;
            for (int Feature = 0; Feature < 2; Feature++)
            {
                using Session Session = new(Inputs, Feature);
                Machine Machine = Session.Machine;
                ulong FactoryEntry = Machine.Va(Inputs.Publics.Find(Factory));
                ulong Record = Machine.Alloc(CreateRule.Size);
                ulong Processed = Machine.Alloc(8);
                Machine.Snapshot Start = Machine.Save();
                ulong[] Arguments(uint Opcode, int Length, uint Type = 0, uint Sharing = 0)
                {
                    Machine.Restore(Start);
                    byte[] Bytes = new byte[CreateRule.Size];
                    BinaryPrimitives.WriteUInt32LittleEndian(Bytes, Opcode);
                    BinaryPrimitives.WriteUInt32LittleEndian(Bytes.AsSpan(4), CreateHandle);
                    BinaryPrimitives.WriteUInt32LittleEndian(Bytes.AsSpan(8), Type);
                    BinaryPrimitives.WriteUInt32LittleEndian(Bytes.AsSpan(12), Sharing);
                    Machine.Write(Record, Bytes);
                    return new[] { Session.Channel, Record, (ulong)Length, 0UL, Processed };
                }

                // A case whose size check fails also ends at the default, so the default is not checked.
                foreach (ulong Target in Dispatch.Cases.Distinct().Where(Target => Target != Dispatch.Default))
                {
                    foreach (uint Opcode in Opcodes)
                    {
                        if (Machine.Reaches(Iterator, Target, Arguments(Opcode, OpcodeBytes)) != (CaseOf(Opcode) == Target))
                            throw new FactException($"command switch: a run of opcode 0x{Opcode:X} disagrees about the case at 0x{Target - Inputs.Image.ImageBase:X}");
                    }
                }

                foreach (uint Opcode in Opcodes)
                {
                    if (Machine.Reaches(Iterator, FactoryEntry, Arguments(Opcode, CreateRule.Size, 1)) != (Opcode == Create.Opcode))
                        throw new FactException($"a create record with opcode 0x{Opcode:X} {(Opcode == Create.Opcode ? "does not reach" : "reaches")} the factory");
                }

                foreach (uint Type in new[] { 1u, Create.MaxType })
                {
                    if (!Machine.Reaches(Iterator, Create.Call, Arguments(Create.Opcode, CreateRule.Size, Type)))
                        throw new FactException($"a create record of type 0x{Type:X} does not reach the factory call the case was read from");
                }

                foreach (uint Type in new[] { 0u, Create.MaxType + 1, uint.MaxValue })
                {
                    foreach (uint Sharing in new uint[] { 0, 1 })
                    {
                        if (Machine.TryCall(Iterator, Arguments(Create.Opcode, CreateRule.Size, Type, Sharing)) is not ulong Status || (uint)Status != StatusInvalidParameter)
                            throw new FactException($"a create record of type 0x{Type:X}, sharing {Sharing}, does not get STATUS_INVALID_PARAMETER");
                    }
                }
            }
        }

        private static (List<Instruction> Path, CommandRule Rule, bool Wrapped) FindCommand(VersionInputs Inputs, Function Iterator, HashSet<ulong> Own,
            ulong Target, Dictionary<string, uint> Slots)
        {
            CommandRule Rule = null;
            bool Wrapped = false;
            List<Instruction> Path = Iterator.FindPath(Target, Own, int.MaxValue, Candidate =>
            {
                (Rule, Wrapped) = CommandAt(Inputs, Candidate, Slots);
                return Rule != null;
            });

            return (Path, Rule, Wrapped);
        }

        private static int ReadSizeCheck(Function Iterator, HashSet<ulong> Own, ulong Target, Register Remaining, int Wire)
        {
            List<Instruction> Path = Iterator.FindPath(Target, Own, MaxSizeCheckDistance, Candidate => IsSizeCheck(Iterator, Candidate[^1], Remaining));
            return Path != null ? (int)Path[^1].GetImmediate(1) : throw new FactException($"opcode {Wire}: no size check");
        }

        private static bool IsSizeCheck(Function Iterator, in Instruction Instruction, Register Remaining)
            => Instruction.Mnemonic == Mnemonic.Cmp && Instruction.Op0Kind == OpKind.Register && Instruction.Op0Register.GetFullRegister() == Remaining &&
               Instruction.Op1Kind.IsImmediate() && Iterator.TryGet(Instruction.NextIP, out Instruction Branch) && Branch.Mnemonic is Mnemonic.Jb or Mnemonic.Jae;

        private static bool PassesSizeCheck(List<Instruction> Path, Register Remaining, int Size)
        {
            for (int i = 0; i + 2 < Path.Count; i++)
            {
                if (Path[i].Mnemonic != Mnemonic.Cmp || Path[i].Op0Kind != OpKind.Register || Path[i].Op0Register.GetFullRegister() != Remaining ||
                    !Path[i].Op1Kind.IsImmediate() || (int)Path[i].GetImmediate(1) != Size)
                    continue;

                return Path[i + 1].Mnemonic switch
                {
                    Mnemonic.Jb => Path[i + 2].IP == Path[i + 1].NextIP,
                    Mnemonic.Jae => Path[i + 2].IP == Path[i + 1].NearBranchTarget,
                    _ => false,
                };
            }

            return false;
        }

        // NT: the create case refuses a type outside 1..MaxType with lea t, [type-1] / cmp t, MaxType-1 / ja.
        private static uint ReadTypeRangeCheck(List<Instruction> Path, int Wire)
        {
            for (int i = 0; i + 3 < Path.Count; i++)
            {
                if (Path[i].Mnemonic == Mnemonic.Lea && Path[i].Op0Register.IsGPR32() && (long)Path[i].MemoryDisplacement64 == -1 &&
                    Path[i + 1].Mnemonic == Mnemonic.Cmp && Path[i + 1].Op0Kind == OpKind.Register && Path[i + 1].Op0Register == Path[i].Op0Register &&
                    Path[i + 1].Op1Kind.IsImmediate() && Path[i + 2].Mnemonic == Mnemonic.Ja && Path[i + 3].IP == Path[i + 2].NextIP)
                    return (uint)Path[i + 1].GetImmediate(1) + 1;
            }

            throw new FactException($"CreateResource (opcode {Wire}): no type range check");
        }

        private static SortedSet<(int Offset, int Bytes)> ReadRecordFields(List<Instruction> Path, HashSet<Register> Cursors)
        {
            InstructionInfoFactory Info = new();
            HashSet<Register> Aliases = new(Cursors);
            SortedSet<(int, int)> Fields = new();
            foreach (Instruction Instruction in Path)
            {
                foreach (UsedMemory Memory in Info.GetInfo(Instruction).GetUsedMemory())
                {
                    if (Memory.Access is OpAccess.Read or OpAccess.ReadWrite or OpAccess.CondRead or OpAccess.ReadCondWrite &&
                        Aliases.Contains(Memory.Base.GetFullRegister()) && Memory.Index == Register.None)
                        Fields.Add(((int)Memory.Displacement, Memory.MemorySize.GetSize()));
                }

                TrackCopies(Aliases, Info, Instruction);
            }

            return Fields;
        }

        private static void TrackCopies(HashSet<Register> Aliases, InstructionInfoFactory Info, in Instruction Instruction)
        {
            if (Instruction.Mnemonic == Mnemonic.Mov && Instruction.Op0Kind == OpKind.Register && Instruction.Op1Kind == OpKind.Register &&
                Instruction.Op0Register.IsGPR64() && Aliases.Contains(Instruction.Op1Register.GetFullRegister()))
            {
                Aliases.Add(Instruction.Op0Register);
                return;
            }

            ForgetClobbered(Aliases, Info.GetInfo(Instruction), Instruction);
        }

        private static void ForgetClobbered(HashSet<Register> Registers, in InstructionInfo Used, in Instruction Instruction)
        {
            foreach (UsedRegister Register in Used.GetUsedRegisters())
            {
                if (Register.Access is OpAccess.Write or OpAccess.ReadWrite or OpAccess.CondWrite or OpAccess.ReadCondWrite)
                    Registers.Remove(Register.Register.GetFullRegister());
            }

            if (Instruction.FlowControl is FlowControl.Call or FlowControl.IndirectCall)
                Registers.ExceptWith(VolatileRegisters);
        }

        private static string FormatFields(IEnumerable<(int Offset, int Bytes)> Fields)
            => string.Join(" ", Fields.OrderBy(Field => Field.Offset).Select(Field => $"+{Field.Offset}:{Field.Bytes}"));

        private static (CommandRule Rule, bool Wrapped) CommandAt(VersionInputs Inputs, List<Instruction> Path, Dictionary<string, uint> Slots)
        {
            Instruction Last = Path[^1];
            string Callee = CalleeName(Inputs, Last);
            if (Callee == null)
            {
                uint? Slot = IsPlainLoad(Last) ? VirtualSlots(Path)[^1] : null;
                return (Commands.FirstOrDefault(Command => Command.Method != null && Slot == Slots[Command.Method]), false);
            }

            CommandRule Named = Commands.FirstOrDefault(Command => Names(Command, Callee));
            if (Named != null || Last.FlowControl != FlowControl.Call || !IsChannelFunction(Callee, false))
                return (Named, false);

            Function Wrapper = Function.Decode(Inputs.Image, Inputs.Publics, (uint)(Last.NearBranchTarget - Inputs.Image.ImageBase));
            HashSet<CommandRule> Called = new();
            if (ChannelCalls(Inputs, Wrapper, MaxWrapperDepth, false).Any(Function => Function.Instructions.Any(Instruction =>
                    Instruction.FlowControl is FlowControl.Call or FlowControl.UnconditionalBranch && CalleeName(Inputs, Instruction) is string Name &&
                    Names(CreateRule, Name))))
                Called.Add(CreateRule);

            if (Callee.StartsWith(ChannelWrapper, StringComparison.Ordinal))
            {
                HashSet<uint?> Loads = ChannelCalls(Inputs, Wrapper, MaxWrapperDepth, true).SelectMany(Function => VirtualSlots(Function.Instructions.ToList())).ToHashSet();
                Called.UnionWith(Commands.Where(Command => Command.Method != null && Loads.Contains(Slots[Command.Method])));
            }

            return Called.Count == 1 ? (Called.First(), true) : (null, false);
        }

        // For each instruction that loads a function from a vtable, the slot it loads: mov v, [object] puts a vtable in v
        // until v is written again, and mov f, [v + slot] loads from it.
        private static uint?[] VirtualSlots(List<Instruction> Code)
        {
            InstructionInfoFactory Info = new();
            HashSet<Register> Vtables = new();
            uint?[] Slots = new uint?[Code.Count];
            for (int i = 0; i < Code.Count; i++)
            {
                Instruction Instruction = Code[i];
                bool Load = IsPlainLoad(Instruction);
                if (Load && Vtables.Contains(Instruction.MemoryBase))
                    Slots[i] = (uint)Instruction.MemoryDisplacement64;

                ForgetClobbered(Vtables, Info.GetInfo(Instruction), Instruction);
                if (Load && Instruction.MemoryDisplacement64 == 0)
                    Vtables.Add(Instruction.Op0Register);
            }

            return Slots;
        }

        private static bool IsPlainLoad(in Instruction Instruction)
            => Instruction.Mnemonic == Mnemonic.Mov && Instruction.Op0Kind == OpKind.Register && Instruction.Op0Register.IsGPR64() &&
               Instruction.Op1Kind == OpKind.Memory && Instruction.MemoryIndex == Register.None && !Instruction.IsIPRelativeMemoryOperand;

        private static IEnumerable<Function> ChannelCalls(VersionInputs Inputs, Function Function, int Depth, bool SetResourceOnly)
        {
            yield return Function;
            if (Depth <= 1)
                yield break;

            foreach (Instruction Instruction in Function.Instructions)
            {
                if (Instruction.FlowControl != FlowControl.Call || CalleeName(Inputs, Instruction) is not string Name || !IsChannelFunction(Name, SetResourceOnly))
                    continue;

                Function Callee = Function.Decode(Inputs.Image, Inputs.Publics, (uint)(Instruction.NearBranchTarget - Inputs.Image.ImageBase));
                foreach (Function Reached in ChannelCalls(Inputs, Callee, Depth - 1, SetResourceOnly))
                    yield return Reached;
            }
        }

        private static bool IsChannelFunction(string Name, bool SetResourceOnly)
            => (!SetResourceOnly || Name.StartsWith(ChannelWrapper, StringComparison.Ordinal)) && !Name.StartsWith(Iterator, StringComparison.Ordinal) &&
               Name.Contains("@CApplicationChannel@" + NtNamespace + "@@", StringComparison.Ordinal);

        private static bool Names(CommandRule Command, string Function) => Command.Markers.Any(Marker => Function.StartsWith(Marker, StringComparison.Ordinal));

        private static string CalleeName(VersionInputs Inputs, in Instruction Instruction)
        {
            ulong Target;
            if (Instruction.FlowControl is FlowControl.Call or FlowControl.UnconditionalBranch && Instruction.Op0Kind == OpKind.NearBranch64)
                Target = Instruction.NearBranchTarget;
            else if (Instruction.Mnemonic == Mnemonic.Lea && Instruction.IsIPRelativeMemoryOperand)
                Target = Instruction.IPRelativeMemoryAddress;
            else
                return null;

            ulong Base = Inputs.Image.ImageBase;
            return Target >= Base && Target - Base < Inputs.Image.SizeOfImage ? Inputs.Publics.NameAt((uint)(Target - Base)) : null;
        }

        // IsDerivedResourceType walks parent = table[type] until it meets the base or passes the table, so a type derives from
        // itself only below the table's length. Every entry of the table that the walk loads is checked against a run of it.
        private static int[] ReadParents(VersionInputs Inputs)
        {
            uint Walker = Inputs.Publics.Find(IsDerived);
            Function Walk = Readers.Function.Decode(Inputs.Image, Inputs.Publics, Walker);
            List<ulong> Tables = Walk.Instructions.Where(Instruction => Instruction.Mnemonic == Mnemonic.Lea && Instruction.IsIPRelativeMemoryOperand)
                .Select(Instruction => Instruction.IPRelativeMemoryAddress).Distinct().ToList();
            if (Tables.Count != 1)
                throw new FactException($"parent table: the walk loads {Tables.Count} tables");

            using Machine Machine = Machine.Load(Inputs.Image, Inputs.Publics);
            bool Derived(uint Type, uint Base) => (Machine.Call(Walker, Type, Base) & 0xFF) == 1;
            uint Limit = 0;
            while (Limit <= byte.MaxValue && Derived(Limit, Limit))
                Limit++;

            if (Limit == 0 || Limit > byte.MaxValue || Enumerable.Range((int)Limit, 16).Any(Type => Derived((uint)Type, (uint)Type)))
                throw new FactException($"parent table: no end below 0x{byte.MaxValue + 1:X}");

            int[] Parents = new int[Limit];
            uint Table = (uint)(Tables[0] - Inputs.Image.ImageBase);
            for (uint Type = 0; Type < Limit; Type++)
            {
                uint Parent = Inputs.Image.ReadUInt32(Table + Type * 4);
                if (Parent > Limit)
                    throw new FactException($"parent table: type 0x{Type:X} has parent 0x{Parent:X} past 0x{Limit:X}");

                if (Parent < Limit && !Derived(Type, Parent))
                    throw new FactException($"parent table: the walk disagrees with the table at type 0x{Type:X}");

                Parents[Type] = (int)Parent;
            }

            return Parents;
        }

        // CreatePrivateMarshaler runs for every type with every feature check answering 0 and then 1. A type maps to a
        // class only when both runs build an object with that class's vtable.
        private static string[] ReadTypeClasses(VersionInputs Inputs, uint MaxType)
        {
            Dictionary<ulong, string> ByVtable = new();
            foreach (ClassRule Class in Classes)
            {
                if (!Inputs.Publics.TryGet(VtableName(Class.NtClass), out uint Vtable))
                    throw new FactException($"{Class.NtClass}: no vtable");

                if (!ByVtable.TryAdd(Vtable, Class.Name))
                    throw new FactException($"{Class.NtClass}: shares its vtable with {ByVtable[Vtable]}");
            }

            string[][] States = new string[2][];
            for (int Feature = 0; Feature < 2; Feature++)
            {
                using Session Session = new(Inputs, Feature);
                string[] Created = new string[MaxType + 1];
                Created[0] = "";
                for (uint Type = 1; Type <= MaxType; Type++)
                {
                    ulong Object = Session.TryCreate(Type);
                    Created[Type] = Object != 0 && ByVtable.TryGetValue(Session.Machine.ReadUInt64(Object) - Inputs.Image.ImageBase, out string Class) ? Class : "";
                }

                States[Feature] = Created;
            }

            string[] TypeClasses = new string[MaxType + 1];
            for (int Type = 0; Type <= MaxType; Type++)
                TypeClasses[Type] = States[0][Type] == States[1][Type] ? States[0][Type] : "";

            foreach (ClassRule Class in Classes)
            {
                if (!TypeClasses.Contains(Class.Name))
                    throw new FactException($"{Class.NtClass}: no type creates it");
            }

            return TypeClasses;
        }

        private static void CheckClassSlots(VersionInputs Inputs, Dictionary<string, uint> Slots)
        {
            Dictionary<string, uint> BaseStubs = SlotMethods.ToDictionary(Method => Method, Method => Inputs.Publics.Find(MemberName(BaseClass, Method)));
            foreach (ClassRule Class in Classes)
            {
                if (!Inputs.Publics.TryGet(VtableName(Class.NtClass), out uint Vtable))
                    throw new FactException($"{Class.NtClass}: no vtable");

                foreach ((string Method, string Expected) in new[] { (SetInteger, Class.Integer), (SetBuffer, Class.Buffer), (SetReference, Class.Reference), (SetCallbackId, Class.CallbackId) })
                {
                    uint Entry = (uint)(Inputs.Image.ReadUInt64(Vtable + Slots[Method]) - Inputs.Image.ImageBase);
                    bool Matches = Expected switch
                    {
                        Base => Entry == BaseStubs[Method],
                        Own => Entry != BaseStubs[Method],
                        _ => Entry == Inputs.Publics.Find(MemberName(Expected, Method)),
                    };

                    if (!Matches)
                        throw new FactException($"{Class.NtClass}::{Method} is {Inputs.Publics.NameAt(Entry) ?? $"0x{Entry:X}"}, Brovan expects {Expected}");
                }
            }
        }

        private static void CheckBaseAnswers(VersionInputs Inputs, string[] TypeClasses)
        {
            using Session Session = new(Inputs, 0);
            Machine Machine = Session.Machine;
            ulong Updated = Machine.Alloc(8);
            ulong Data = Machine.Alloc(64);
            ulong Brush = Session.Create(TypeOf(TypeClasses, "ColorBrush"));
            ulong Visual = Session.Create(TypeOf(TypeClasses, "Visual"));

            uint Status(string Function, params ulong[] Args) => (uint)Machine.Call(Inputs.Publics.Find(Function), Args);
            void Expect(string What, uint Actual, uint Expected)
            {
                if (Actual != Expected)
                    throw new FactException($"{What} answers 0x{Actual:X8}, Brovan answers 0x{Expected:X8}");
            }

            Expect("base " + SetInteger, Status(MemberName(BaseClass, SetInteger), Brush, Session.Channel, 0, 0, Updated), StatusInvalidParameter);
            Expect("base " + SetBuffer, Status(MemberName(BaseClass, SetBuffer), Brush, Session.Channel, 0, Data, ColorBytes, Updated), StatusInvalidParameter);
            Expect("base " + SetReference, Status(MemberName(BaseClass, SetReference), Brush, Session.Channel, 0, 0, Updated), StatusInvalidParameter);
            Expect("base " + SetCallbackId, Status(MemberName(BaseClass, SetCallbackId), Brush, 1, Updated), StatusNotSupported);
            Expect("notification " + SetCallbackId, Status(MemberName("CNotificationResourceMarshaler", SetCallbackId), Visual, 0x40200003, Updated), StatusSuccess);

            string ColorBuffer = MemberName("CColorBrushMarshaler", SetBuffer);
            Expect("color buffer of 16 bytes", Status(ColorBuffer, Brush, Session.Channel, 0, Data, ColorBytes, Updated), StatusSuccess);
            Expect("color buffer of 15 bytes", Status(ColorBuffer, Brush, Session.Channel, 0, Data, ColorBytes - 1, Updated), StatusInvalidParameter);
            Expect("color buffer of 17 bytes", Status(ColorBuffer, Brush, Session.Channel, 0, Data, ColorBytes + 1, Updated), StatusInvalidParameter);
            Expect("color buffer property 1", Status(ColorBuffer, Brush, Session.Channel, 1, Data, ColorBytes, Updated), StatusInvalidParameter);
            Expect("color buffer without data", Status(ColorBuffer, Brush, Session.Channel, 0, 0, ColorBytes, Updated), StatusInvalidParameter);
        }

        // NT: CPropertyChangeResourceMarshaler::SetIntegerProperty accepts one property, the property-change mask.
        private static uint ReadPropertyChangeMask(VersionInputs Inputs, string[] TypeClasses)
        {
            using Session Session = new(Inputs, 0);
            ulong Updated = Session.Machine.Alloc(8);
            ulong Transform = Session.Create(TypeOf(TypeClasses, "ComponentTransform3D"));
            string Name = MemberName(PropertyChangeClass, SetInteger);
            uint Function = Inputs.Publics.Find(Name);
            List<uint> Accepted = new();
            foreach (uint Property in ScanProperties(Inputs, Name))
            {
                uint Status = (uint)Session.Machine.Call(Function, Transform, Session.Channel, Property, 1, Updated);
                if (Status == StatusSuccess)
                    Accepted.Add(Property);
                else if (Status != StatusInvalidParameter)
                    throw new FactException($"property-change property 0x{Property:X} answers 0x{Status:X8}");
            }

            if (Accepted.Count != 1)
                throw new FactException($"property-change mask: {Accepted.Count} properties accepted");

            return Accepted[0];
        }

        // NT: CVisualMarshaler::SetIntegerProperty handles some properties itself and passes the rest to the
        // property-change base. A property is the Visual's own when any feature state handles it without the base.
        private static uint[] ReadVisualOwnIntegers(VersionInputs Inputs, string[] TypeClasses, uint Mask)
        {
            string Name = MemberName(VisualClass, SetInteger);
            uint Function = Inputs.Publics.Find(Name);
            uint BaseSetter = Inputs.Publics.Find(MemberName(PropertyChangeClass, SetInteger));
            uint[] Scanned = ScanProperties(Inputs, Name).Append(Mask).ToArray();
            SortedSet<uint> Own = new();
            for (int Feature = 0; Feature < 2; Feature++)
            {
                using Session Session = new(Inputs, Feature);
                ulong Updated = Session.Machine.Alloc(8);
                Session.Machine.PatchReturn(BaseSetter, BaseMarker);
                ulong Visual = Session.Create(TypeOf(TypeClasses, "Visual"));
                foreach (uint Property in Scanned)
                {
                    if (Session.Machine.TryCall(Function, Visual, Session.Channel, Property, 1, Updated) is not ulong Status || (uint)Status != BaseMarker)
                        Own.Add(Property);
                }
            }

            if (Own.Contains(Mask))
                throw new FactException($"Visual handles the property-change mask 0x{Mask:X} itself");

            return Own.ToArray();
        }

        // A property is the Visual's own when a target in unmapped memory gets any answer but invalid parameter. The transform
        // is the own property that takes null and exactly the types derived from Transform3D, ComponentTransform3D's parent.
        private static (uint Transform, uint TransformBase, uint[] Handled) ReadVisualReferences(VersionInputs Inputs, string[] TypeClasses, int[] Parents)
        {
            string Name = MemberName(VisualClass, SetReference);
            uint Function = Inputs.Publics.Find(Name);
            uint TransformType = TypeOf(TypeClasses, "ComponentTransform3D");
            uint Required = (uint)Parents[TransformType];
            using Session Session = new(Inputs, 0);
            Machine Machine = Session.Machine;
            ulong Updated = Machine.Alloc(8);
            ulong Visual = Session.Create(TypeOf(TypeClasses, "Visual"));
            List<(uint Type, ulong Object)> Targets = new();
            for (uint Type = 1; Type < TypeClasses.Length; Type++)
            {
                ulong Object = Session.TryCreate(Type);
                if (Object != 0)
                    Targets.Add((Type, Object));
            }

            Machine.Snapshot Start = Machine.Save();
            uint? Answer(uint Property, ulong Target)
            {
                Machine.Restore(Start);
                return Machine.TryCall(Function, Visual, Session.Channel, Property, Target, Updated) is ulong Status ? (uint)Status : null;
            }

            ulong TransformObject = Targets.First(Target => Target.Type == TransformType).Object;
            SortedSet<uint> Own = new();
            List<(uint Property, uint Base)> Transforms = new();
            foreach (uint Property in ScanProperties(Inputs, Name))
            {
                if (Answer(Property, UnmappedTarget) == StatusInvalidParameter)
                    continue;

                Own.Add(Property);
                if (Answer(Property, 0) != StatusSuccess || Answer(Property, TransformObject) != StatusSuccess)
                    continue;

                HashSet<uint> Accepted = Targets.Where(Target => Answer(Property, Target.Object) == StatusSuccess).Select(Target => Target.Type).ToHashSet();
                if (Targets.All(Target => IsDerivedFrom(Parents, Target.Type, Required) == Accepted.Contains(Target.Type)))
                    Transforms.Add((Property, Required));
            }

            if (Transforms.Count != 1)
                throw new FactException($"Visual transform: {Transforms.Count} properties take an optional 0x{Required:X} " +
                                        $"({string.Join(", ", Transforms.Select(Transform => $"0x{Transform.Property:X}"))})");

            return (Transforms[0].Property, Transforms[0].Base, Own.ToArray());
        }

        private static bool IsDerivedFrom(int[] Parents, uint Type, uint Base)
        {
            while (Type < Parents.Length)
            {
                if (Type == Base)
                    return true;

                Type = (uint)Parents[Type];
            }

            return false;
        }

        // Every property value that can take its own path through Function. Past the sum of the constants its compares
        // and subtractions use, every value takes the same path. The scan is capped and always tries the wide mask property.
        private static IEnumerable<uint> ScanProperties(VersionInputs Inputs, string Name)
        {
            Function Function = Readers.Function.Decode(Inputs.Image, Inputs.Publics, Inputs.Publics.Find(Name));
            ulong Sum = 0;
            foreach (Instruction Instruction in Function.Instructions)
            {
                if (Instruction.Mnemonic is Mnemonic.Cmp or Mnemonic.Sub or Mnemonic.Add && Instruction.Op0Kind == OpKind.Register &&
                    Instruction.Op0Register.IsGPR32() && Instruction.Op1Kind.IsImmediate())
                    Sum += (ulong)Math.Abs((long)(int)(uint)Instruction.GetImmediate(1));
                else if (Instruction.Mnemonic == Mnemonic.Lea && Instruction.Op0Register.IsGPR32())
                    Sum += (ulong)Math.Abs((long)(int)(uint)Instruction.MemoryDisplacement64);
            }

            uint Bound = (uint)Math.Min(Sum + 2, MaxScanProperty);
            for (uint Property = 0; Property < Bound; Property++)
                yield return Property;

            if (Bound <= WideMaskProperty)
                yield return WideMaskProperty;
        }

        private static uint TypeOf(string[] TypeClasses, string Class)
        {
            int Type = Array.IndexOf(TypeClasses, Class);
            if (Type < 0 || Array.LastIndexOf(TypeClasses, Class) != Type)
                throw new FactException($"{Class}: {TypeClasses.Count(Name => Name == Class)} types");

            return (uint)Type;
        }

        private static string MemberName(string Class, string Method) => $"?{Method}@{Class}@{NtNamespace}@@";

        private static string VtableName(string Class) => $"??_7{Class}@{NtNamespace}@@6B@";

        private static bool IsCompare(in Instruction Instruction, ulong Value)
            => Instruction.Mnemonic == Mnemonic.Cmp && Instruction.Op0Kind == OpKind.Register && Instruction.Op0Register.IsGPR32() &&
               Instruction.Op1Kind.IsImmediate() && Instruction.GetImmediate(1) == Value;

        private sealed class Session : IDisposable
        {
            private readonly uint FactoryRva;
            private readonly ulong Out;

            internal Machine Machine { get; }
            internal ulong Channel { get; }

            internal Session(VersionInputs Inputs, int Feature)
            {
                FactoryRva = Inputs.Publics.Find(Factory);
                Machine = Machine.Load(Inputs.Image, Inputs.Publics);
                try
                {
                    foreach (uint Rva in Inputs.Publics.NamesStartingWith("Feature_").Where(Symbol => Symbol.Name.Contains("IsEnabled", StringComparison.Ordinal))
                                 .Select(Symbol => Symbol.Rva).Distinct().ToList())
                        Machine.PatchReturn(Rva, (ulong)Feature);

                    // NT: pool allocations go through the leak-tracking allocator object, kept in the session state or, in
                    // older builds, in a global. A zeroed one allocates straight from pool.
                    Machine.PatchImportReturn(SessionState, Machine.Alloc(SessionStateBytes));
                    if (Inputs.Publics.TryFind(LeakTrackingAllocator, "", out uint Global))
                        Machine.WriteUInt64(Machine.Va(Global), Machine.Alloc(ObjectBytes));

                    Channel = Machine.Alloc(ObjectBytes);
                    Machine.Call(Inputs.Publics.Find(ChannelConstructor), Channel, Machine.Alloc(ObjectBytes), 1, 0);
                    Out = Machine.Alloc(8);
                }
                catch
                {
                    Machine.Dispose();
                    throw;
                }
            }

            internal ulong TryCreate(uint Type)
            {
                Machine.WriteUInt64(Out, 0);
                ulong? Status = Machine.TryCall(FactoryRva, Channel, Type, Out);
                return Status is ulong Answer && (uint)Answer == StatusSuccess ? Machine.ReadUInt64(Out) : 0;
            }

            internal ulong Create(uint Type)
            {
                ulong Object = TryCreate(Type);
                return Object != 0 ? Object : throw new FactException($"type 0x{Type:X}: no object");
            }

            public void Dispose() => Machine.Dispose();
        }

        protected override void WriteTypes(SourceWriter Code)
        {
            WriteEnum(Code, "CompositionCommand", new[] { "None", "Other" }.Concat(Commands.Select(Command => Command.Name)));
            WriteEnum(Code, "CompositionClass", new[] { "None" }.Concat(Classes.Select(Class => Class.Name)));
            WriteEnum(Code, "CompositionProperty", Properties);
        }

        private static void WriteEnum(SourceWriter Code, string Name, IEnumerable<string> Members)
        {
            Code.Line($"    internal enum {Name} : byte");
            Code.Line("    {");
            foreach (string Member in Members)
                Code.Line($"        {Member},");

            Code.Line("    }");
            Code.Line();
        }

        protected override void WriteMembers(SourceWriter Code)
        {
            Code.Line("        internal readonly CompositionCommand[] Commands;");
            Code.Line("        internal readonly byte[] RecordSizes;");
            Code.Line("        internal readonly uint MaxType;");
            Code.Line("        internal readonly byte[] Parents;");
            Code.Line("        internal readonly CompositionClass[] TypeClasses;");
            Code.Line("        private readonly uint[] PropertyIds;");
            Code.Line("        private readonly uint[] RequiredBases;");
            Code.Line("        private readonly (CompositionClass Class, CompositionSlots Setter, uint[] Properties)[] OwnProperties;");
            Code.Line();
            Code.Line("        // NT: an opcode the kernel refuses has record size 0 and command None. Parents has one entry per type, and its");
            Code.Line("        // length is where the walk ends.");
            Code.Line("        private CompositionTableSet(byte[] RecordSizes, (int Opcode, CompositionCommand Command)[] Commands, byte[] Parents,");
            Code.Line("            (int Type, CompositionClass Class)[] Classes, (CompositionProperty Property, uint Id, uint Base)[] Properties,");
            Code.Line("            (CompositionClass Class, CompositionSlots Setter, uint[] Properties)[] OwnProperties)");
            Code.Line("        {");
            Code.Line("            this.RecordSizes = RecordSizes;");
            Code.Line("            this.Commands = new CompositionCommand[RecordSizes.Length];");
            Code.Line("            for (int Opcode = 0; Opcode < RecordSizes.Length; Opcode++)");
            Code.Line("                this.Commands[Opcode] = RecordSizes[Opcode] == 0 ? CompositionCommand.None : CompositionCommand.Other;");
            Code.Line();
            Code.Line("            foreach ((int Opcode, CompositionCommand Command) in Commands)");
            Code.Line("                this.Commands[Opcode] = Command;");
            Code.Line();
            Code.Line("            MaxType = (uint)Parents.Length - 1;");
            Code.Line("            this.Parents = Parents;");
            Code.Line("            TypeClasses = new CompositionClass[MaxType + 1];");
            Code.Line("            foreach ((int Type, CompositionClass Class) in Classes)");
            Code.Line("                TypeClasses[Type] = Class;");
            Code.Line();
            Code.Line("            PropertyIds = new uint[Properties.Length];");
            Code.Line("            RequiredBases = new uint[Properties.Length];");
            Code.Line("            foreach ((CompositionProperty Property, uint Id, uint Base) in Properties)");
            Code.Line("            {");
            Code.Line("                PropertyIds[(int)Property] = Id;");
            Code.Line("                RequiredBases[(int)Property] = Base;");
            Code.Line("            }");
            Code.Line();
            Code.Line("            this.OwnProperties = OwnProperties;");
            Code.Line("        }");
            Code.Line();
            Code.Line("        internal uint Property(CompositionProperty Property) => PropertyIds[(int)Property];");
            Code.Line();
            Code.Line("        internal uint RequiredBase(CompositionProperty Property) => RequiredBases[(int)Property];");
            Code.Line();
            Code.Line("        internal bool IsOwnProperty(CompositionClass Class, CompositionSlots Setter, uint Property)");
            Code.Line("        {");
            Code.Line("            foreach ((CompositionClass OwnClass, CompositionSlots OwnSetter, uint[] Properties) in OwnProperties)");
            Code.Line("            {");
            Code.Line("                if (OwnClass == Class && OwnSetter == Setter)");
            Code.Line("                    return Array.IndexOf(Properties, Property) >= 0;");
            Code.Line("            }");
            Code.Line();
            Code.Line("            return false;");
            Code.Line("        }");
        }

        protected override void WriteSet(SourceWriter Code, string Json)
        {
            CompositionFacts Facts = JsonSerializer.Deserialize<CompositionFacts>(Json);
            if (!Facts.Properties.Select(Property => Property.Name).SequenceEqual(Properties))
                throw new InvalidDataException("the facts do not list the properties in the order of CompositionProperty");

            Code.Line($"            new byte[] {{ {string.Join(", ", Facts.RecordSizes)} }},");
            Code.Line("            new[]");
            Code.Line("            {");
            for (int Opcode = 0; Opcode < Facts.Commands.Length; Opcode++)
            {
                if (Facts.Commands[Opcode].Length != 0)
                    Code.Line($"                ({Opcode}, CompositionCommand.{Facts.Commands[Opcode]}),");
            }

            Code.Line("            },");
            Code.Line("            new byte[]");
            Code.Line("            {");
            for (int Row = 0; Row < Facts.Parents.Length; Row += 16)
                Code.Line($"                {string.Join(" ", Facts.Parents.Skip(Row).Take(16).Select(Parent => $"0x{Parent:X2},"))}");

            Code.Line("            },");
            Code.Line("            new[]");
            Code.Line("            {");
            for (int Type = 0; Type < Facts.TypeClasses.Length; Type++)
            {
                if (Facts.TypeClasses[Type].Length != 0)
                    Code.Line($"                (0x{Type:X}, CompositionClass.{Facts.TypeClasses[Type]}),");
            }

            Code.Line("            },");
            Code.Line("            new[]");
            Code.Line("            {");
            foreach (CompositionPropertyFact Property in Facts.Properties)
                Code.Line($"                (CompositionProperty.{Property.Name}, 0x{Property.Id:X}u, 0x{Property.Base:X}u),");

            Code.Line("            },");
            Code.Line("            new[]");
            Code.Line("            {");
            foreach (CompositionOwnPropertiesFact Own in Facts.OwnProperties)
            {
                Code.Line($"                (CompositionClass.{Own.Class}, CompositionSlots.{Own.Setter},");
                Code.Line($"                    new uint[] {{ {string.Join(", ", Own.Properties.Select(Property => $"0x{Property:X}"))} }}),");
            }

            Code.Line("            });");
        }
    }
}
