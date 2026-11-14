using System.Buffers.Binary;
using System.Text.Json;
using Brovan.WinFacts.Readers;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace Brovan.WinFacts.Rules
{
    internal sealed record CompositionFacts(
        string[] Commands,
        int[] RecordSizes,
        uint MaxType,
        int[] Parents,
        string[] TypeClasses,
        CompositionPropertyFact[] Properties,
        CompositionReferenceFact[] References,
        CompositionHandleFact[] Handles,
        CompositionOwnPropertiesFact[] OwnProperties,
        CompositionOwnPropertiesFact[] Refused,
        CompositionRuleFact[] Rules,
        CompositionOwnerFact[] RuleOwners);

    // Bases are the types whose subtrees a reference property takes, empty for other properties.
    internal sealed record CompositionPropertyFact(string Name, uint Id, uint[] Bases);

    internal sealed record CompositionHandleFact(string Class, string Property, uint Id, uint Access, uint Kind);

    internal sealed record CompositionReferenceFact(string Class, string Property);

    internal sealed record CompositionOwnerFact(string Class, string Owner);

    internal sealed record CompositionOwnPropertiesFact(string Class, string Setter, uint[] Properties);

    // Initial is the start value where a run finds it: the integer, its truth for a NonZero compare, or the bits of a float.
    // The NonZero flag marks a buffer that takes only nonzero bytes.
    internal sealed record CompositionRuleFact(string Class, string Setter, uint Property, int Bytes, ulong[] Values, string Compare, ulong? Initial = null)
    {
        public bool NonZero { get; init; }
        public string Requires { get; init; }
        public uint[] RequiredBases { get; init; }
    }

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
        private const uint ChangeMarker = 0x7EADBEEE;
        private const uint ReferenceMarker = 0x7EAD0100;
        private const uint HandleMarker = 0x7EAD0200;
        private const ulong FakeHandle = 0x1234;
        private const string ReferenceObject = "DxgkReferenceCompositionObject";
        private const string EnsureBatchBuffer = "?EnsureBatchBuffer@CBatch@" + NtNamespace + "@@";
        private const int PageBytes = 0x1000;
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
        private const string SetFloat = "SetFloatProperty";
        private const string SetHandle = "SetHandleProperty";
        private const string EmitUpdate = "EmitUpdateCommands";
        private const string Initialize = "Initialize";
        private const string AddChild = "AddChild";
        private const string RemoveChild = "RemoveChild";
        private const string RemoveAllChildren = "RemoveAllChildren";
        private static readonly string[] SlotMethods = { SetInteger, SetBuffer, SetReference, SetCallbackId, SetFloat, SetHandle };

        // The Visual's child methods move between builds, and older builds call them through their slots.
        private static readonly string[] ChildMethods = { AddChild, RemoveChild, RemoveAllChildren };
        internal static readonly Register[] VolatileRegisters = { Register.RAX, Register.RCX, Register.RDX, Register.R8, Register.R9, Register.R10, Register.R11 };

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
            new("SetFloat", new[] { "?" + SetFloat + "@" }, 16, new[] { (4, 4), (8, 4), (12, 4) }, SetFloat),
            new("SetHandle", new[] { "?" + SetHandle + "@" }, 24, new[] { (4, 4), (8, 4), (16, 8) }, SetHandle),
            new("OpenResource", new[] { OpenRead, OpenWrite, OpenInternalRead, OpenInternalWrite }, 24, new[] { (4, 4), (8, 8), (16, 4), (20, 4) }, null),
            new("InsertChild", new[] { "?" + AddChild + "@" + VisualClass + "@" + NtNamespace + "@@", "?AddVisualChild@CApplicationChannel@" + NtNamespace + "@@" }, 20, new[] { (4, 4), (8, 4), (12, 4), (16, 4) }, AddChild),
            new("RemoveChild", new[] { "?" + RemoveChild + "@" + VisualClass + "@" + NtNamespace + "@@", "?" + RemoveAllChildren + "@" + VisualClass + "@" + NtNamespace + "@@",
                    "?RemoveVisualChild@CApplicationChannel@" + NtNamespace + "@@" },
                12, new[] { (4, 4), (8, 4) }, RemoveChild),
        };

        private static readonly CommandRule CreateRule = Commands[0];
        private static readonly CommandRule OpenRule = Commands.First(Command => Command.Name == "OpenResource");

        // Each setter slot holds CResourceMarshaler's stub (Base), any other function (Own), or the named function, or is
        // not checked (Any). CResourceMarshaler::SetFloatProperty is not a stub, so a Float slot is never Base.
        private static readonly ClassRule[] Classes =
        {
            new("BlurredWallpaperBackdropBrush", "CBlurredWallpaperBackdropBrushMarshaler", Base, Base, Base, Base, Any, Base),
            new("ColorBrush", "CColorBrushMarshaler", Base, "CColorBrushMarshaler", Base, Base, Any, Base, Ruled: new[] { SetBuffer }),
            new("ComponentTransform3D", "CComponentTransform3DMarshaler", "CPropertyChangeResourceMarshaler", Own, Base, "CNotificationResourceMarshaler", Any,
                Base),
            new("Visual", "CVisualMarshaler", "CVisualMarshaler", Own, "CVisualMarshaler", "CNotificationResourceMarshaler", Any, Base,
                Ruled: new[] { SetInteger, SetFloat, SetBuffer }, Kept: new KeptReference[] { new(VisualTransform, "ComponentTransform3D", 1) }),
            new("SurfaceBrush", SurfaceBrushClass, SurfaceBrushClass, SurfaceBrushClass, SurfaceBrushClass, Base, Any, Base,
                Ruled: new[] { SetInteger, SetFloat, SetBuffer }, NullOnly: true,
                Kept: new KeptReference[] { new(SurfaceBrushSurface, "CompositionSurfaceBitmap", 0, Union: true) }),
            new("SpriteVisual", SpriteVisualClass, VisualClass, VisualClass, SpriteVisualClass, "CNotificationResourceMarshaler", Any, Base, RuleOwner: "Visual",
                Kept: new KeptReference[] { new(SpriteVisualBrush, "ColorBrush", 1) }),
            new("VisualTarget", VisualTargetClass, Base, Base, VisualTargetClass, Base, Any, Base, Opened: true,
                Kept: new KeptReference[] { new(VisualTargetRoot, "Visual", 0) }),
            new("CompositionSurfaceBitmap", SurfaceBitmapClass, SurfaceBitmapClass, Base, Base, Base, Any, SurfaceBitmapClass,
                Ruled: new[] { SetInteger }, HandleName: SurfaceBitmapSurface),
        };

        private const string Base = "<base>";
        private const string Own = "<own>";
        private const string Any = "<any>";
        private const string SurfaceBrushClass = "CSurfaceBrushMarshaler";
        private const string SpriteVisualClass = "CSpriteVisualMarshaler";
        private const string VisualTargetClass = "CVisualTargetMarshaler";
        private const string SurfaceBitmapClass = "CCompositionSurfaceBitmapMarshaler";
        private const string FloatSignature = "UEAAJIMPEA_N@Z";
        private const int MaxBufferBytes = 64;
        private const ulong MaxSizeCompare = 0x1000;
        private const int MaxTypeFieldOffset = 0x80;

        private const string OpenRead = "?OpenExternalSharedReadResource@CApplicationChannel@" + NtNamespace + "@@";
        private const string OpenWrite = "?OpenExternalSharedWriteResource@CApplicationChannel@" + NtNamespace + "@@";
        private const string OpenInternalRead = "?OpenInternalSharedReadResource@CApplicationChannel@" + NtNamespace + "@@";
        private const string OpenInternalWrite = "?OpenInternalSharedWriteResource@CApplicationChannel@" + NtNamespace + "@@";
        private const string TargetConstructor = "??0" + VisualTargetClass + "@" + NtNamespace + "@@";
        private const string SharedVisualFactory = "CreateSharedSystemVisualObject";
        private const string SharedResourceFactory = "CreateSharedResourceObject";

        // These stay in the order of the generated CompositionProperty enum.
        private const string PropertyChangeMask = "PropertyChangeMask";
        private const string VisualTransform = "VisualTransform";
        private const string SpriteVisualBrush = "SpriteVisualBrush";
        private const string VisualTargetRoot = "VisualTargetRoot";
        private const string SurfaceBrushSurface = "SurfaceBrushSurface";
        private const string SurfaceBitmapSurface = "SurfaceBitmapSurface";
        private static readonly string[] Properties = { PropertyChangeMask, VisualTransform, SpriteVisualBrush, VisualTargetRoot, SurfaceBrushSurface, SurfaceBitmapSurface };

        private const string CompareNone = "None";
        private const string CompareValue = "Value";
        private const string CompareNonZero = "NonZero";
        private const string CompareNever = "Never";
        private const string CompareAfterCommit = "AfterCommit";

        private sealed record CommandRule(string Name, string[] Markers, int Size, (int Offset, int Bytes)[] Fields, string Method);

        private sealed record CreateCase(uint Opcode, ulong Call, uint MaxType);

        // An opened class comes from the open of a shared resource, never from the factory. NullOnly means Brovan takes only
        // null for the class's other own references, so each of them must take null.
        private sealed record ClassRule(string Name, string NtClass, string Integer, string Buffer, string Reference, string CallbackId, string Float,
            string Handle, bool Opened = false, string[] Ruled = null, string RuleOwner = null, KeptReference[] Kept = null, bool NullOnly = false,
            string HandleName = null);

        // A kept reference takes null and exactly the types derived from the ancestor Up levels above the anchor class's type.
        // A union one takes the anchor's type and a union of subtrees, recorded by their highest roots.
        private sealed record KeptReference(string Property, string Anchor, int Up, bool Union = false);

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

            Dictionary<string, uint> Slots = ReadSlots(Inputs, SlotMethods.Concat(ChildMethods).Append(EmitUpdate));
            (string[] CommandMap, int[] Sizes, CreateCase Create) = ReadCommands(Inputs, Slots);
            uint MaxType = Create.MaxType;
            int[] Parents = ReadParents(Inputs);
            if (MaxType + 1 != Parents.Length)
                throw new FactException($"create accepts types up to 0x{MaxType:X} but the parent table ends at 0x{Parents.Length:X}");

            string[] TypeClasses = ReadTypeClasses(Inputs, MaxType);
            CheckClassSlots(Inputs, Slots);
            CheckBaseAnswers(Inputs, TypeClasses);
            uint Mask = ReadPropertyChangeMask(Inputs, TypeClasses);
            uint TypeField = ReadTypeField(Inputs, TypeClasses);
            uint TargetType = ReadVisualTarget(Inputs, TypeClasses, TypeField);
            if (TypeClasses[TargetType].Length != 0)
                throw new FactException($"the visual target's type 0x{TargetType:X} makes a {TypeClasses[TargetType]}");

            TypeClasses[TargetType] = "VisualTarget";
            List<CompositionPropertyFact> PropertyFacts = new() { new(PropertyChangeMask, Mask, Array.Empty<uint>()) };
            List<CompositionReferenceFact> ReferenceFacts = new();
            List<CompositionOwnPropertiesFact> OwnFacts = new();
            List<CompositionOwnPropertiesFact> RefusedFacts = new();
            List<(string Class, CompositionPropertyFact Property)> Kept = ReadReferenceSetters(Inputs, TypeClasses, Parents, Slots, PropertyFacts, ReferenceFacts,
                OwnFacts, RefusedFacts);
            List<CompositionHandleFact> HandleFacts = new();
            ReadHandleSetters(Inputs, TypeClasses, Slots, PropertyFacts, HandleFacts);
            List<CompositionRuleFact> RuleFacts = new();
            ReadSetterRules(Inputs, TypeClasses, Slots, Mask, Kept, OwnFacts, RuleFacts);
            CompositionPropertyFact[] Ordered = PropertyFacts.OrderBy(Fact => Array.IndexOf(Properties, Fact.Name)).ToArray();
            if (!Ordered.Select(Fact => Fact.Name).SequenceEqual(Properties))
                throw new FactException($"properties read: {string.Join(", ", Ordered.Select(Fact => Fact.Name))}");

            CompositionOwnerFact[] Owners = Classes.Where(Class => Class.RuleOwner != null).Select(Class => new CompositionOwnerFact(Class.Name, Class.RuleOwner)).ToArray();
            CompositionFacts Facts = new(CommandMap, Sizes, MaxType, Parents, TypeClasses, Ordered, ReferenceFacts.ToArray(), HandleFacts.ToArray(),
                OwnFacts.ToArray(), RefusedFacts.ToArray(), RuleFacts.ToArray(), Owners);
            return JsonSerializer.Serialize(Facts);
        }

        // The vtable offset of each setter and child method, from the vtables whose entry at that offset is a function of only that name.
        private static Dictionary<string, uint> ReadSlots(VersionInputs Inputs, IEnumerable<string> Wanted)
        {
            Dictionary<string, SortedSet<uint>> Found = Wanted.ToDictionary(Method => Method, _ => new SortedSet<uint>());
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
            uint OpenMaxType = 0;
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
                else if (Rule == OpenRule)
                    OpenMaxType = ReadTypeRangeCheck(Path, Wire);
            }

            foreach (CommandRule Rule in Commands)
            {
                if (!Names.Contains(Rule.Name))
                    throw new FactException($"{Rule.Name}: no opcode");
            }

            // Brovan's parser checks the type of an open as it checks the type of a create.
            if (OpenMaxType != Create.MaxType)
                throw new FactException($"OpenResource takes types up to 0x{OpenMaxType:X}, CreateResource up to 0x{Create.MaxType:X}");

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

            // A channel function the case calls by name makes the method call itself, so the method's slot is not on the path.
            CommandRule Named = Commands.FirstOrDefault(Command => Names(Command, Callee));
            if (Named != null || Last.FlowControl != FlowControl.Call || !IsChannelFunction(Callee, false))
                return (Named, Named != null && IsChannelFunction(Callee, false));

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
            foreach (ClassRule Class in Classes.Where(Class => !Class.Opened))
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

            foreach (ClassRule Class in Classes.Where(Class => !Class.Opened))
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

                foreach ((string Method, string Expected) in new[] { (SetInteger, Class.Integer), (SetBuffer, Class.Buffer), (SetReference, Class.Reference),
                             (SetCallbackId, Class.CallbackId), (SetFloat, Class.Float), (SetHandle, Class.Handle) })
                {
                    uint Entry = VtableEntry(Inputs, Vtable, Slots[Method]);
                    bool Matches = Expected switch
                    {
                        Any => true,
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
            Expect("base " + SetHandle, Status(MemberName(BaseClass, SetHandle), Brush, 0, FakeHandle, Updated), StatusInvalidParameter);
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

        private sealed record ReferenceRead(List<uint> Own, List<uint> Refused, List<CompositionPropertyFact> Kept, List<CompositionPropertyFact> Passed,
            bool PassesOn);

        // The run patches the base stub and every other class's reference setter to return a marker of its own. A marker
        // answer goes to that setter, invalid parameter for null and every target is refused, and any other answer is own.
        private static List<(string Class, CompositionPropertyFact Property)> ReadReferenceSetters(VersionInputs Inputs, string[] TypeClasses, int[] Parents,
            Dictionary<string, uint> Slots, List<CompositionPropertyFact> PropertyFacts, List<CompositionReferenceFact> ReferenceFacts,
            List<CompositionOwnPropertiesFact> OwnFacts, List<CompositionOwnPropertiesFact> RefusedFacts)
        {
            ClassRule[] Setting = Classes.Where(Class => Class.Reference == Class.NtClass).ToArray();
            uint[] Setters = Setting.Select(Class => VtableEntry(Inputs, Inputs.Publics.Find(VtableName(Class.NtClass)), Slots[SetReference])).ToArray();
            uint? Stub = Inputs.Publics.TryFind(MemberName(BaseClass, SetReference), "", out uint Found) ? Found : null;
            List<(string Class, CompositionPropertyFact Property)> Kept = new();
            for (int Index = 0; Index < Setting.Length; Index++)
            {
                ClassRule Class = Setting[Index];
                uint[] Scan = ScanProperties(Inputs, Setters[Index]).Union(Kept.Select(Entry => Entry.Property.Id)).Order().ToArray();
                ReferenceRead Read = null;
                string First = null;
                for (int Feature = 0; Feature < 2; Feature++)
                {
                    ReferenceRead State = ReadReferenceSetter(Inputs, TypeClasses, Parents, Setting, Setters, Index, Stub, Scan, Kept, Feature);
                    string Shape = JsonSerializer.Serialize(State);
                    if (Read == null)
                    {
                        Read = State;
                        First = Shape;
                        continue;
                    }

                    if (Shape == First)
                        continue;

                    if (!State.Kept.Select(Fact => (Fact.Name, Fact.Id)).SequenceEqual(Read.Kept.Select(Fact => (Fact.Name, Fact.Id))) ||
                        !State.Passed.Select(Fact => Fact.Name).SequenceEqual(Read.Passed.Select(Fact => Fact.Name)))
                        throw new FactException($"{Class.Name} references: the feature states keep different properties");

                    List<CompositionPropertyFact> Joined = Read.Kept.Zip(State.Kept, (Mine, Theirs) => Mine with { Bases = Mine.Bases.Union(Theirs.Bases).Order().ToArray() })
                        .ToList();
                    Read = Read with
                    {
                        Own = Read.Own.Union(State.Own).Order().ToList(), Refused = Read.Refused.Intersect(State.Refused).Except(State.Own).Order().ToList(),
                        Kept = Joined, PassesOn = Read.PassesOn || State.PassesOn,
                    };
                }

                OwnFacts.Add(new(Class.Name, "Reference", Read.Own.ToArray()));
                if (Read.PassesOn && Read.Refused.Count != 0)
                    RefusedFacts.Add(new(Class.Name, "Reference", Read.Refused.ToArray()));

                foreach (CompositionPropertyFact Property in Read.Kept)
                {
                    PropertyFacts.Add(Property);
                    Kept.Add((Class.Name, Property));
                    ReferenceFacts.Add(new(Class.Name, Property.Name));
                }

                foreach (CompositionPropertyFact Property in Read.Passed)
                {
                    Kept.Add((Class.Name, Property));
                    ReferenceFacts.Add(new(Class.Name, Property.Name));
                }
            }

            return Kept;
        }

        private static ReferenceRead ReadReferenceSetter(VersionInputs Inputs, string[] TypeClasses, int[] Parents, ClassRule[] Setting, uint[] Setters,
            int Index, uint? Stub, uint[] Scan, List<(string Class, CompositionPropertyFact Property)> Kept, int Feature)
        {
            ClassRule Class = Setting[Index];
            using Session Session = new(Inputs, Feature);
            Machine Machine = Session.Machine;
            if (Stub is uint Base)
                Machine.PatchReturn(Base, BaseMarker);

            for (int Other = 0; Other < Setting.Length; Other++)
            {
                if (Setters[Other] != Setters[Index])
                    Machine.PatchReturn(Setters[Other], ReferenceMarker + (uint)Other);
            }

            ulong Updated = Machine.Alloc(8);
            ulong Object = Class.Opened ? OpenVisualTarget(Inputs, Session, TypeClasses) : Session.Create(TypeOf(TypeClasses, Class.Name));
            List<(uint Type, ulong Object)> Targets = CreateAll(Session, TypeClasses);
            Machine.Snapshot Start = Machine.Save();
            uint? Answer(uint Property, ulong Target)
            {
                Machine.Restore(Start);
                return (uint?)Machine.TryCall(Setters[Index], Object, Session.Channel, Property, Target, Updated);
            }

            bool IsMarker(uint? Status) => Status == BaseMarker || Status - ReferenceMarker < (uint)Setting.Length;

            List<uint> Own = new();
            List<uint> Refused = new();
            List<CompositionPropertyFact> Passed = new();
            bool PassesOn = false;
            foreach (uint Property in Scan)
            {
                uint? Unmapped = Answer(Property, UnmappedTarget);
                if (IsMarker(Unmapped))
                {
                    PassesOn = true;
                    int Receiver = Unmapped == BaseMarker ? -1 : (int)(Unmapped.Value - ReferenceMarker);
                    if (Receiver > Index)
                        throw new FactException($"{Class.Name} passes reference 0x{Property:X} to {Setting[Receiver].Name}, which the rules read later");

                    foreach ((string Keeper, CompositionPropertyFact Fact) in Kept)
                    {
                        if (Receiver >= 0 && Fact.Id == Property && Keeper == Setting[Receiver].Name)
                            Passed.Add(Fact);
                    }

                    continue;
                }

                uint? Null = Answer(Property, 0);
                if (Unmapped == StatusInvalidParameter && Null == StatusInvalidParameter && Targets.All(Target => Answer(Property, Target.Object) == StatusInvalidParameter))
                {
                    Refused.Add(Property);
                    continue;
                }

                Own.Add(Property);
                if (Class.NullOnly && Null != StatusSuccess)
                    throw new FactException($"{Class.Name} reference 0x{Property:X} answers null with {FormatStatus(Null)}");
            }

            List<CompositionPropertyFact> Found = new();
            foreach (KeptReference Spec in Class.Kept ?? Array.Empty<KeptReference>())
            {
                uint Anchor = TypeOf(TypeClasses, Spec.Anchor);
                ulong AnchorObject = Targets.FirstOrDefault(Target => Target.Type == Anchor).Object;
                if (AnchorObject == 0)
                    throw new FactException($"{Spec.Anchor}: no object to set as {Spec.Property}");

                uint Required = Anchor;
                for (int Level = 0; Level < Spec.Up; Level++)
                    Required = Required < Parents.Length ? (uint)Parents[Required] : throw new FactException($"{Spec.Anchor} has no ancestor {Spec.Up} levels up");

                List<CompositionPropertyFact> Matches = new();
                foreach (uint Property in Own)
                {
                    if (Answer(Property, 0) != StatusSuccess || Answer(Property, AnchorObject) != StatusSuccess)
                        continue;

                    HashSet<uint> Accepted = Targets.Where(Target => Answer(Property, Target.Object) == StatusSuccess).Select(Target => Target.Type).ToHashSet();
                    uint[] Roots = Spec.Union ? ReadRoots(Parents, Targets, Accepted) : new[] { Required };
                    if (Targets.All(Target => Roots.Any(Root => IsDerivedFrom(Parents, Target.Type, Root)) == Accepted.Contains(Target.Type)))
                        Matches.Add(new(Spec.Property, Property, Roots));
                }

                if (Matches.Count != 1)
                    throw new FactException($"{Class.Name} {Spec.Property}: {Matches.Count} properties take null and exactly the types derived from 0x{Required:X} " +
                                            $"({string.Join(", ", Matches.Select(Match => $"0x{Match.Id:X}"))})");

                Found.Add(Matches[0]);
            }

            return new ReferenceRead(Own, Refused, Found, Passed, PassesOn);
        }

        private static uint[] ReadRoots(int[] Parents, List<(uint Type, ulong Object)> Targets, HashSet<uint> Accepted)
        {
            SortedSet<uint> Roots = new();
            foreach (uint Type in Accepted)
            {
                uint Root = Type;
                while (Root < Parents.Length && (uint)Parents[Root] < Parents.Length)
                {
                    uint Parent = (uint)Parents[Root];
                    if (!Targets.Where(Target => IsDerivedFrom(Parents, Target.Type, Parent)).All(Target => Accepted.Contains(Target.Type)))
                        break;

                    Root = Parent;
                }

                Roots.Add(Root);
            }

            return Roots.ToArray();
        }

        // The run patches dxgkrnl's reference call to record the access and object kind it asks for and answer a marker.
        private static void ReadHandleSetters(VersionInputs Inputs, string[] TypeClasses, Dictionary<string, uint> Slots,
            List<CompositionPropertyFact> PropertyFacts, List<CompositionHandleFact> HandleFacts)
        {
            foreach (ClassRule Class in Classes.Where(Class => Class.HandleName != null))
            {
                uint Function = VtableEntry(Inputs, Inputs.Publics.Find(VtableName(Class.NtClass)), Slots[SetHandle]);
                uint[] Scan = ScanProperties(Inputs, Function).ToArray();
                CompositionHandleFact Found = null;
                for (int Feature = 0; Feature < 2; Feature++)
                {
                    using Session Session = new(Inputs, Feature);
                    Machine Machine = Session.Machine;
                    ulong Cells = Machine.Alloc(16);
                    Machine.PatchImport(ReferenceObject, Asm =>
                    {
                        Asm.mov(rax, Cells);
                        Asm.mov(__qword_ptr[rax], rdx);
                        Asm.mov(__qword_ptr[rax + 8], r8);
                        Asm.mov(eax, HandleMarker);
                        Asm.ret();
                    });

                    ulong Updated = Machine.Alloc(8);
                    ulong Object = Session.Create(TypeOf(TypeClasses, Class.Name));
                    Machine.Snapshot Start = Machine.Save();
                    List<CompositionHandleFact> Taken = new();
                    foreach (uint Property in Scan)
                    {
                        Machine.Restore(Start);
                        if (Machine.TryCall(Function, Object, Property, FakeHandle, Updated) is ulong Status && (uint)Status == HandleMarker)
                            Taken.Add(new(Class.Name, Class.HandleName, Property, (uint)Machine.ReadUInt64(Cells), (uint)Machine.ReadUInt64(Cells + 8)));
                    }

                    if (Taken.Count != 1)
                        throw new FactException($"{Class.Name} handles: {Taken.Count} properties reach the reference call");

                    if (Found != null && Found != Taken[0])
                        throw new FactException($"{Class.Name} handles: the feature states differ");

                    Found = Taken[0];
                }

                PropertyFacts.Add(new(Class.HandleName, Found.Id, Array.Empty<uint>()));
                HandleFacts.Add(Found);
            }
        }

        private enum Outcome
        {
            Accepted,
            NonZero,
            Refused,
            Other,
        }

        private static Outcome Classify(IEnumerable<uint?> Answers)
        {
            uint?[] All = Answers.ToArray();
            if (All.All(Status => Status == StatusSuccess))
                return Outcome.Accepted;

            if (All.All(Status => Status == StatusInvalidParameter))
                return Outcome.Refused;

            int Zero = Array.IndexOf(BufferFills, (byte)0);
            return All.Length == BufferFills.Length && All[Zero] == StatusInvalidParameter &&
                   All.Where((_, Index) => Index != Zero).All(Status => Status == StatusSuccess) ? Outcome.NonZero : Outcome.Other;
        }

        private static readonly float[] FloatProbes = { 0f, 1f, -1f, float.NaN };
        private static readonly byte[] BufferFills = { 1, 0, 2 };

        private static readonly (string Method, string Setter)[] RuledSetters = { (SetInteger, "Integer"), (SetFloat, "Float"), (SetBuffer, "Buffer") };

        // A property is the class's own when its setter answers it without the base, and it gets a rule only when the answer
        // does not depend on the data or the other properties. Brovan does not serve an own property without a rule.
        private static void ReadSetterRules(VersionInputs Inputs, string[] TypeClasses, Dictionary<string, uint> Slots, uint Mask,
            List<(string Class, CompositionPropertyFact Property)> Kept, List<CompositionOwnPropertiesFact> Own, List<CompositionRuleFact> Rules)
        {
            BatchLayout Layout = ReadBatchLayout(Inputs);
            foreach (ClassRule Class in Classes)
            {
                if (Class.RuleOwner != null)
                    CheckRuleOwner(Inputs, Slots, Class);

                foreach ((string Method, string Setter) in RuledSetters)
                {
                    if (Class.Ruled?.Contains(Method) == true)
                        ReadSetter(Inputs, TypeClasses, Slots, Mask, Layout, Class, Method, Setter, Kept, Own, Rules);
                }
            }
        }

        private static void CheckRuleOwner(VersionInputs Inputs, Dictionary<string, uint> Slots, ClassRule Class)
        {
            ClassRule Owner = Classes.First(Other => Other.Name == Class.RuleOwner);
            uint Mine = Inputs.Publics.Find(VtableName(Class.NtClass));
            uint Theirs = Inputs.Publics.Find(VtableName(Owner.NtClass));
            foreach (string Method in Owner.Ruled)
            {
                if (VtableEntry(Inputs, Mine, Slots[Method]) != VtableEntry(Inputs, Theirs, Slots[Method]))
                    throw new FactException($"{Class.NtClass}::{Method} is not the {Owner.Name}'s");
            }
        }

        // Gate is a kept reference of the class, set to an object of the given type before the setter is read.
        private sealed record SetterState(CompositionPropertyFact Gate, uint Type, ulong Target);

        private static void ReadSetter(VersionInputs Inputs, string[] TypeClasses, Dictionary<string, uint> Slots, uint Mask, BatchLayout Layout,
            ClassRule Class, string Method, string Setter, List<(string Class, CompositionPropertyFact Property)> Kept, List<CompositionOwnPropertiesFact> OwnFacts,
            List<CompositionRuleFact> RuleFacts)
        {
            // A base stub, or the per-type table that answers floats in some builds, gets no rules.
            uint Vtable = Inputs.Publics.Find(VtableName(Class.NtClass));
            uint Function = VtableEntry(Inputs, Vtable, Slots[Method]);
            if (!Inputs.Publics.NamesAt(Function).Any(Name => Name.StartsWith(MemberName(Class.NtClass, Method), StringComparison.Ordinal)))
                return;

            // Build 28000 has no base float setter.
            List<uint> Stubs = new();
            foreach (string Name in new[] { SetInteger, SetBuffer, SetFloat })
            {
                if (Inputs.Publics.TryFind(MemberName(BaseClass, Name), Name == SetFloat ? FloatSignature : "", out uint Stub))
                    Stubs.Add(Stub);
            }

            bool Changes = Inputs.Publics.TryFind(MemberName(PropertyChangeClass, SetInteger), "", out uint ChangeSetter);
            uint ReferenceSetter = VtableEntry(Inputs, Vtable, Slots[SetReference]);
            uint Emit = VtableEntry(Inputs, Vtable, Slots[EmitUpdate]);
            CompositionPropertyFact[] Gates = Kept.Where(Entry => Entry.Class == Class.Name).Select(Entry => Entry.Property).ToArray();
            uint[] Properties = ScanProperties(Inputs, Function).ToArray();
            int[] Sizes = Method == SetBuffer ? ScanSizes(Inputs, Function) : null;
            ulong[] Candidates = Method == SetInteger ? ScanValues(Inputs, Function) : null;
            string[] Shapes = new string[2];
            (List<uint> Own, List<CompositionRuleFact> Rules) Found = default;
            for (int Feature = 0; Feature < 2; Feature++)
            {
                using Session Session = new(Inputs, Feature);
                Machine Machine = Session.Machine;
                foreach (uint Stub in Stubs)
                    Machine.PatchReturn(Stub, BaseMarker);

                if (Changes)
                    Machine.PatchReturn(ChangeSetter, ChangeMarker);

                ulong Updated = Machine.Alloc(8);
                ulong Data = Machine.Alloc(MaxBufferBytes + 1);
                ulong BatchCell = MakeBatch(Machine, Layout);
                ulong Object = Session.Create(TypeOf(TypeClasses, Class.Name));
                List<SetterState> GateStates = new();
                foreach (CompositionPropertyFact Gate in Gates)
                {
                    foreach (uint Base in Gate.Bases)
                    {
                        ulong Target = Session.TryCreate(Base);
                        if (Target != 0)
                            GateStates.Add(new SetterState(Gate, Base, Target));
                    }
                }

                Machine.Snapshot Clean = Machine.Save();
                bool Forwards = false;
                (List<uint> Own, Dictionary<uint, CompositionRuleFact> Rules) Default = ReadState(null);
                List<uint> Own = Default.Own;
                Dictionary<uint, CompositionRuleFact> Rules = Default.Rules;
                Dictionary<uint, (CompositionRuleFact Rule, List<uint> Bases)> Gated = new();
                foreach (SetterState State in GateStates)
                {
                    (List<uint> GateOwn, Dictionary<uint, CompositionRuleFact> GateRules) = ReadState(State);
                    foreach ((uint Property, CompositionRuleFact Rule) in GateRules)
                    {
                        if (Default.Own.Contains(Property))
                        {
                            if (Rules.TryGetValue(Property, out CompositionRuleFact Plain) && Plain.Compare == CompareNever && Rule.Compare == CompareAfterCommit)
                                Rules[Property] = Plain with { Compare = CompareAfterCommit };

                            continue;
                        }

                        if (!Gated.TryGetValue(Property, out (CompositionRuleFact Rule, List<uint> Bases) Entry))
                            Gated[Property] = (Rule with { Requires = State.Gate.Name }, new List<uint> { State.Type });
                        else if (JsonSerializer.Serialize(Entry.Rule with { Requires = null }) == JsonSerializer.Serialize(Rule))
                            Entry.Bases.Add(State.Type);
                        else
                            throw new FactException($"{Class.Name} {Setter} 0x{Property:X}: rules differ between the types of {State.Gate.Name}");
                    }

                    Own = Own.Union(GateOwn).Order().ToList();
                }

                foreach ((uint Property, (CompositionRuleFact Rule, List<uint> Bases)) in Gated)
                    Rules[Property] = Rule with { RequiredBases = Bases.Order().ToArray() };

                List<CompositionRuleFact> Ordered = Rules.Values.OrderBy(Rule => Rule.Property).ToList();

                // Brovan answers the property-change mask in the property-change base.
                if (Forwards && Own.Contains(Mask))
                    throw new FactException($"{Class.NtClass} handles the property-change mask 0x{Mask:X} itself");

                Shapes[Feature] = JsonSerializer.Serialize(new { Own, Ordered });
                if (Feature == 0)
                {
                    Found = (Own, Ordered);
                }
                else if (Shapes[0] != Shapes[1])
                {
                    HashSet<string> Agreed = Ordered.Select(Rule => JsonSerializer.Serialize(Rule)).ToHashSet();
                    Found = (Found.Own.Union(Own).Order().ToList(), Found.Rules.Where(Rule => Agreed.Contains(JsonSerializer.Serialize(Rule))).ToList());
                }

                (List<uint> Own, Dictionary<uint, CompositionRuleFact> Rules) ReadState(SetterState State)
                {
                    Machine.Restore(Clean);
                    if (State != null && Machine.TryCall(ReferenceSetter, Object, Session.Channel, State.Gate.Id, State.Target, Updated) != StatusSuccess)
                        return (new List<uint>(), new Dictionary<uint, CompositionRuleFact>());

                    Machine.Snapshot Start = Machine.Save();
                    bool Dirty = false;

                    // A refused call changes nothing, so the next call may start from the state it left.
                    uint? Call(uint Property, ulong Value, int Bytes, bool Fresh = true)
                    {
                        if (Fresh && Dirty)
                            Machine.Restore(Start);

                        Machine.Write(Updated, new byte[1]);
                        uint? Status;
                        if (Method == SetInteger)
                        {
                            Status = (uint?)Machine.TryCall(Function, Object, Session.Channel, Property, Value, Updated);
                        }
                        else if (Method == SetFloat)
                        {
                            Machine.WriteFloatArgument(2, BitConverter.Int32BitsToSingle((int)Value));
                            Status = (uint?)Machine.TryCall(Function, Object, Property, 0, Updated);
                        }
                        else
                        {
                            Machine.Write(Data, Enumerable.Repeat((byte)Value, Bytes).ToArray());
                            Status = (uint?)Machine.TryCall(Function, Object, Session.Channel, Property, Data, (ulong)Bytes, Updated);
                        }

                        Dirty = Status != StatusInvalidParameter;
                        return Status;
                    }

                    bool Held() => Machine.Read(Updated, 1)[0] == 0;

                    // A second value that leaves the updated flag clear finds the first one held.
                    bool Compares(uint Property, ulong First, ulong Second, int Bytes)
                    {
                        Call(Property, First, Bytes);
                        Call(Property, Second, Bytes, Fresh: false);
                        return Held();
                    }

                    // A value that leaves the updated flag clear on a new object is what the object starts with.
                    bool Starts(uint Property, ulong Value, int Bytes)
                    {
                        Call(Property, Value, Bytes);
                        return Held();
                    }

                    List<uint> StateOwn = new();
                    Dictionary<uint, CompositionRuleFact> StateRules = new();
                    foreach (uint Property in Properties)
                    {
                        CompositionRuleFact Rule = null;
                        if (Method == SetBuffer)
                        {
                            uint?[][] Answers = Sizes.Select(Bytes => BufferFills.Select(Fill => Call(Property, Fill, Bytes)).ToArray()).ToArray();
                            if (Answers.SelectMany(Size => Size).All(Status => Status is StatusInvalidParameter or BaseMarker))
                                continue;

                            StateOwn.Add(Property);
                            Outcome[] Outcomes = Answers.Select(Size => Classify(Size)).ToArray();
                            int Taken = Outcomes.Count(Size => Size is Outcome.Accepted or Outcome.NonZero);
                            if (Taken != 1 || Outcomes.Contains(Outcome.Other))
                                continue;

                            int Index = Array.FindIndex(Outcomes, Size => Size is Outcome.Accepted or Outcome.NonZero);
                            int Bytes = Sizes[Index];
                            bool NonZero = Outcomes[Index] == Outcome.NonZero;
                            bool Same = Compares(Property, 1, 1, Bytes);
                            if (Same && Starts(Property, 2, Bytes) && Starts(Property, 1, Bytes))
                                Rule = new(Class.Name, Setter, Property, Bytes, null, CompareNever) { NonZero = NonZero };
                            else
                                Rule = new(Class.Name, Setter, Property, Bytes, null, Same ? CompareValue : CompareNone,
                                    Same && !NonZero && Starts(Property, 0, Bytes) ? 0 : null) { NonZero = NonZero };
                        }
                        else if (Method == SetFloat)
                        {
                            uint?[] Answers = FloatProbes.Select(Value => Call(Property, (uint)BitConverter.SingleToInt32Bits(Value), 0)).ToArray();
                            if (Answers.All(Status => Status is StatusInvalidParameter or BaseMarker))
                                continue;

                            StateOwn.Add(Property);
                            if (Classify(Answers) != Outcome.Accepted)
                                continue;

                            ulong One = (uint)BitConverter.SingleToInt32Bits(1f);
                            bool Same = Compares(Property, One, One, 0);
                            ulong[] Starting = Same
                                ? FloatProbes.Select(Value => (ulong)(uint)BitConverter.SingleToInt32Bits(Value)).Where(Bits => Starts(Property, Bits, 0)).ToArray()
                                : Array.Empty<ulong>();
                            Rule = Starting.Length == FloatProbes.Length
                                ? new(Class.Name, Setter, Property, 0, null, CompareNever)
                                : new(Class.Name, Setter, Property, 0, null, Same ? CompareValue : CompareNone, Starting.Length == 1 ? Starting[0] : null);
                        }
                        else
                        {
                            uint?[] Answers = Candidates.Select(Value => Call(Property, Value, 0)).ToArray();
                            Forwards |= Answers.Contains(ChangeMarker);
                            if (Answers.All(Status => Status is StatusInvalidParameter or BaseMarker or ChangeMarker))
                                continue;

                            StateOwn.Add(Property);
                            if (Answers.Any(Status => Status is not (StatusSuccess or StatusInvalidParameter)))
                                continue;

                            ulong[] Accepted = Candidates.Where((_, Index) => Answers[Index] == StatusSuccess).ToArray();
                            string Compare = CompareNone;
                            ulong? Initial = null;
                            ulong First = Accepted.Contains(1UL) ? 1 : Accepted[0];
                            ulong[] NonZero = Accepted.Where(Value => Value != 0).Take(2).ToArray();
                            if (Compares(Property, First, First, 0))
                                Compare = NonZero.Length == 2 && Compares(Property, NonZero[0], NonZero[1], 0) ? CompareNonZero : CompareValue;

                            // A setter that compares the low 32 bits holds every value with the same low half.
                            ulong[] Starting = Compare == CompareNone ? Array.Empty<ulong>() : Accepted.Where(Value => Starts(Property, Value, 0)).ToArray();
                            if (Compare != CompareNone && Starting.Length == Accepted.Length && Accepted.Length > 1)
                                Compare = CompareNever;
                            else if (Compare == CompareNonZero && Starting.Length != 0)
                                Initial = Convert.ToUInt64(Starting[0] != 0);
                            else if (Starting.Length != 0 && Starting.All(Value => (uint)Value == (uint)Starting[0]))
                                Initial = Starting[0];

                            Rule = new(Class.Name, Setter, Property, 0, Accepted.Length == Candidates.Length ? null : Accepted, Compare,
                                Compare == CompareNever ? null : Initial);
                        }

                        StateRules[Property] = Rule;
                    }

                    // A property whose sets mark nothing may count after a commit with every other property of its setter set.
                    foreach (CompositionRuleFact Rule in StateRules.Values.Where(Rule => Rule?.Compare == CompareNever).ToList())
                    {
                        Machine.Restore(Start);
                        foreach (CompositionRuleFact Other in StateRules.Values.Where(Other => Other != null))
                            Call(Other.Property, SampleValue(Other), Other.Bytes, Fresh: false);

                        ulong Pool = Machine.ReadUInt64(Machine.ReadUInt64(BatchCell) + (ulong)Layout.Pool);
                        if (Machine.TryCall(Emit, Object, BatchCell) == null || Machine.ReadUInt64(Pool + (ulong)Layout.Used) == 0)
                            throw new FactException($"{Class.NtClass}::{EmitUpdate} did not write into the made-up batch");

                        if (Call(Rule.Property, SecondValue(Rule), Rule.Bytes, Fresh: false) == StatusSuccess && !Held())
                            StateRules[Rule.Property] = Rule with { Compare = CompareAfterCommit };
                    }

                    foreach (uint Property in StateRules.Where(Entry => Entry.Value == null).Select(Entry => Entry.Key).ToList())
                        StateRules.Remove(Property);

                    return (StateOwn, StateRules);
                }
            }

            OwnFacts.Add(new(Class.Name, Setter, Found.Own.ToArray()));
            RuleFacts.AddRange(Found.Rules);
        }

        private static ulong SampleValue(CompositionRuleFact Rule) => Rule.Setter switch
        {
            "Float" => (uint)BitConverter.SingleToInt32Bits(1f),
            "Integer" => Rule.Values?.FirstOrDefault(Value => Value != 0) ?? 1,
            _ => 1,
        };

        private static ulong SecondValue(CompositionRuleFact Rule) => Rule.Setter switch
        {
            "Float" => (uint)BitConverter.SingleToInt32Bits(-1f),
            "Integer" => Rule.Values?.Where(Value => Value != 0).Skip(1).FirstOrDefault() ?? 2,
            _ => 2,
        };

        private sealed record BatchLayout(int Pool, int Used, int Page);

        // NT: CBatch::EnsureBatchBuffer takes room from the batch's pool page, so EmitUpdateCommands writes without the channel.
        private static ulong MakeBatch(Machine Machine, BatchLayout Layout)
        {
            ulong Batch = Machine.Alloc(Layout.Pool + 8);
            ulong Pool = Machine.Alloc(Math.Max(Layout.Used, Layout.Page) + 8);
            ulong Page = Machine.Alloc(PageBytes);
            Machine.WriteUInt64(Batch + (ulong)Layout.Pool, Pool);
            Machine.WriteUInt64(Pool + (ulong)Layout.Used, 0);
            Machine.WriteUInt64(Pool + (ulong)Layout.Page, Page);
            ulong Cell = Machine.Alloc(8);
            Machine.WriteUInt64(Cell, Batch);
            return Cell;
        }

        // The room check at the start of CBatch::EnsureBatchBuffer reads the batch from rcx, then its pool, bytes used and page.
        private static BatchLayout ReadBatchLayout(VersionInputs Inputs)
        {
            Function Ensure = Function.Decode(Inputs.Image, Inputs.Publics, Inputs.Publics.Find(EnsureBatchBuffer));
            HashSet<Register> Cells = new() { Register.RCX };
            HashSet<Register> Batches = new();
            HashSet<Register> Pools = new();
            int? Pool = null;
            HashSet<int> Loads = new();
            HashSet<int> Stores = new();
            foreach (Instruction Instruction in Ensure.Instructions)
            {
                if (Instruction.FlowControl == FlowControl.Call)
                    break;

                if (Instruction.Mnemonic == Mnemonic.Mov && Instruction.Op0Kind == OpKind.Memory && Pools.Contains(Instruction.MemoryBase))
                    Stores.Add((int)Instruction.MemoryDisplacement64);

                if (Instruction.Mnemonic == Mnemonic.Mov && Instruction.Op0Kind == OpKind.Register && Instruction.Op1Kind == OpKind.Register &&
                    Cells.Contains(Instruction.Op1Register))
                    Cells.Add(Instruction.Op0Register);
                else if (IsPlainLoad(Instruction) && Cells.Contains(Instruction.MemoryBase) && Instruction.MemoryDisplacement64 == 0)
                    Batches.Add(Instruction.Op0Register);
                else if (IsPlainLoad(Instruction) && Batches.Contains(Instruction.MemoryBase) && Pool == null)
                {
                    Pool = (int)Instruction.MemoryDisplacement64;
                    Pools.Add(Instruction.Op0Register);
                }
                else if (IsPlainLoad(Instruction) && Pools.Contains(Instruction.MemoryBase))
                    Loads.Add((int)Instruction.MemoryDisplacement64);
            }

            int[] Used = Stores.Where(Loads.Contains).ToArray();
            int[] Page = Loads.Except(Stores).ToArray();
            if (Pool == null || Used.Length != 1 || Page.Length != 1)
                throw new FactException($"{EnsureBatchBuffer}: no room check");

            return new(Pool.Value, Used[0], Page[0]);
        }

        private static List<(uint Type, ulong Object)> CreateAll(Session Session, string[] TypeClasses)
        {
            List<(uint Type, ulong Object)> Made = new();
            for (uint Type = 1; Type < TypeClasses.Length; Type++)
            {
                ulong Object = Session.TryCreate(Type);
                if (Object != 0)
                    Made.Add((Type, Object));
            }

            return Made;
        }

        // NT keeps a marshaler's type in one dword field, and the factory gives a few types the object of another type.
        private static uint ReadTypeField(VersionInputs Inputs, string[] TypeClasses)
        {
            using Session Session = new(Inputs, 0);
            List<(uint Type, ulong Object)> Made = CreateAll(Session, TypeClasses).Where(Entry => TypeClasses[Entry.Type].Length != 0).ToList();
            List<uint> Offsets = Enumerable.Range(1, MaxTypeFieldOffset / 4 - 1).Select(Index => (uint)Index * 4)
                .Where(Offset => Made.All(Entry => Session.Machine.ReadUInt32(Entry.Object + Offset) == Entry.Type)).ToList();
            return Offsets.Count == 1 ? Offsets[0] : throw new FactException($"marshaler type field: {Offsets.Count} offsets hold the type of every modeled object");
        }

        // NT: the open of a shared system visual as a Visual makes a visual target (OpenInternalSharedReadResource).
        // Some builds inline the open and construct the target with a function of their own, which runs instead.
        private static ulong OpenVisualTarget(VersionInputs Inputs, Session Session, string[] TypeClasses)
        {
            Machine Machine = Session.Machine;
            ulong Vtable = Inputs.Image.ImageBase + Inputs.Publics.Find(VtableName(VisualTargetClass));
            ulong Target;
            if (Inputs.Publics.TryFind(OpenInternalRead, "", out uint Opener))
            {
                ulong Out = Machine.Alloc(8);
                ulong Opened(uint Type)
                {
                    Machine.WriteUInt64(Out, 0);
                    ulong? Status = Machine.TryCall(Opener, Session.Channel, Type, Machine.Alloc(ObjectBytes), Out);
                    return Status is ulong Answer && (uint)Answer == StatusSuccess ? Machine.ReadUInt64(Out) : 0;
                }

                Target = Opened(TypeOf(TypeClasses, "Visual"));
                ulong Other = Opened(TypeOf(TypeClasses, "ColorBrush"));
                if (Other == 0 || Machine.ReadUInt64(Other) == Vtable)
                    throw new FactException("an open of a shared color brush does not make a shared marshaler");
            }
            else
            {
                Target = Machine.Alloc(ObjectBytes);
                if (Machine.TryCall(Inputs.Publics.Find(TargetConstructor), Target, Machine.Alloc(ObjectBytes)) == null)
                    Target = 0;
            }

            if (Target == 0 || Machine.ReadUInt64(Target) != Vtable)
                throw new FactException("an open of a shared visual does not make a visual target");

            return Target;
        }

        private static uint ReadVisualTarget(VersionInputs Inputs, string[] TypeClasses, uint TypeField)
        {
            CheckSharedVisualType(Inputs, TypeOf(TypeClasses, "Visual"));
            using Session Session = new(Inputs, 0);
            return Session.Machine.ReadUInt32(OpenVisualTarget(Inputs, Session, TypeClasses) + TypeField);
        }

        // The target syscall makes its shared system visual with the Visual's type, which Brovan's target object takes.
        private static void CheckSharedVisualType(VersionInputs Inputs, uint VisualType)
        {
            Function Factory = Readers.Function.Decode(Inputs.Image, Inputs.Publics, Inputs.Publics.Find(SharedVisualFactory));
            uint Callee = Inputs.Publics.Find(SharedResourceFactory);
            ulong? Type = null;
            foreach (Instruction Instruction in Factory.Instructions.OrderBy(Instruction => Instruction.IP))
            {
                if (Instruction.FlowControl is FlowControl.Call or FlowControl.UnconditionalBranch && Instruction.Op0Kind == OpKind.NearBranch64 &&
                    Instruction.NearBranchTarget == Inputs.Image.ImageBase + Callee)
                    break;

                if (Instruction.Mnemonic == Mnemonic.Mov && Instruction.Op0Kind == OpKind.Register && Instruction.Op0Register.GetFullRegister() == Register.RCX)
                    Type = Instruction.Op1Kind.IsImmediate() ? Instruction.GetImmediate(1) : null;
            }

            if (Type != VisualType)
                throw new FactException($"the shared system visual has type {(Type is ulong Known ? $"0x{Known:X}" : "unknown")}, the Visual is 0x{VisualType:X}");
        }

        // The constants Function compares or adds, their negations and neighbors, and the edges of the 32 and 64 bit ranges.
        private static ulong[] ScanValues(VersionInputs Inputs, uint Rva)
        {
            Function Function = Readers.Function.Decode(Inputs.Image, Inputs.Publics, Rva);
            SortedSet<ulong> Values = new() { 0, 1, 2, 3, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x100000000, ulong.MaxValue - 1, ulong.MaxValue };
            foreach (Instruction Instruction in Function.Instructions)
            {
                long Constant;
                if (Instruction.Mnemonic is Mnemonic.Cmp or Mnemonic.Sub or Mnemonic.Add && Instruction.Op1Kind.IsImmediate())
                    Constant = (long)Instruction.GetImmediate(1);
                else if (Instruction.Mnemonic == Mnemonic.Lea && !Instruction.IsIPRelativeMemoryOperand)
                    Constant = (long)Instruction.MemoryDisplacement64;
                else
                    continue;

                if (Math.Abs(Constant) >= MaxScanProperty)
                    continue;

                foreach (long Value in new[] { Constant - 1, Constant, Constant + 1, -Constant - 1, -Constant, -Constant + 1 })
                    Values.Add((ulong)Value);
            }

            return Values.ToArray();
        }

        private static int[] ScanSizes(VersionInputs Inputs, uint Rva)
        {
            Function Function = Readers.Function.Decode(Inputs.Image, Inputs.Publics, Rva);
            SortedSet<int> Sizes = new(Enumerable.Range(0, MaxBufferBytes + 1));
            foreach (Instruction Instruction in Function.Instructions)
            {
                if (Instruction.Mnemonic != Mnemonic.Cmp || !Instruction.Op1Kind.IsImmediate() || Instruction.GetImmediate(1) >= MaxSizeCompare)
                    continue;

                int Value = (int)Instruction.GetImmediate(1);
                Sizes.UnionWith(new[] { Math.Max(Value - 1, 0), Value, Value + 1 });
            }

            return Sizes.ToArray();
        }

        private static string FormatStatus(uint? Status) => Status is uint Known ? $"0x{Known:X8}" : "nothing";

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
        private static IEnumerable<uint> ScanProperties(VersionInputs Inputs, string Name) => ScanProperties(Inputs, Inputs.Publics.Find(Name));

        private static IEnumerable<uint> ScanProperties(VersionInputs Inputs, uint Rva)
        {
            Function Function = Readers.Function.Decode(Inputs.Image, Inputs.Publics, Rva);
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

        private static uint VtableEntry(VersionInputs Inputs, uint Vtable, uint Slot) => (uint)(Inputs.Image.ReadUInt64(Vtable + Slot) - Inputs.Image.ImageBase);

        private static bool IsCompare(in Instruction Instruction, ulong Value)
            => Instruction.Mnemonic == Mnemonic.Cmp && Instruction.Op0Kind == OpKind.Register && Instruction.Op0Register.IsGPR32() &&
               Instruction.Op1Kind.IsImmediate() && Instruction.GetImmediate(1) == Value;

        private sealed class Session : IDisposable
        {
            private readonly uint FactoryRva;
            private readonly uint InitializeSlot;
            private readonly ulong ImageBase;
            private readonly ulong Out;

            internal Machine Machine { get; }
            internal ulong Channel { get; }

            internal Session(VersionInputs Inputs, int Feature)
            {
                FactoryRva = Inputs.Publics.Find(Factory);
                InitializeSlot = ReadSlots(Inputs, new[] { Initialize })[Initialize];
                ImageBase = Inputs.Image.ImageBase;
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
                if (Status is not ulong Answer || (uint)Answer != StatusSuccess)
                    return 0;

                ulong Object = Machine.ReadUInt64(Out);
                // NT's create calls the marshaler's Initialize after the factory, which sets what some properties start with.
                ulong Initializer = Machine.ReadUInt64(Machine.ReadUInt64(Object) + InitializeSlot);
                ulong? Initialized = Initializer > ImageBase ? Machine.TryCall((uint)(Initializer - ImageBase), Object) : null;
                return Initialized is ulong Result && (int)(uint)Result >= 0 ? Object : 0;
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
            Code.Line("        private readonly uint[][] PropertyBases;");
            Code.Line("        private readonly (CompositionClass Class, CompositionSlots Setter, uint[] Properties)[] OwnProperties;");
            Code.Line("        private readonly (CompositionClass Class, CompositionSlots Setter, uint[] Properties)[] RefusedProperties;");
            Code.Line("        private readonly System.Collections.Generic.Dictionary<(CompositionClass, CompositionSlots, uint), CompositionRule> Rules = new();");
            Code.Line("        private readonly (CompositionClass Class, CompositionClass Owner)[] RuleOwners;");
            Code.Line("        private readonly (CompositionClass Class, uint Id, CompositionProperty Property)[] References;");
            Code.Line("        private readonly (CompositionClass Class, uint Id, CompositionProperty Property, uint Access, uint Kind)[] Handles;");
            Code.Line();
            Code.Line("        // NT: an opcode the kernel refuses has record size 0 and command None. Parents has one entry per type, and its");
            Code.Line("        // length is where the walk ends.");
            Code.Line("        private CompositionTableSet(byte[] RecordSizes, (int Opcode, CompositionCommand Command)[] Commands, byte[] Parents,");
            Code.Line("            (int Type, CompositionClass Class)[] Classes, (CompositionProperty Property, uint Id, uint[] Bases)[] Properties,");
            Code.Line("            (CompositionClass Class, uint Id, CompositionProperty Property)[] References,");
            Code.Line("            (CompositionClass Class, uint Id, CompositionProperty Property, uint Access, uint Kind)[] Handles,");
            Code.Line("            (CompositionClass Class, CompositionSlots Setter, uint[] Properties)[] OwnProperties,");
            Code.Line("            (CompositionClass Class, CompositionSlots Setter, uint[] Properties)[] RefusedProperties, CompositionRule[] Rules,");
            Code.Line("            (CompositionClass Class, CompositionClass Owner)[] RuleOwners)");
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
            Code.Line("            PropertyBases = new uint[Properties.Length][];");
            Code.Line("            foreach ((CompositionProperty Property, uint Id, uint[] Bases) in Properties)");
            Code.Line("            {");
            Code.Line("                PropertyIds[(int)Property] = Id;");
            Code.Line("                PropertyBases[(int)Property] = Bases;");
            Code.Line("            }");
            Code.Line();
            Code.Line("            this.OwnProperties = OwnProperties;");
            Code.Line("            this.RefusedProperties = RefusedProperties;");
            Code.Line("            this.RuleOwners = RuleOwners;");
            Code.Line("            this.References = References;");
            Code.Line("            this.Handles = Handles;");
            Code.Line("            foreach (CompositionRule Rule in Rules)");
            Code.Line("                this.Rules.Add((Rule.Class, Rule.Setter, Rule.Property), Rule);");
            Code.Line("        }");
            Code.Line();
            Code.Line("        internal uint Property(CompositionProperty Property) => PropertyIds[(int)Property];");
            Code.Line();
            Code.Line("        internal uint[] RequiredBases(CompositionProperty Property) => PropertyBases[(int)Property];");
            Code.Line();
            Code.Line("        internal bool TryGetHandle(CompositionClass Class, uint Id, out CompositionProperty Property, out uint Access, out uint Kind)");
            Code.Line("        {");
            Code.Line("            foreach ((CompositionClass Named, uint NamedId, CompositionProperty Name, uint NamedAccess, uint NamedKind) in Handles)");
            Code.Line("            {");
            Code.Line("                if (Named == Class && NamedId == Id)");
            Code.Line("                {");
            Code.Line("                    Property = Name;");
            Code.Line("                    Access = NamedAccess;");
            Code.Line("                    Kind = NamedKind;");
            Code.Line("                    return true;");
            Code.Line("                }");
            Code.Line("            }");
            Code.Line();
            Code.Line("            Property = default;");
            Code.Line("            Access = 0;");
            Code.Line("            Kind = 0;");
            Code.Line("            return false;");
            Code.Line("        }");
            Code.Line();
            Code.Line("        internal bool IsOwnProperty(CompositionClass Class, CompositionSlots Setter, uint Property) => Lists(OwnProperties, Class, Setter, Property);");
            Code.Line();
            Code.Line("        internal bool IsRefused(CompositionClass Class, CompositionSlots Setter, uint Property) => Lists(RefusedProperties, Class, Setter, Property);");
            Code.Line();
            Code.Line("        internal bool HasOwnProperties(CompositionClass Class, CompositionSlots Setter)");
            Code.Line("        {");
            Code.Line("            foreach ((CompositionClass OwnClass, CompositionSlots OwnSetter, uint[] _) in OwnProperties)");
            Code.Line("            {");
            Code.Line("                if (OwnClass == Class && OwnSetter == Setter)");
            Code.Line("                    return true;");
            Code.Line("            }");
            Code.Line();
            Code.Line("            return false;");
            Code.Line("        }");
            Code.Line();
            Code.Line("        internal uint TypeOf(CompositionClass Class) => (uint)Array.IndexOf(TypeClasses, Class);");
            Code.Line();
            Code.Line("        internal CompositionClass RuleOwner(CompositionClass Class)");
            Code.Line("        {");
            Code.Line("            foreach ((CompositionClass Owned, CompositionClass Owner) in RuleOwners)");
            Code.Line("            {");
            Code.Line("                if (Owned == Class)");
            Code.Line("                    return Owner;");
            Code.Line("            }");
            Code.Line();
            Code.Line("            return Class;");
            Code.Line("        }");
            Code.Line();
            Code.Line("        internal bool TryGetReference(CompositionClass Class, uint Id, out CompositionProperty Property)");
            Code.Line("        {");
            Code.Line("            foreach ((CompositionClass Named, uint NamedId, CompositionProperty Name) in References)");
            Code.Line("            {");
            Code.Line("                if (Named == Class && NamedId == Id)");
            Code.Line("                {");
            Code.Line("                    Property = Name;");
            Code.Line("                    return true;");
            Code.Line("                }");
            Code.Line("            }");
            Code.Line();
            Code.Line("            Property = default;");
            Code.Line("            return false;");
            Code.Line("        }");
            Code.Line();
            Code.Line("        internal bool TryGetRule(CompositionClass Class, CompositionSlots Setter, uint Property, out CompositionRule Rule)");
            Code.Line("            => Rules.TryGetValue((Class, Setter, Property), out Rule);");
            Code.Line();
            Code.Line("        private static bool Lists((CompositionClass Class, CompositionSlots Setter, uint[] Properties)[] Table, CompositionClass Class,");
            Code.Line("            CompositionSlots Setter, uint Property)");
            Code.Line("        {");
            Code.Line("            foreach ((CompositionClass ListClass, CompositionSlots ListSetter, uint[] Properties) in Table)");
            Code.Line("            {");
            Code.Line("                if (ListClass == Class && ListSetter == Setter)");
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
                Code.Line($"                (CompositionProperty.{Property.Name}, 0x{Property.Id:X}u, new uint[] {{ {string.Join(", ", Property.Bases.Select(Base => $"0x{Base:X}"))} }}),");

            Code.Line("            },");
            Code.Line("            new[]");
            Code.Line("            {");
            foreach (CompositionReferenceFact Reference in Facts.References)
            {
                CompositionPropertyFact Property = Facts.Properties.Single(Fact => Fact.Name == Reference.Property);
                Code.Line($"                (CompositionClass.{Reference.Class}, 0x{Property.Id:X}u, CompositionProperty.{Property.Name}),");
            }

            Code.Line("            },");
            Code.Line("            new (CompositionClass, uint, CompositionProperty, uint, uint)[]");
            Code.Line("            {");
            foreach (CompositionHandleFact Handle in Facts.Handles)
                Code.Line($"                (CompositionClass.{Handle.Class}, 0x{Handle.Id:X}u, CompositionProperty.{Handle.Property}, 0x{Handle.Access:X}u, 0x{Handle.Kind:X}u),");

            Code.Line("            },");
            WritePropertyLists(Code, Facts.OwnProperties);
            WritePropertyLists(Code, Facts.Refused);
            Code.Line("            new CompositionRule[]");
            Code.Line("            {");
            foreach (CompositionRuleFact Rule in Facts.Rules)
            {
                string Values = Rule.Values == null ? "null" : $"new ulong[] {{ {string.Join(", ", Rule.Values.Select(Value => $"0x{Value:X}"))} }}";
                string Initial = Rule.Initial is ulong Held ? $"0x{Held:X}ul" : "null";
                string Extra = (Rule.NonZero ? ", NonZero: true" : "") + (Rule.Requires != null
                    ? $", Requires: CompositionProperty.{Rule.Requires}, RequiredBases: new uint[] {{ {string.Join(", ", Rule.RequiredBases.Select(Base => $"0x{Base:X}"))} }}"
                    : "");
                Code.Line($"                new(CompositionClass.{Rule.Class}, CompositionSlots.{Rule.Setter}, 0x{Rule.Property:X}u, {Rule.Bytes}, {Values}, " +
                          $"CompositionCompare.{Rule.Compare}, {Initial}{Extra}),");
            }

            Code.Line("            },");
            Code.Line("            new (CompositionClass, CompositionClass)[]");
            Code.Line("            {");
            foreach (CompositionOwnerFact Owner in Facts.RuleOwners)
                Code.Line($"                (CompositionClass.{Owner.Class}, CompositionClass.{Owner.Owner}),");

            Code.Line("            });");
        }

        private static void WritePropertyLists(SourceWriter Code, CompositionOwnPropertiesFact[] Lists)
        {
            Code.Line("            new (CompositionClass, CompositionSlots, uint[])[]");
            Code.Line("            {");
            foreach (CompositionOwnPropertiesFact List in Lists)
            {
                Code.Line($"                (CompositionClass.{List.Class}, CompositionSlots.{List.Setter},");
                Code.Line($"                    new uint[] {{ {string.Join(", ", List.Properties.Select(Property => $"0x{Property:X}"))} }}),");
            }

            Code.Line("            },");
        }
    }
}
