using System;
using System.Collections.Generic;
using System.Text;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal enum SpirvTypeKind
    {
        Float,
        Int,
        Vector,
        Matrix,
        Array,
        Struct,
    }

    internal sealed class SpirvType
    {
        public SpirvTypeKind Kind;
        public int Width;
        public bool Signed;
        public int Count;
        public SpirvType? Element;
        public SpirvType[] Members = Array.Empty<SpirvType>();
        public List<uint[]>[] MemberDecorations = Array.Empty<List<uint[]>>();
    }

    internal sealed class SpirvVariable
    {
        public SpirvType Type = new SpirvType();
        public readonly List<uint[]> Decorations = new List<uint[]>();

        public int BuiltIn => Spirv.BuiltInOf(Decorations);
    }

    /// <summary>
    /// The output interface of one entry point, which is all the pass-through geometry shader has to copy.
    /// </summary>
    internal sealed class SpirvInterface
    {
        public uint ExecutionModel;
        public readonly List<SpirvVariable> Outputs = new List<SpirvVariable>();
        public bool TessellationIsolines;
        public bool TessellationPointMode;
        public bool Unsupported;
    }

    internal static unsafe class Spirv
    {
        public const uint Magic = 0x07230203;

        public const int OpName = 5;
        public const int OpMemoryModel = 14;
        public const int OpEntryPoint = 15;
        public const int OpExecutionMode = 16;
        public const int OpCapability = 17;
        public const int OpTypeVoid = 19;
        public const int OpTypeInt = 21;
        public const int OpTypeFloat = 22;
        public const int OpTypeVector = 23;
        public const int OpTypeMatrix = 24;
        public const int OpTypeArray = 28;
        public const int OpTypeStruct = 30;
        public const int OpTypePointer = 32;
        public const int OpTypeFunction = 33;
        public const int OpConstant = 43;
        public const int OpSpecConstant = 50;
        public const int OpFunction = 54;
        public const int OpFunctionEnd = 56;
        public const int OpVariable = 59;
        public const int OpLoad = 61;
        public const int OpStore = 62;
        public const int OpAccessChain = 65;
        public const int OpDecorate = 71;
        public const int OpMemberDecorate = 72;
        public const int OpEmitVertex = 218;
        public const int OpEndPrimitive = 219;
        public const int OpLabel = 248;
        public const int OpReturn = 253;

        public const uint StorageInput = 1;
        public const uint StorageOutput = 3;

        public const uint ModelVertex = 0;
        public const uint ModelTessellationEvaluation = 2;
        public const uint ModelGeometry = 3;

        public const uint ModePointMode = 10;
        public const uint ModeTriangles = 22;
        public const uint ModeIsolines = 25;
        public const uint ModeOutputVertices = 26;
        public const uint ModeOutputPoints = 27;
        public const uint ModeOutputLineStrip = 28;

        public const uint DecorationRelaxedPrecision = 0;
        public const uint DecorationBlock = 2;
        public const uint DecorationBuiltIn = 11;
        public const uint DecorationNoPerspective = 13;
        public const uint DecorationFlat = 14;
        public const uint DecorationCentroid = 16;
        public const uint DecorationSample = 17;
        public const uint DecorationInvariant = 18;
        public const uint DecorationStream = 29;
        public const uint DecorationLocation = 30;
        public const uint DecorationComponent = 31;
        public const uint DecorationXfbBuffer = 36;
        public const uint DecorationXfbStride = 37;

        public const uint BuiltInPosition = 0;
        public const uint BuiltInPointSize = 1;
        public const uint BuiltInClipDistance = 3;
        public const uint BuiltInCullDistance = 4;
        public const uint BuiltInLayer = 9;
        public const uint BuiltInViewportIndex = 10;

        public const uint CapabilityGeometry = 2;
        public const uint CapabilityGeometryPointSize = 24;
        public const uint CapabilityClipDistance = 32;
        public const uint CapabilityCullDistance = 33;
        public const uint CapabilityMultiViewport = 57;
        public const uint CapabilityShaderViewportIndex = 70;
        public const uint CapabilityShaderViewportIndexLayerEXT = 5254;

        public static int BuiltInOf(List<uint[]> decorations)
        {
            foreach (uint[] d in decorations)
            {
                if (d[0] == DecorationBuiltIn && d.Length > 1)
                    return (int)d[1];
            }

            return -1;
        }

        public static SpirvInterface? ParseInterface(uint* words, int count, uint executionModel, string? entryName)
        {
            if (count < 5 || words[0] != Magic)
                return null;

            Dictionary<uint, int> typeAt = new Dictionary<uint, int>();
            Dictionary<uint, uint> constants = new Dictionary<uint, uint>();
            HashSet<uint> specConstants = new HashSet<uint>();
            Dictionary<uint, List<uint[]>> decorations = new Dictionary<uint, List<uint[]>>();
            Dictionary<uint, Dictionary<uint, List<uint[]>>> memberDecorations = new Dictionary<uint, Dictionary<uint, List<uint[]>>>();
            Dictionary<uint, (uint Storage, uint PointerType)> variables = new Dictionary<uint, (uint, uint)>();
            List<uint> interfaces = new List<uint>();
            uint entry = 0;
            bool found = false;
            SpirvInterface result = new SpirvInterface { ExecutionModel = executionModel };

            for (int i = 5; i < count;)
            {
                uint head = words[i];
                int len = (int)(head >> 16);
                int op = (int)(head & 0xFFFF);
                if (len == 0 || i + len > count)
                    return null;

                switch (op)
                {
                    case OpEntryPoint:
                    {
                        int at = i + 3;
                        string name = ReadString(words, count, ref at);
                        if (!found && words[i + 1] == executionModel && (entryName == null || name == entryName))
                        {
                            found = true;
                            entry = words[i + 2];
                            for (int k = at; k < i + len; k++)
                                interfaces.Add(words[k]);
                        }
                        break;
                    }
                    case OpExecutionMode:
                        if (found && words[i + 1] == entry)
                        {
                            if (words[i + 2] == ModeIsolines) result.TessellationIsolines = true;
                            if (words[i + 2] == ModePointMode) result.TessellationPointMode = true;
                        }
                        break;
                    case OpDecorate:
                    {
                        uint[] d = Slice(words, i + 2, len - 2);
                        if (!decorations.TryGetValue(words[i + 1], out List<uint[]>? list))
                            decorations[words[i + 1]] = list = new List<uint[]>();
                        list.Add(d);
                        break;
                    }
                    case OpMemberDecorate:
                    {
                        uint[] d = Slice(words, i + 3, len - 3);
                        if (!memberDecorations.TryGetValue(words[i + 1], out Dictionary<uint, List<uint[]>>? members))
                            memberDecorations[words[i + 1]] = members = new Dictionary<uint, List<uint[]>>();
                        if (!members.TryGetValue(words[i + 2], out List<uint[]>? list))
                            members[words[i + 2]] = list = new List<uint[]>();
                        list.Add(d);
                        break;
                    }
                    case OpTypeInt:
                    case OpTypeFloat:
                    case OpTypeVector:
                    case OpTypeMatrix:
                    case OpTypeArray:
                    case OpTypeStruct:
                    case OpTypePointer:
                        typeAt[words[i + 1]] = i;
                        break;
                    case OpConstant:
                        if (len == 4)
                            constants[words[i + 2]] = words[i + 3];
                        break;
                    case OpSpecConstant:
                        specConstants.Add(words[i + 2]);
                        break;
                    case OpVariable:
                        variables[words[i + 2]] = (words[i + 3], words[i + 1]);
                        break;
                    case OpFunction:
                        i = count;
                        continue;
                }

                i += len;
            }

            if (!found)
                return null;

            Dictionary<uint, SpirvType> built = new Dictionary<uint, SpirvType>();
            foreach (uint id in interfaces)
            {
                if (!variables.TryGetValue(id, out (uint Storage, uint PointerType) v) || v.Storage != StorageOutput)
                    continue;
                if (!typeAt.TryGetValue(v.PointerType, out int at) || (words[at] & 0xFFFF) != OpTypePointer)
                    return null;

                SpirvVariable variable = new SpirvVariable();
                variable.Type = BuildType(words, typeAt, constants, specConstants, memberDecorations, built, words[at + 3], result);
                if (decorations.TryGetValue(id, out List<uint[]>? list))
                {
                    foreach (uint[] d in list)
                    {
                        if (d[0] == DecorationXfbBuffer || d[0] == DecorationXfbStride || d[0] == DecorationStream)
                            result.Unsupported = true;
                        variable.Decorations.Add(d);
                    }
                }

                result.Outputs.Add(variable);
            }

            return result;
        }

        private static SpirvType BuildType(uint* words, Dictionary<uint, int> typeAt, Dictionary<uint, uint> constants, HashSet<uint> specConstants,
            Dictionary<uint, Dictionary<uint, List<uint[]>>> memberDecorations, Dictionary<uint, SpirvType> built, uint id, SpirvInterface result)
        {
            if (built.TryGetValue(id, out SpirvType? done))
                return done;

            SpirvType t = new SpirvType();
            built[id] = t;
            if (!typeAt.TryGetValue(id, out int at))
            {
                result.Unsupported = true;
                return t;
            }

            switch (words[at] & 0xFFFF)
            {
                case OpTypeFloat:
                    t.Kind = SpirvTypeKind.Float;
                    t.Width = (int)words[at + 2];
                    break;
                case OpTypeInt:
                    t.Kind = SpirvTypeKind.Int;
                    t.Width = (int)words[at + 2];
                    t.Signed = words[at + 3] != 0;
                    break;
                case OpTypeVector:
                    t.Kind = SpirvTypeKind.Vector;
                    t.Element = BuildType(words, typeAt, constants, specConstants, memberDecorations, built, words[at + 2], result);
                    t.Count = (int)words[at + 3];
                    break;
                case OpTypeMatrix:
                    t.Kind = SpirvTypeKind.Matrix;
                    t.Element = BuildType(words, typeAt, constants, specConstants, memberDecorations, built, words[at + 2], result);
                    t.Count = (int)words[at + 3];
                    break;
                case OpTypeArray:
                    t.Kind = SpirvTypeKind.Array;
                    t.Element = BuildType(words, typeAt, constants, specConstants, memberDecorations, built, words[at + 2], result);
                    if (specConstants.Contains(words[at + 3]) || !constants.TryGetValue(words[at + 3], out uint length))
                        result.Unsupported = true;
                    else
                        t.Count = (int)length;
                    break;
                case OpTypeStruct:
                {
                    t.Kind = SpirvTypeKind.Struct;
                    int n = (int)(words[at] >> 16) - 2;
                    t.Members = new SpirvType[n];
                    t.MemberDecorations = new List<uint[]>[n];
                    memberDecorations.TryGetValue(id, out Dictionary<uint, List<uint[]>>? members);
                    for (int m = 0; m < n; m++)
                    {
                        t.Members[m] = BuildType(words, typeAt, constants, specConstants, memberDecorations, built, words[at + 2 + m], result);
                        t.MemberDecorations[m] = members != null && members.TryGetValue((uint)m, out List<uint[]>? list) ? list : new List<uint[]>();
                        foreach (uint[] d in t.MemberDecorations[m])
                        {
                            if (d[0] == DecorationXfbBuffer || d[0] == DecorationXfbStride || d[0] == DecorationStream)
                                result.Unsupported = true;
                        }
                    }
                    break;
                }
                default:
                    result.Unsupported = true;
                    break;
            }

            if ((t.Kind == SpirvTypeKind.Float || t.Kind == SpirvTypeKind.Int) && t.Width != 32)
                result.Unsupported = true;

            return t;
        }

        private static string ReadString(uint* words, int count, ref int at)
        {
            StringBuilder s = new StringBuilder();
            while (at < count)
            {
                uint w = words[at++];
                for (int k = 0; k < 4; k++)
                {
                    byte c = (byte)(w >> (8 * k));
                    if (c == 0)
                        return s.ToString();
                    s.Append((char)c);
                }
            }

            return s.ToString();
        }

        private static uint[] Slice(uint* words, int at, int n)
        {
            uint[] r = new uint[n];
            for (int k = 0; k < n; k++)
                r[k] = words[at + k];
            return r;
        }

        /// <summary>
        /// Removes every write of the ViewportIndex built-in, and the capabilities that need it, from a
        /// module. Returns the new word count, or -1 when the module uses the built-in in a way this
        /// cannot remove.
        /// </summary>
        public static int StripViewportIndex(uint* words, int count)
        {
            if (count < 5 || words[0] != Magic)
                return -1;

            HashSet<uint> targets = new HashSet<uint>();
            bool layer = false;
            bool inFunction = false;
            for (int i = 5; i < count;)
            {
                uint head = words[i];
                int len = (int)(head >> 16);
                int op = (int)(head & 0xFFFF);
                if (len == 0 || i + len > count)
                    return -1;

                if (op == OpDecorate && len >= 4 && words[i + 2] == DecorationBuiltIn)
                {
                    if (words[i + 3] == BuiltInViewportIndex) targets.Add(words[i + 1]);
                    if (words[i + 3] == BuiltInLayer) layer = true;
                }
                else if (op == OpMemberDecorate && len >= 5 && words[i + 3] == DecorationBuiltIn && words[i + 4] == BuiltInViewportIndex)
                    return -1;
                else if (op == OpFunction)
                    inFunction = true;
                else if (inFunction && targets.Count != 0)
                {
                    // Only a plain store to the variable can go. Any other use keeps the module as it is.
                    for (int k = 1; k < len; k++)
                    {
                        if (targets.Contains(words[i + k]) && !(op == OpStore && k == 1))
                            return -1;
                    }
                }

                i += len;
            }

            if (targets.Count == 0 && !HasCapability(words, count, CapabilityMultiViewport)
                && !HasCapability(words, count, CapabilityShaderViewportIndex)
                && (layer || !HasCapability(words, count, CapabilityShaderViewportIndexLayerEXT)))
                return count;

            int w = 5;
            for (int i = 5; i < count;)
            {
                uint head = words[i];
                int len = (int)(head >> 16);
                int op = (int)(head & 0xFFFF);
                bool drop = false;

                switch (op)
                {
                    case OpCapability:
                        drop = words[i + 1] == CapabilityMultiViewport || words[i + 1] == CapabilityShaderViewportIndex
                            || (words[i + 1] == CapabilityShaderViewportIndexLayerEXT && !layer);
                        break;
                    case OpVariable:
                        drop = targets.Contains(words[i + 2]);
                        break;
                    case OpDecorate:
                    case OpName:
                        drop = targets.Contains(words[i + 1]);
                        break;
                    case OpStore:
                        drop = targets.Contains(words[i + 1]);
                        break;
                    case OpEntryPoint:
                    {
                        int at = i + 3;
                        ReadString(words, count, ref at);
                        int kept = at - i;
                        for (int k = 0; k < kept; k++)
                            words[w + k] = words[i + k];
                        int n = kept;
                        for (int k = at; k < i + len; k++)
                        {
                            if (!targets.Contains(words[k]))
                                words[w + n++] = words[k];
                        }
                        words[w] = ((uint)n << 16) | (uint)OpEntryPoint;
                        w += n;
                        i += len;
                        continue;
                    }
                }

                if (!drop)
                {
                    for (int k = 0; k < len; k++)
                        words[w + k] = words[i + k];
                    w += len;
                }

                i += len;
            }

            return w;
        }

        private static bool HasCapability(uint* words, int count, uint capability)
        {
            for (int i = 5; i < count;)
            {
                uint head = words[i];
                int len = (int)(head >> 16);
                int op = (int)(head & 0xFFFF);
                if (len == 0)
                    return false;
                if (op == OpCapability && words[i + 1] == capability)
                    return true;
                if (op != OpCapability)
                    return false;
                i += len;
            }

            return false;
        }
    }

    internal sealed class SpirvBuilder
    {
        private readonly List<uint> _capabilities = new List<uint>();
        private readonly List<uint> _entry = new List<uint>();
        private readonly List<uint> _modes = new List<uint>();
        private readonly List<uint> _annotations = new List<uint>();
        private readonly List<uint> _types = new List<uint>();
        private readonly List<uint> _code = new List<uint>();
        private readonly Dictionary<string, uint> _cache = new Dictionary<string, uint>();
        private uint _next = 1;

        public uint NewId() => _next++;

        private static void Emit(List<uint> section, int op, params uint[] operands)
        {
            section.Add(((uint)(operands.Length + 1) << 16) | (uint)op);
            section.AddRange(operands);
        }

        private static void Emit(List<uint> section, int op, List<uint> operands)
        {
            section.Add(((uint)(operands.Count + 1) << 16) | (uint)op);
            section.AddRange(operands);
        }

        public void Capability(uint capability)
        {
            string key = "cap:" + capability;
            if (_cache.ContainsKey(key))
                return;
            _cache[key] = 0;
            Emit(_capabilities, Spirv.OpCapability, capability);
        }

        public void EntryPoint(uint model, uint function, string name, List<uint> interfaces)
        {
            List<uint> operands = new List<uint> { model, function };
            byte[] bytes = Encoding.UTF8.GetBytes(name);
            for (int i = 0; i <= bytes.Length; i += 4)
            {
                uint w = 0;
                for (int k = 0; k < 4 && i + k < bytes.Length; k++)
                    w |= (uint)bytes[i + k] << (8 * k);
                operands.Add(w);
            }
            operands.AddRange(interfaces);
            Emit(_entry, Spirv.OpEntryPoint, operands);
        }

        public void ExecutionMode(uint function, uint mode, params uint[] literals)
        {
            List<uint> operands = new List<uint> { function, mode };
            operands.AddRange(literals);
            Emit(_modes, Spirv.OpExecutionMode, operands);
        }

        public void Decorate(uint target, uint[] decoration)
        {
            List<uint> operands = new List<uint> { target };
            operands.AddRange(decoration);
            Emit(_annotations, Spirv.OpDecorate, operands);
        }

        public void MemberDecorate(uint target, uint member, uint[] decoration)
        {
            List<uint> operands = new List<uint> { target, member };
            operands.AddRange(decoration);
            Emit(_annotations, Spirv.OpMemberDecorate, operands);
        }

        private uint Cached(string key, int op, Func<uint, uint[]> operands)
        {
            if (_cache.TryGetValue(key, out uint id))
                return id;
            id = NewId();
            _cache[key] = id;
            Emit(_types, op, operands(id));
            return id;
        }

        public uint TypeVoid() => Cached("void", Spirv.OpTypeVoid, id => new[] { id });

        public uint TypeFunction(uint returnType) => Cached("fn:" + returnType, Spirv.OpTypeFunction, id => new[] { id, returnType });

        public uint TypeFloat() => Cached("f32", Spirv.OpTypeFloat, id => new[] { id, 32u });

        public uint TypeInt(bool signed) => Cached("i32:" + (signed ? 1 : 0), Spirv.OpTypeInt, id => new[] { id, 32u, signed ? 1u : 0u });

        public uint TypeVector(uint element, int count) => Cached("v:" + element + ":" + count, Spirv.OpTypeVector, id => new[] { id, element, (uint)count });

        public uint TypeMatrix(uint column, int count) => Cached("m:" + column + ":" + count, Spirv.OpTypeMatrix, id => new[] { id, column, (uint)count });

        public uint TypeArray(uint element, int count)
        {
            uint length = ConstantUInt((uint)count);
            return Cached("a:" + element + ":" + count, Spirv.OpTypeArray, id => new[] { id, element, length });
        }

        public uint TypeStruct(uint[] members)
        {
            uint id = NewId();
            List<uint> operands = new List<uint> { id };
            operands.AddRange(members);
            Emit(_types, Spirv.OpTypeStruct, operands);
            return id;
        }

        public uint TypePointer(uint storage, uint type) => Cached("p:" + storage + ":" + type, Spirv.OpTypePointer, id => new[] { id, storage, type });

        public uint ConstantUInt(uint value)
        {
            uint type = TypeInt(false);
            return Cached("cu:" + value, Spirv.OpConstant, id => new[] { type, id, value });
        }

        public uint ConstantInt(int value)
        {
            uint type = TypeInt(true);
            return Cached("ci:" + value, Spirv.OpConstant, id => new[] { type, id, (uint)value });
        }

        public uint ConstantFloat(float value)
        {
            uint type = TypeFloat();
            uint bits = BitConverter.SingleToUInt32Bits(value);
            return Cached("cf:" + bits, Spirv.OpConstant, id => new[] { type, id, bits });
        }

        public uint Variable(uint pointerType, uint storage)
        {
            uint id = NewId();
            Emit(_types, Spirv.OpVariable, pointerType, id, storage);
            return id;
        }

        public uint Function(uint returnType, uint functionType)
        {
            uint id = NewId();
            Emit(_code, Spirv.OpFunction, returnType, id, 0, functionType);
            Emit(_code, Spirv.OpLabel, NewId());
            return id;
        }

        public uint AccessChain(uint pointerType, uint baseId, params uint[] indices)
        {
            uint id = NewId();
            List<uint> operands = new List<uint> { pointerType, id, baseId };
            operands.AddRange(indices);
            Emit(_code, Spirv.OpAccessChain, operands);
            return id;
        }

        public uint Load(uint type, uint pointer)
        {
            uint id = NewId();
            Emit(_code, Spirv.OpLoad, type, id, pointer);
            return id;
        }

        public void Store(uint pointer, uint value) => Emit(_code, Spirv.OpStore, pointer, value);

        public void EmitVertex() => Emit(_code, Spirv.OpEmitVertex);

        public void EndPrimitive() => Emit(_code, Spirv.OpEndPrimitive);

        public void EndFunction()
        {
            Emit(_code, Spirv.OpReturn);
            Emit(_code, Spirv.OpFunctionEnd);
        }

        public uint[] Finish()
        {
            List<uint> words = new List<uint> { Spirv.Magic, 0x00010000, 0, _next, 0 };
            words.AddRange(_capabilities);
            words.Add((3u << 16) | Spirv.OpMemoryModel);
            words.Add(0);
            words.Add(1);
            words.AddRange(_entry);
            words.AddRange(_modes);
            words.AddRange(_annotations);
            words.AddRange(_types);
            words.AddRange(_code);
            return words.ToArray();
        }
    }

    /// <summary>
    /// Builds the geometry shader that turns each triangle of a stage's output into its edges or corners.
    /// </summary>
    internal static class SpirvPassThrough
    {
        private sealed class Slot
        {
            public uint In;
            public uint Out;
            public uint Type;
            public uint InElementPointer;
            public int[] Members = Array.Empty<int>();
            public uint[] MemberTypes = Array.Empty<uint>();
            public uint[] MemberInPointers = Array.Empty<uint>();
            public uint[] MemberOutPointers = Array.Empty<uint>();
        }

        public static uint[]? Build(SpirvInterface stage, bool points, bool pointSize, bool clipDistance, bool cullDistance)
        {
            if (stage.Unsupported || stage.TessellationIsolines || stage.TessellationPointMode)
                return null;

            foreach (SpirvVariable v in stage.Outputs)
            {
                if (!Carryable(v.BuiltIn))
                    return null;
                if (v.Type.Kind == SpirvTypeKind.Struct)
                {
                    foreach (List<uint[]> member in v.Type.MemberDecorations)
                    {
                        if (!Carryable(Spirv.BuiltInOf(member)))
                            return null;
                    }
                }
            }

            SpirvBuilder b = new SpirvBuilder();
            b.Capability(Spirv.CapabilityGeometry);

            List<uint> interfaces = new List<uint>();
            List<Slot> slots = new List<Slot>();
            uint three = b.ConstantUInt(3);
            bool hasPointSize = false;

            foreach (SpirvVariable v in stage.Outputs)
            {
                Slot slot = new Slot();
                if (v.Type.Kind == SpirvTypeKind.Struct)
                {
                    List<int> kept = new List<int>();
                    for (int m = 0; m < v.Type.Members.Length; m++)
                    {
                        int builtIn = Spirv.BuiltInOf(v.Type.MemberDecorations[m]);
                        if (Keep(builtIn, pointSize, clipDistance, cullDistance, b, ref hasPointSize))
                            kept.Add(m);
                    }

                    if (kept.Count == 0)
                        continue;

                    slot.Members = kept.ToArray();
                    slot.MemberTypes = new uint[kept.Count];
                    slot.MemberInPointers = new uint[kept.Count];
                    slot.MemberOutPointers = new uint[kept.Count];
                    for (int k = 0; k < kept.Count; k++)
                    {
                        slot.MemberTypes[k] = TypeId(b, v.Type.Members[kept[k]]);
                        slot.MemberInPointers[k] = b.TypePointer(Spirv.StorageInput, slot.MemberTypes[k]);
                        slot.MemberOutPointers[k] = b.TypePointer(Spirv.StorageOutput, slot.MemberTypes[k]);
                    }

                    uint inStruct = b.TypeStruct(slot.MemberTypes);
                    uint outStruct = b.TypeStruct(slot.MemberTypes);
                    b.Decorate(inStruct, new[] { Spirv.DecorationBlock });
                    b.Decorate(outStruct, new[] { Spirv.DecorationBlock });
                    for (int k = 0; k < kept.Count; k++)
                    {
                        foreach (uint[] d in v.Type.MemberDecorations[kept[k]])
                        {
                            b.MemberDecorate(inStruct, (uint)k, d);
                            b.MemberDecorate(outStruct, (uint)k, d);
                        }
                    }

                    slot.In = b.Variable(b.TypePointer(Spirv.StorageInput, b.TypeArray(inStruct, 3)), Spirv.StorageInput);
                    slot.Out = b.Variable(b.TypePointer(Spirv.StorageOutput, outStruct), Spirv.StorageOutput);
                }
                else
                {
                    if (!Keep(v.BuiltIn, pointSize, clipDistance, cullDistance, b, ref hasPointSize))
                        continue;

                    slot.Type = TypeId(b, v.Type);
                    slot.InElementPointer = b.TypePointer(Spirv.StorageInput, slot.Type);
                    slot.In = b.Variable(b.TypePointer(Spirv.StorageInput, b.TypeArray(slot.Type, 3)), Spirv.StorageInput);
                    slot.Out = b.Variable(b.TypePointer(Spirv.StorageOutput, slot.Type), Spirv.StorageOutput);
                }

                foreach (uint[] d in v.Decorations)
                {
                    b.Decorate(slot.Out, d);
                    if (d[0] == Spirv.DecorationLocation || d[0] == Spirv.DecorationComponent || d[0] == Spirv.DecorationBuiltIn)
                        b.Decorate(slot.In, d);
                }

                interfaces.Add(slot.In);
                interfaces.Add(slot.Out);
                slots.Add(slot);
            }

            uint ownPointSize = 0;
            if (points && pointSize && !hasPointSize)
            {
                b.Capability(Spirv.CapabilityGeometryPointSize);
                ownPointSize = b.Variable(b.TypePointer(Spirv.StorageOutput, b.TypeFloat()), Spirv.StorageOutput);
                b.Decorate(ownPointSize, new[] { Spirv.DecorationBuiltIn, Spirv.BuiltInPointSize });
                interfaces.Add(ownPointSize);
            }

            uint voidType = b.TypeVoid();
            uint main = b.Function(voidType, b.TypeFunction(voidType));
            b.EntryPoint(Spirv.ModelGeometry, main, "main", interfaces);
            b.ExecutionMode(main, Spirv.ModeTriangles);
            b.ExecutionMode(main, points ? Spirv.ModeOutputPoints : Spirv.ModeOutputLineStrip);
            b.ExecutionMode(main, Spirv.ModeOutputVertices, points ? 3u : 4u);

            int[] order = points ? new[] { 0, 1, 2 } : new[] { 0, 1, 2, 0 };
            uint one = ownPointSize != 0 ? b.ConstantFloat(1.0f) : 0;
            foreach (int vertex in order)
            {
                uint index = b.ConstantInt(vertex);
                foreach (Slot slot in slots)
                {
                    if (slot.Members.Length != 0)
                    {
                        for (int k = 0; k < slot.Members.Length; k++)
                        {
                            uint member = b.ConstantInt(k);
                            uint value = b.Load(slot.MemberTypes[k], b.AccessChain(slot.MemberInPointers[k], slot.In, index, member));
                            b.Store(b.AccessChain(slot.MemberOutPointers[k], slot.Out, member), value);
                        }
                    }
                    else
                    {
                        b.Store(slot.Out, b.Load(slot.Type, b.AccessChain(slot.InElementPointer, slot.In, index)));
                    }
                }

                if (ownPointSize != 0)
                    b.Store(ownPointSize, one);
                b.EmitVertex();
            }

            b.EndPrimitive();
            b.EndFunction();
            return b.Finish();
        }

        private static bool Carryable(int builtIn)
        {
            return builtIn < 0 || builtIn == Spirv.BuiltInPosition || builtIn == Spirv.BuiltInPointSize
                || builtIn == Spirv.BuiltInClipDistance || builtIn == Spirv.BuiltInCullDistance;
        }

        private static bool Keep(int builtIn, bool pointSize, bool clipDistance, bool cullDistance, SpirvBuilder b, ref bool hasPointSize)
        {
            switch (builtIn)
            {
                case (int)Spirv.BuiltInPointSize:
                    if (!pointSize) return false;
                    b.Capability(Spirv.CapabilityGeometryPointSize);
                    hasPointSize = true;
                    return true;
                case (int)Spirv.BuiltInClipDistance:
                    if (!clipDistance) return false;
                    b.Capability(Spirv.CapabilityClipDistance);
                    return true;
                case (int)Spirv.BuiltInCullDistance:
                    if (!cullDistance) return false;
                    b.Capability(Spirv.CapabilityCullDistance);
                    return true;
                default:
                    return true;
            }
        }

        private static uint TypeId(SpirvBuilder b, SpirvType t)
        {
            switch (t.Kind)
            {
                case SpirvTypeKind.Float:
                    return b.TypeFloat();
                case SpirvTypeKind.Int:
                    return b.TypeInt(t.Signed);
                case SpirvTypeKind.Vector:
                    return b.TypeVector(TypeId(b, t.Element!), t.Count);
                case SpirvTypeKind.Matrix:
                    return b.TypeMatrix(TypeId(b, t.Element!), t.Count);
                case SpirvTypeKind.Array:
                    return b.TypeArray(TypeId(b, t.Element!), t.Count);
                default:
                {
                    uint[] members = new uint[t.Members.Length];
                    for (int m = 0; m < members.Length; m++)
                        members[m] = TypeId(b, t.Members[m]);
                    uint id = b.TypeStruct(members);
                    for (int m = 0; m < members.Length; m++)
                    {
                        foreach (uint[] d in t.MemberDecorations[m])
                            b.MemberDecorate(id, (uint)m, d);
                    }
                    return id;
                }
            }
        }
    }
}
