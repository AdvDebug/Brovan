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
        public const int OpLine = 8;
        public const int OpMemoryModel = 14;
        public const int OpEntryPoint = 15;
        public const int OpExecutionMode = 16;
        public const int OpCapability = 17;
        public const int OpTypeVoid = 19;
        public const int OpTypeBool = 20;
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
        public const int OpLogicalOr = 166;
        public const int OpFOrdLessThan = 184;
        public const int OpEmitVertex = 218;
        public const int OpEndPrimitive = 219;
        public const int OpSelectionMerge = 247;
        public const int OpLabel = 248;
        public const int OpBranchConditional = 250;
        public const int OpKill = 252;
        public const int OpReturn = 253;
        public const int OpNoLine = 317;
        public const int OpDecorateId = 332;
        public const int OpDecorateString = 5632;
        public const int OpMemberDecorateString = 5633;

        public const uint StorageInput = 1;
        public const uint StorageOutput = 3;

        public const uint ModelVertex = 0;
        public const uint ModelTessellationEvaluation = 2;
        public const uint ModelGeometry = 3;
        public const uint ModelFragment = 4;

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

        public const uint CapabilityShader = 1;
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

        private static int ArrayElements(uint* words, Dictionary<uint, int> typeAt, Dictionary<uint, uint> constants, uint pointerType)
        {
            if (!typeAt.TryGetValue(pointerType, out int at) || (words[at] & 0xFFFF) != OpTypePointer)
                return -1;

            uint type = words[at + 3];
            int elements = 1;
            while (typeAt.TryGetValue(type, out at) && (words[at] & 0xFFFF) == OpTypeArray)
            {
                if (!constants.TryGetValue(words[at + 3], out uint length))
                    return -1;
                elements = (int)length;
                type = words[at + 2];
            }

            return elements;
        }

        /// <summary>
        /// Moves the built-ins a host cannot export onto user locations, in place. The word count never changes,
        /// so a capability that becomes unnecessary turns into a repeated Shader capability.
        /// </summary>
        public static void Relocate(uint* words, int count, in SpirvRelocation where, out SpirvModuleInfo info)
        {
            info = default;
            if (count < 5 || words[0] != Magic)
                return;

            List<int> capabilities = new List<int>();
            List<(int At, uint Target, uint BuiltIn)> targets = new List<(int, uint, uint)>();
            List<(uint Target, uint Location)> locations = new List<(uint, uint)>();
            Dictionary<uint, (uint Storage, uint Type)> variables = new Dictionary<uint, (uint, uint)>();
            Dictionary<uint, int> typeAt = new Dictionary<uint, int>();
            Dictionary<uint, uint> constants = new Dictionary<uint, uint>();
            bool layer = false;
            for (int i = 5; i < count;)
            {
                uint head = words[i];
                int len = (int)(head >> 16);
                int op = (int)(head & 0xFFFF);
                if (len == 0 || i + len > count)
                {
                    info.Left = true;
                    return;
                }

                switch (op)
                {
                    case OpCapability:
                        capabilities.Add(i);
                        break;
                    case OpEntryPoint:
                        if (words[i + 1] < 32)
                            info.Models |= 1u << (int)words[i + 1];
                        break;
                    case OpDecorate:
                        if (len >= 4 && words[i + 2] == DecorationBuiltIn)
                        {
                            uint builtIn = words[i + 3];
                            if (builtIn == BuiltInLayer)
                                layer = true;
                            else if (builtIn == BuiltInViewportIndex || builtIn == BuiltInClipDistance || builtIn == BuiltInCullDistance)
                                targets.Add((i, words[i + 1], builtIn));
                        }
                        else if (len >= 4 && words[i + 2] == DecorationLocation)
                            locations.Add((words[i + 1], words[i + 3]));
                        break;
                    case OpMemberDecorate:
                        if (len >= 5 && words[i + 3] == DecorationBuiltIn && where.LocationOf(words[i + 4]) >= 0)
                            info.Left = true;
                        break;
                    case OpTypeArray:
                    case OpTypePointer:
                        typeAt[words[i + 1]] = i;
                        break;
                    case OpConstant:
                        if (len == 4)
                            constants[words[i + 2]] = words[i + 3];
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

            int moved = 0;
            int[] newLocation = new int[targets.Count];
            for (int t = 0; t < targets.Count; t++)
            {
                (int at, uint target, uint builtIn) = targets[t];
                newLocation[t] = -1;
                int location = where.LocationOf(builtIn);
                if (location < 0)
                    continue;

                if (!variables.TryGetValue(target, out (uint Storage, uint Type) variable))
                {
                    info.Left = true;
                    continue;
                }

                int elements = ArrayElements(words, typeAt, constants, variable.Type);
                if (elements < 1 || elements > SpirvRelocation.MaxElements
                    || (builtIn == BuiltInViewportIndex && variable.Storage == StorageInput))
                {
                    info.Left = true;
                    continue;
                }

                foreach ((uint other, uint used) in locations)
                {
                    if (used >= (uint)location && used < (uint)(location + elements)
                        && variables.TryGetValue(other, out (uint Storage, uint Type) o) && o.Storage == variable.Storage)
                        info.Left = true;
                }

                if (builtIn == BuiltInClipDistance && variable.Storage == StorageOutput)
                    info.ClipOutputs = elements;

                newLocation[t] = location;
                moved++;
            }

            if (info.Left)
            {
                info.ClipOutputs = 0;
                return;
            }

            for (int t = 0; t < targets.Count; t++)
            {
                if (newLocation[t] < 0)
                    continue;

                int at = targets[t].At;
                words[at + 2] = DecorationLocation;
                words[at + 3] = (uint)newLocation[t];
            }

            foreach (int at in capabilities)
            {
                uint capability = words[at + 1];
                bool drop = (capability == CapabilityClipDistance && where.Clip >= 0)
                    || (capability == CapabilityCullDistance && where.Cull >= 0)
                    || ((capability == CapabilityMultiViewport || capability == CapabilityShaderViewportIndex) && where.Viewport >= 0)
                    || (capability == CapabilityShaderViewportIndexLayerEXT && where.Viewport >= 0 && !layer);
                if (!drop)
                    continue;

                words[at + 1] = CapabilityShader;
                moved++;
            }

            info.Relocated = moved != 0;
        }
    }

    /// <summary>User locations that stand in for the built-ins a host cannot export. -1 leaves a built-in as it is.</summary>
    internal readonly struct SpirvRelocation
    {
        public const int MaxElements = 8;

        public readonly int Viewport;
        public readonly int Clip;
        public readonly int Cull;

        public SpirvRelocation(int viewport, int clip, int cull)
        {
            Viewport = viewport;
            Clip = clip;
            Cull = cull;
        }

        public bool Any => Viewport >= 0 || Clip >= 0 || Cull >= 0;

        public int LocationOf(uint builtIn)
        {
            switch (builtIn)
            {
                case Spirv.BuiltInViewportIndex: return Viewport;
                case Spirv.BuiltInClipDistance: return Clip;
                case Spirv.BuiltInCullDistance: return Cull;
                default: return -1;
            }
        }
    }

    internal struct SpirvModuleInfo
    {
        public uint Models;
        public int ClipOutputs;
        public bool Relocated;
        public bool Left;

        public bool Has(uint model) => (Models & (1u << (int)model)) != 0;
    }

    /// <summary>Fragment prologue that discards where a relocated clip distance is negative, as the clip planes would.</summary>
    internal static unsafe class SpirvClipDiscard
    {
        private const uint FragmentModel = 4;

        public static uint[]? Build(uint* words, int count, int location, int elements)
        {
            if (count < 5 || words[0] != Spirv.Magic || elements < 1 || elements > SpirvRelocation.MaxElements)
                return null;

            uint bound = words[3];
            int entryAt = -1;
            int annotationsEnd = -1;
            int firstFunction = -1;
            uint entryFunction = 0;
            uint floatType = 0, boolType = 0, uintType = 0, pointerFloat = 0, zero = 0, variable = 0;
            uint[] index = new uint[elements];
            Dictionary<uint, int> typeAt = new Dictionary<uint, int>();
            Dictionary<uint, (uint Type, uint Value)> constants = new Dictionary<uint, (uint, uint)>();
            List<uint> located = new List<uint>();
            for (int i = 5; i < count;)
            {
                uint head = words[i];
                int len = (int)(head >> 16);
                int op = (int)(head & 0xFFFF);
                if (len == 0 || i + len > count)
                    return null;

                switch (op)
                {
                    case Spirv.OpEntryPoint:
                        if (words[i + 1] == FragmentModel && entryAt < 0)
                        {
                            entryAt = i;
                            entryFunction = words[i + 2];
                        }
                        break;
                    case Spirv.OpDecorate:
                    case Spirv.OpMemberDecorate:
                    case Spirv.OpDecorateId:
                    case Spirv.OpDecorateString:
                    case Spirv.OpMemberDecorateString:
                        annotationsEnd = i + len;
                        if (op == Spirv.OpDecorate && len >= 4 && words[i + 2] == Spirv.DecorationLocation && words[i + 3] == (uint)location)
                            located.Add(words[i + 1]);
                        break;
                    case Spirv.OpTypeFloat:
                        if (words[i + 2] == 32)
                            floatType = words[i + 1];
                        break;
                    case Spirv.OpTypeBool:
                        boolType = words[i + 1];
                        break;
                    case Spirv.OpTypeInt:
                        if (words[i + 2] == 32 && words[i + 3] == 0)
                            uintType = words[i + 1];
                        typeAt[words[i + 1]] = i;
                        break;
                    case Spirv.OpTypeArray:
                    case Spirv.OpTypePointer:
                        typeAt[words[i + 1]] = i;
                        break;
                    case Spirv.OpConstant:
                        if (len == 4)
                            constants[words[i + 2]] = (words[i + 1], words[i + 3]);
                        break;
                    case Spirv.OpVariable:
                        if (words[i + 3] == Spirv.StorageInput && located.Contains(words[i + 2])
                            && typeAt.TryGetValue(words[i + 1], out int pointerAt) && typeAt.TryGetValue(words[pointerAt + 3], out int arrayAt)
                            && (words[arrayAt] & 0xFFFF) == Spirv.OpTypeArray && words[arrayAt + 2] == floatType
                            && constants.TryGetValue(words[arrayAt + 3], out (uint Type, uint Value) length) && length.Value == (uint)elements)
                            variable = words[i + 2];
                        break;
                    case Spirv.OpFunction:
                        firstFunction = i;
                        i = count;
                        continue;
                }

                i += len;
            }

            if (entryAt < 0 || firstFunction < 0)
                return null;

            foreach (KeyValuePair<uint, int> type in typeAt)
            {
                int at = type.Value;
                if ((words[at] & 0xFFFF) == Spirv.OpTypePointer && words[at + 2] == Spirv.StorageInput && words[at + 3] == floatType)
                    pointerFloat = type.Key;
            }

            foreach (KeyValuePair<uint, (uint Type, uint Value)> constant in constants)
            {
                if (floatType != 0 && constant.Value.Type == floatType && constant.Value.Value == 0)
                    zero = constant.Key;
                if (uintType != 0 && constant.Value.Type == uintType && constant.Value.Value < (uint)elements)
                    index[constant.Value.Value] = constant.Key;
            }

            int functionAt = -1;
            for (int i = firstFunction; i < count;)
            {
                uint head = words[i];
                int len = (int)(head >> 16);
                if (len == 0 || i + len > count)
                    return null;
                if ((head & 0xFFFF) == Spirv.OpFunction && words[i + 2] == entryFunction)
                {
                    functionAt = i;
                    break;
                }
                i += len;
            }

            if (functionAt < 0)
                return null;

            int prologueAt = -1;
            for (int i = functionAt; i < count;)
            {
                uint head = words[i];
                int len = (int)(head >> 16);
                if (len == 0 || i + len > count)
                    return null;
                if ((head & 0xFFFF) == Spirv.OpLabel)
                {
                    prologueAt = i + len;
                    for (int k = prologueAt; k < count;)
                    {
                        uint h = words[k];
                        int l = (int)(h >> 16);
                        int o = (int)(h & 0xFFFF);
                        if (l == 0 || (o != Spirv.OpVariable && o != Spirv.OpLine && o != Spirv.OpNoLine))
                            break;
                        prologueAt = k + l;
                        k += l;
                    }
                    break;
                }
                i += len;
            }

            if (prologueAt < 0)
                return null;

            List<uint> globals = new List<uint>();
            if (floatType == 0)
                floatType = Emit(globals, ref bound, Spirv.OpTypeFloat, 32);
            if (boolType == 0)
                boolType = Emit(globals, ref bound, Spirv.OpTypeBool);
            if (uintType == 0)
                uintType = Emit(globals, ref bound, Spirv.OpTypeInt, 32, 0);
            for (int k = 0; k < elements; k++)
            {
                if (index[k] == 0)
                    index[k] = EmitTyped(globals, ref bound, Spirv.OpConstant, uintType, (uint)k);
            }
            if (zero == 0)
                zero = EmitTyped(globals, ref bound, Spirv.OpConstant, floatType, 0);
            if (pointerFloat == 0)
                pointerFloat = Emit(globals, ref bound, Spirv.OpTypePointer, Spirv.StorageInput, floatType);

            List<uint> annotations = new List<uint>();
            bool created = variable == 0;
            if (created)
            {
                uint length = EmitTyped(globals, ref bound, Spirv.OpConstant, uintType, (uint)elements);
                uint array = Emit(globals, ref bound, Spirv.OpTypeArray, floatType, length);
                uint pointer = Emit(globals, ref bound, Spirv.OpTypePointer, Spirv.StorageInput, array);
                variable = EmitTyped(globals, ref bound, Spirv.OpVariable, pointer, Spirv.StorageInput);
                annotations.Add((4u << 16) | Spirv.OpDecorate);
                annotations.Add(variable);
                annotations.Add(Spirv.DecorationLocation);
                annotations.Add((uint)location);
            }

            List<uint> prologue = new List<uint>();
            uint condition = 0;
            for (int k = 0; k < elements; k++)
            {
                uint pointer = bound++;
                prologue.Add((5u << 16) | Spirv.OpAccessChain);
                prologue.Add(pointerFloat);
                prologue.Add(pointer);
                prologue.Add(variable);
                prologue.Add(index[k]);
                uint value = bound++;
                prologue.Add((4u << 16) | Spirv.OpLoad);
                prologue.Add(floatType);
                prologue.Add(value);
                prologue.Add(pointer);
                uint negative = bound++;
                prologue.Add((5u << 16) | Spirv.OpFOrdLessThan);
                prologue.Add(boolType);
                prologue.Add(negative);
                prologue.Add(value);
                prologue.Add(zero);
                if (condition == 0)
                {
                    condition = negative;
                    continue;
                }

                uint any = bound++;
                prologue.Add((5u << 16) | Spirv.OpLogicalOr);
                prologue.Add(boolType);
                prologue.Add(any);
                prologue.Add(condition);
                prologue.Add(negative);
                condition = any;
            }

            uint kill = bound++;
            uint merge = bound++;
            prologue.Add((3u << 16) | Spirv.OpSelectionMerge);
            prologue.Add(merge);
            prologue.Add(0);
            prologue.Add((4u << 16) | Spirv.OpBranchConditional);
            prologue.Add(condition);
            prologue.Add(kill);
            prologue.Add(merge);
            prologue.Add((2u << 16) | Spirv.OpLabel);
            prologue.Add(kill);
            prologue.Add((1u << 16) | Spirv.OpKill);
            prologue.Add((2u << 16) | Spirv.OpLabel);
            prologue.Add(merge);

            int entryLen = (int)(words[entryAt] >> 16);
            if (annotationsEnd < 0)
                annotationsEnd = firstFunction;
            List<uint> result = new List<uint>(count + globals.Count + prologue.Count + annotations.Count + 1);
            for (int i = 0; i < entryAt; i++)
                result.Add(words[i]);
            result.Add(((uint)(entryLen + (created ? 1 : 0)) << 16) | Spirv.OpEntryPoint);
            for (int i = entryAt + 1; i < entryAt + entryLen; i++)
                result.Add(words[i]);
            if (created)
                result.Add(variable);
            for (int i = entryAt + entryLen; i < annotationsEnd; i++)
                result.Add(words[i]);
            result.AddRange(annotations);
            for (int i = annotationsEnd; i < firstFunction; i++)
                result.Add(words[i]);
            result.AddRange(globals);
            for (int i = firstFunction; i < prologueAt; i++)
                result.Add(words[i]);
            result.AddRange(prologue);
            for (int i = prologueAt; i < count; i++)
                result.Add(words[i]);
            result[3] = bound;
            return result.ToArray();
        }

        private static uint Emit(List<uint> section, ref uint bound, int op, params uint[] operands)
        {
            uint id = bound++;
            section.Add(((uint)(operands.Length + 2) << 16) | (uint)op);
            section.Add(id);
            section.AddRange(operands);
            return id;
        }

        private static uint EmitTyped(List<uint> section, ref uint bound, int op, uint type, uint operand)
        {
            uint id = bound++;
            section.Add((4u << 16) | (uint)op);
            section.Add(type);
            section.Add(id);
            section.Add(operand);
            return id;
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
