using System;
using System.Collections.Generic;
using static Brovan.Core.Emulation.OS.Windows.Spirv;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static unsafe class SpirvBounds
    {
        internal delegate bool BindingInfo(uint set, uint binding, out long count, out int type);

        private static readonly uint[] MemoryOperandBits = { 0x2, 0x8, 0x10, 0x10000, 0x20000 };

        // SPIR-V universal limit for the ID bound.
        private const uint MaxIdBound = 0x3FFFFF;

        private enum Kind { Unknown, Sampler, Combined, Sampled, Storage, UniformTexel, StorageTexel, InputAttachment, UniformBlock, StorageBlock, AccelerationStructure }

        public static uint[]? Bound(uint* words, int count, ReadOnlySpan<byte> entry, uint stage, BindingInfo layout, BrovVulkAddressSpace? addresses,
            HashSet<uint> usedSets, out string? refusal)
        {
            refusal = null;
            if (count < 5 || words[0] != Spirv.Magic)
            {
                refusal = "not a SPIR-V module";
                return null;
            }

            uint guestBound = words[3];
            if (guestBound == 0 || guestBound > MaxIdBound)
            {
                refusal = $"an id bound of {guestBound}";
                return null;
            }

            Dictionary<uint, uint> sets = new Dictionary<uint, uint>();
            Dictionary<uint, uint> bindings = new Dictionary<uint, uint>();
            HashSet<uint> nonUniform = new HashSet<uint>();
            HashSet<uint> blocks = new HashSet<uint>();
            HashSet<uint> bufferBlocks = new HashSet<uint>();
            Dictionary<uint, uint> intWidth = new Dictionary<uint, uint>();
            Dictionary<uint, (uint Element, uint Length)> arrays = new Dictionary<uint, (uint, uint)>();
            Dictionary<uint, uint> runtimeArrays = new Dictionary<uint, uint>();
            Dictionary<uint, (uint Storage, uint Pointee)> pointers = new Dictionary<uint, (uint, uint)>();
            Dictionary<uint, Kind> resourceTypes = new Dictionary<uint, Kind>();
            Dictionary<uint, ulong> constants = new Dictionary<uint, ulong>();
            Dictionary<uint, uint> types = new Dictionary<uint, uint>();
            List<(uint Id, uint PointerType)> variables = new List<(uint, uint)>();
            HashSet<uint> nonSemantic = new HashSet<uint>();
            uint entryFunction = 0;
            bool entryFound = false;
            uint boolType = 0;
            int annotationsEnd = -1, preambleEnd = -1, firstFunction = -1, capabilitiesEnd = 5;
            bool physicalPointers = false, int64 = false;
            Layouts layouts = new Layouts();
            ulong[] typeIds = new ulong[(guestBound + 63) / 64];

            for (int i = 5; i < count;)
            {
                uint head = words[i];
                int len = (int)(head >> 16);
                int op = (int)(head & 0xFFFF);
                if (len == 0 || i + len > count || len < MinimumLength(op))
                {
                    refusal = "a malformed instruction";
                    return null;
                }

                bool typed = len >= 3 && HasId(typeIds, words[i + 1]);
                if (DefinedId(words, i, len, op, typed, firstFunction >= 0) >= guestBound)
                {
                    refusal = "an id at or past the module's id bound";
                    return null;
                }

                if (firstFunction < 0)
                {
                    switch (op)
                    {
                        case OpCapability when len >= 2:
                            uint capability = words[i + 1];
                            if (capability == CapabilityUntypedPointersKHR || capability == CapabilityAddresses)
                            {
                                refusal = "the module uses untyped pointers or kernel addresses";
                                return null;
                            }
                            physicalPointers |= capability == CapabilityPhysicalStorageBufferAddresses;
                            int64 |= capability == CapabilityInt64;
                            capabilitiesEnd = i + len;
                            break;
                        case OpExtInstImport when len >= 3:
                            if (Literal(words, i + 2, len - 2).StartsWith("NonSemantic.Shader.DebugInfo."u8))
                                nonSemantic.Add(words[i + 1]);
                            break;
                        case OpEntryPoint when len >= 4:
                            if (ModelMatches(words[i + 1], stage) && Literal(words, i + 3, len - 3).SequenceEqual(entry))
                            {
                                entryFunction = words[i + 2];
                                entryFound = true;
                            }
                            break;
                        case OpMemoryModel when len >= 3:
                            if (words[i + 1] == AddressingPhysical32 || words[i + 1] == AddressingPhysical64)
                            {
                                refusal = "the module uses physical addressing";
                                return null;
                            }
                            physicalPointers |= words[i + 1] == AddressingPhysicalStorageBuffer64;
                            break;
                        case OpDecorate:
                            uint decoration = words[i + 2];
                            if ((decoration == DecorationDescriptorSet || decoration == DecorationBinding || decoration == DecorationArrayStride) && len < 4)
                            {
                                refusal = "a decoration without its literal";
                                return null;
                            }
                            if (!Decorate(words[i + 1], decoration, len >= 4 ? words[i + 3] : 0, sets, bindings, nonUniform, blocks, bufferBlocks))
                            {
                                refusal = "a descriptor set or binding given twice";
                                return null;
                            }
                            if (decoration == DecorationArrayStride)
                                layouts.Conflict |= !layouts.ArrayStrides.TryAdd(words[i + 1], words[i + 3]);
                            break;
                        case OpMemberDecorate:
                            (uint, uint) member = (words[i + 1], words[i + 2]);
                            if ((words[i + 3] == DecorationOffset || words[i + 3] == DecorationMatrixStride) && len < 5)
                            {
                                refusal = "a decoration without its literal";
                                return null;
                            }
                            if (words[i + 3] == DecorationOffset)
                                layouts.Conflict |= !layouts.Offsets.TryAdd(member, words[i + 4]);
                            else if (words[i + 3] == DecorationMatrixStride)
                                layouts.Conflict |= !layouts.MatrixStrides.TryAdd(member, words[i + 4]);
                            else if (words[i + 3] == DecorationRowMajor || words[i + 3] == DecorationColMajor)
                                layouts.Conflict |= !layouts.Majors.TryAdd(member, words[i + 3] == DecorationRowMajor);
                            break;
                        // Allow only reflection decorations in forms the bounds pass cannot track.
                        case OpDecorateId:
                        case OpDecorateString:
                        case OpMemberDecorateString:
                            uint alternate = words[i + (op == OpMemberDecorateString ? 3 : 2)];
                            if (alternate != DecorationCounterBuffer && alternate != DecorationUserSemantic && alternate != DecorationUserTypeGOOGLE)
                            {
                                refusal = $"decoration {alternate} given through an id or string form";
                                return null;
                            }
                            break;
                        case OpGroupMemberDecorate:
                            layouts.Conflict = true;
                            break;
                        case OpTypeUntypedPointerKHR:
                            refusal = "the module uses untyped pointers";
                            return null;
                        case OpGroupDecorate:
                            for (int w = 2; w < len; w++)
                            {
                                if (!CopyDecorations(words[i + 1], words[i + w], sets, bindings, nonUniform, blocks, bufferBlocks))
                                {
                                    refusal = "a descriptor set or binding given twice";
                                    return null;
                                }
                            }
                            layouts.Conflict = true;
                            break;
                        case OpTypeBool when len >= 2:
                            boolType = words[i + 1];
                            break;
                        case OpTypeInt when len >= 4:
                            intWidth[words[i + 1]] = words[i + 2];
                            layouts.IntSigned[words[i + 1]] = words[i + 3];
                            break;
                        case OpTypeFloat when len >= 3:
                            layouts.FloatWidth[words[i + 1]] = words[i + 2];
                            break;
                        case OpTypeVector when len >= 4:
                            layouts.Vectors[words[i + 1]] = (words[i + 2], words[i + 3]);
                            break;
                        case OpTypeMatrix when len >= 4:
                            layouts.Matrices[words[i + 1]] = (words[i + 2], words[i + 3]);
                            break;
                        case OpTypeStruct when len >= 2:
                            layouts.Structs[words[i + 1]] = new ReadOnlySpan<uint>(words + i + 2, len - 2).ToArray();
                            break;
                        case OpTypeFunction when len >= 3:
                            layouts.FunctionTypes.Add((words[i + 1], words[i + 2], new ReadOnlySpan<uint>(words + i + 3, len - 3).ToArray()));
                            break;
                        case OpTypeImage when len >= 9:
                            uint dim = words[i + 3], sampled = words[i + 7];
                            resourceTypes[words[i + 1]] = dim == DimSubpassData ? Kind.InputAttachment
                                : dim == DimBuffer ? (sampled == 2 ? Kind.StorageTexel : Kind.UniformTexel)
                                : sampled == 2 ? Kind.Storage : sampled == 1 ? Kind.Sampled : Kind.Unknown;
                            break;
                        case OpTypeSampler when len >= 2:
                            resourceTypes[words[i + 1]] = Kind.Sampler;
                            break;
                        case OpTypeSampledImage when len >= 3:
                            resourceTypes[words[i + 1]] = Kind.Combined;
                            break;
                        case OpTypeAccelerationStructureKHR when len >= 2:
                            resourceTypes[words[i + 1]] = Kind.AccelerationStructure;
                            break;
                        case OpTypeArray when len >= 4:
                            arrays[words[i + 1]] = (words[i + 2], words[i + 3]);
                            break;
                        case OpTypeRuntimeArray when len >= 3:
                            runtimeArrays[words[i + 1]] = words[i + 2];
                            break;
                        case OpTypePointer when len >= 4:
                        case OpTypeForwardPointer when len >= 3:
                            uint pointerStorage = words[i + 2];
                            if (pointerStorage == StorageCrossWorkgroup || pointerStorage == StorageGeneric)
                            {
                                refusal = "the module uses kernel pointers";
                                return null;
                            }
                            physicalPointers |= pointerStorage == StoragePhysicalStorageBuffer;
                            if (op == OpTypePointer)
                                pointers[words[i + 1]] = (pointerStorage, words[i + 3]);
                            break;
                        case OpConstant when len >= 4:
                            constants[words[i + 2]] = len >= 5 ? words[i + 3] | ((ulong)words[i + 4] << 32) : words[i + 3];
                            break;
                        case OpVariable when len >= 4:
                            uint storage = words[i + 3];
                            if (storage == StorageUniformConstant || storage == StorageUniform || storage == StorageStorageBuffer)
                                variables.Add((words[i + 2], words[i + 1]));
                            break;
                        case OpFunction:
                            firstFunction = i;
                            break;
                    }

                    if (IsAnnotation(op))
                        annotationsEnd = i + len;
                    else if (preambleEnd < 0 && !IsPreamble(op))
                        preambleEnd = i;
                }
                else if (op == OpVariable && len >= 4 && words[i + 3] != StorageFunction)
                {
                    refusal = "a variable inside a function that is not of Function storage";
                    return null;
                }

                if (IsTypeDeclaration(op) && len >= 2 && firstFunction < 0)
                    typeIds[words[i + 1] >> 6] |= 1UL << (int)(words[i + 1] & 63);
                else if (typed && (firstFunction >= 0 || DeclaresValue(op)))
                    types[words[i + 2]] = words[i + 1];
                i += len;
            }

            if (firstFunction < 0)
                return null;
            if (physicalPointers && (addresses == null || layouts.Conflict))
            {
                refusal = addresses == null ? "the device has no address space for physical storage buffer pointers"
                    : "the module gives a layout decoration twice or through a decoration group";
                return null;
            }
            if (annotationsEnd < 0)
                annotationsEnd = preambleEnd >= 0 ? preambleEnd : firstFunction;
            // Use the entry point's call tree because the interface list can omit accesses.
            HashSet<uint> used = Referenced(words, count, annotationsEnd, variables, entryFound, entryFunction, nonSemantic);

            Dictionary<uint, ulong[]> descriptors = new Dictionary<uint, ulong[]>();
            HashSet<uint> bufferDescriptors = new HashSet<uint>();
            foreach ((uint id, uint pointerType) in variables)
            {
                if (!used.Contains(id))
                    continue;
                if (!pointers.TryGetValue(pointerType, out (uint Storage, uint Pointee) pointer))
                {
                    refusal = "a descriptor variable whose pointer type is not declared";
                    return null;
                }
                if (!sets.TryGetValue(id, out uint set) || !bindings.TryGetValue(id, out uint binding))
                {
                    refusal = "a descriptor variable without a set and binding";
                    return null;
                }
                if (!layout(set, binding, out long declared, out int bindingType) || declared <= 0)
                {
                    refusal = $"set {set} binding {binding} is not in the pipeline layout";
                    return null;
                }

                List<ulong> dims = new List<ulong>();
                bool runtime = false;
                uint type = pointer.Pointee;
                for (int depth = 0; depth < 8; depth++)
                {
                    if (arrays.TryGetValue(type, out (uint Element, uint Length) array))
                    {
                        if (!constants.TryGetValue(array.Length, out ulong length) || length == 0)
                        {
                            refusal = "a descriptor array whose length is not a constant";
                            return null;
                        }
                        dims.Add(length);
                        type = array.Element;
                    }
                    else if (depth == 0 && runtimeArrays.TryGetValue(type, out uint element))
                    {
                        dims.Add(0);
                        runtime = true;
                        type = element;
                    }
                    else
                        break;
                }

                if (arrays.ContainsKey(type) || runtimeArrays.ContainsKey(type))
                {
                    refusal = $"set {set} binding {binding} nests descriptor arrays deeper than this pass bounds";
                    return null;
                }

                if (bindingType == BrovVulkConstants.VK_DESCRIPTOR_TYPE_INLINE_UNIFORM_BLOCK && dims.Count != 0)
                {
                    refusal = $"set {set} binding {binding} is an array of inline uniform blocks";
                    return null;
                }

                Kind kind = resourceTypes.TryGetValue(type, out Kind found) ? found
                    : pointer.Storage == StorageStorageBuffer || bufferBlocks.Contains(type) ? Kind.StorageBlock
                    : pointer.Storage == StorageUniform && blocks.Contains(type) ? Kind.UniformBlock : Kind.Unknown;
                if (!Accepts(bindingType, kind))
                {
                    refusal = $"set {set} binding {binding} is read as a different kind of resource than its descriptors";
                    return null;
                }

                ulong inner = 1;
                for (int k = 1; k < dims.Count; k++)
                    inner = inner > ulong.MaxValue / dims[k] ? ulong.MaxValue : inner * dims[k];
                if (runtime)
                    dims[0] = (ulong)declared / inner;
                ulong total = dims.Count == 0 ? 1 : dims[0] > ulong.MaxValue / inner ? ulong.MaxValue : dims[0] * inner;
                if ((dims.Count != 0 && dims[0] == 0) || total > (ulong)declared)
                {
                    refusal = $"the shader's array at set {set} binding {binding} is larger than the layout's {declared} descriptors";
                    return null;
                }
                descriptors[id] = dims.ToArray();
                if (kind == Kind.UniformBlock || kind == Kind.StorageBlock)
                    bufferDescriptors.Add(id);
                usedSets.Add(set);
            }

            if (descriptors.Count == 0 && !physicalPointers)
                return null;

            uint bound = words[3];
            List<uint> globals = new List<uint>();
            List<uint> decorations = new List<uint>();
            Dictionary<(uint Type, ulong Value), uint> made = new Dictionary<(uint, ulong), uint>();
            List<uint> body = new List<uint>(count - firstFunction + 64);
            List<uint> chain = new List<uint>();
            bool changed = false;
            Resolver? resolver = null;
            if (physicalPointers)
            {
                resolver = new Resolver(addresses!, layouts, types, typeIds, intWidth, arrays, constants, pointers, nonSemantic);
                resolver.Declare(globals, ref bound, ref boolType);
            }

            for (int i = firstFunction; i < count;)
            {
                uint head = words[i];
                int len = (int)(head >> 16);
                int op = (int)(head & 0xFFFF);

                // An OpPhi back edge can name a pointer this pass has yet to see.
                if (op == OpPhi && len >= 3 && pointers.TryGetValue(words[i + 1], out (uint Storage, uint Pointee) chosen)
                    && (chosen.Storage == StorageUniformConstant || chosen.Storage == StorageUniform || chosen.Storage == StorageStorageBuffer)
                    && (arrays.ContainsKey(chosen.Pointee) || runtimeArrays.ContainsKey(chosen.Pointee)))
                {
                    refusal = "a phi of a pointer to an array in descriptor memory";
                    return null;
                }

                if (EscapesBounds(words, i, len, op, descriptors))
                {
                    refusal = "a descriptor pointer is used other than through an access chain, a load or a texel pointer";
                    return null;
                }

                // IDs at or above guestBound can name injected code that returns host addresses.
                if (op == OpFunctionCall)
                {
                    for (int w = 3; w < len; w++)
                    {
                        if (words[i + w] >= guestBound)
                        {
                            refusal = "a call that names an id past the module's id bound";
                            return null;
                        }
                    }
                }

                if ((op == OpBitcast || op == OpConvertUToPtr || op == OpConvertPtrToU) && len >= 4
                    && (IsLogicalPointer(words[i + 1], pointers) || (types.TryGetValue(words[i + 3], out uint from) && IsLogicalPointer(from, pointers))))
                {
                    refusal = "a pointer other than a physical storage buffer pointer converted to or from a value";
                    return null;
                }

                if (resolver != null)
                {
                    if (resolver.TryAccess(words, i, len, op, body, globals, made, ref bound, out refusal))
                    {
                        changed = true;
                        i += len;
                        continue;
                    }
                    if (refusal != null)
                        return null;
                }

                if ((op == OpAccessChain || op == OpInBoundsAccessChain) && len >= 4 && descriptors.TryGetValue(words[i + 3], out ulong[]? dims))
                {
                    chain.Clear();
                    chain.AddRange(new ReadOnlySpan<uint>(words + i, len));
                    int indices = len - 4;
                    // Robust buffer access covers buffer members beyond the descriptor indices.
                    if (indices > dims.Length && !bufferDescriptors.Contains(words[i + 3]))
                    {
                        refusal = "an access chain that indexes past a descriptor that is not a buffer";
                        return null;
                    }
                    for (int k = 0; k < dims.Length && k < indices; k++)
                    {
                        uint index = words[i + 4 + k];
                        if (constants.TryGetValue(index, out ulong value))
                        {
                            if (value >= dims[k])
                            {
                                refusal = $"a constant descriptor index {value} past the array's {dims[k]}";
                                return null;
                            }
                            continue;
                        }
                        if (!types.TryGetValue(index, out uint indexType) || !intWidth.TryGetValue(indexType, out uint width) || (width != 32 && width != 64))
                        {
                            refusal = "a descriptor index of a type this pass cannot clamp";
                            return null;
                        }

                        if (boolType == 0)
                        {
                            boolType = bound++;
                            Emit(globals, OpTypeBool, boolType);
                        }
                        uint length = Constant(globals, made, ref bound, indexType, width, dims[k]);
                        uint last = Constant(globals, made, ref bound, indexType, width, dims[k] - 1);
                        uint inRange = bound++;
                        uint clamped = bound++;
                        Emit(body, OpULessThan, boolType, inRange, index, length);
                        Emit(body, OpSelect, indexType, clamped, inRange, index, last);
                        chain[4 + k] = clamped;
                        if (nonUniform.Contains(index))
                            Emit(decorations, OpDecorate, clamped, DecorationNonUniform);
                        changed = true;
                    }
                    if (indices <= dims.Length)
                    {
                        descriptors[words[i + 2]] = dims.AsSpan(indices).ToArray();
                        if (bufferDescriptors.Contains(words[i + 3]))
                            bufferDescriptors.Add(words[i + 2]);
                    }
                    body.AddRange(chain);
                }
                else
                {
                    for (int w = 0; w < len; w++)
                        body.Add(words[i + w]);
                }
                i += len;
            }

            if (!changed)
                return null;
            resolver?.Finish(body, globals, made, ref bound);

            List<uint> result = new List<uint>(count + globals.Count + decorations.Count + (body.Count - (count - firstFunction)) + 2);
            for (int i = 0; i < capabilitiesEnd; i++)
                result.Add(words[i]);
            if (resolver != null && !int64)
                Emit(result, OpCapability, CapabilityInt64);
            for (int i = capabilitiesEnd; i < annotationsEnd; i++)
                result.Add(words[i]);
            result.AddRange(decorations);
            for (int i = annotationsEnd; i < firstFunction; i++)
                result.Add(words[i]);
            result.AddRange(globals);
            result.AddRange(body);
            result[3] = bound;
            return result.ToArray();
        }

        // Conflicting decorations can make the driver and the bounds pass use different bindings.
        private static bool Decorate(uint target, uint decoration, uint value, Dictionary<uint, uint> sets, Dictionary<uint, uint> bindings,
            HashSet<uint> nonUniform, HashSet<uint> blocks, HashSet<uint> bufferBlocks)
        {
            if (decoration == DecorationDescriptorSet)
                return SetOnce(sets, target, value);
            if (decoration == DecorationBinding)
                return SetOnce(bindings, target, value);
            if (decoration == DecorationNonUniform)
                nonUniform.Add(target);
            else if (decoration == DecorationBlock)
                blocks.Add(target);
            else if (decoration == DecorationBufferBlock)
                bufferBlocks.Add(target);
            return true;
        }

        private static bool CopyDecorations(uint group, uint target, Dictionary<uint, uint> sets, Dictionary<uint, uint> bindings,
            HashSet<uint> nonUniform, HashSet<uint> blocks, HashSet<uint> bufferBlocks)
        {
            if (sets.TryGetValue(group, out uint set) && !SetOnce(sets, target, set))
                return false;
            if (bindings.TryGetValue(group, out uint binding) && !SetOnce(bindings, target, binding))
                return false;
            if (nonUniform.Contains(group))
                nonUniform.Add(target);
            if (blocks.Contains(group))
                blocks.Add(target);
            if (bufferBlocks.Contains(group))
                bufferBlocks.Add(target);
            return true;
        }

        private static bool SetOnce(Dictionary<uint, uint> values, uint target, uint value)
            => values.TryAdd(target, value) || values[target] == value;

        private static bool Accepts(int bindingType, Kind kind) => bindingType switch
        {
            BrovVulkConstants.VK_DESCRIPTOR_TYPE_SAMPLER => kind == Kind.Sampler,
            BrovVulkConstants.VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER => kind == Kind.Combined || kind == Kind.Sampled || kind == Kind.Sampler,
            BrovVulkConstants.VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE => kind == Kind.Sampled,
            BrovVulkConstants.VK_DESCRIPTOR_TYPE_STORAGE_IMAGE => kind == Kind.Storage,
            BrovVulkConstants.VK_DESCRIPTOR_TYPE_UNIFORM_TEXEL_BUFFER => kind == Kind.UniformTexel,
            BrovVulkConstants.VK_DESCRIPTOR_TYPE_STORAGE_TEXEL_BUFFER => kind == Kind.StorageTexel,
            BrovVulkConstants.VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER or BrovVulkConstants.VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC
                or BrovVulkConstants.VK_DESCRIPTOR_TYPE_INLINE_UNIFORM_BLOCK => kind == Kind.UniformBlock,
            BrovVulkConstants.VK_DESCRIPTOR_TYPE_STORAGE_BUFFER or BrovVulkConstants.VK_DESCRIPTOR_TYPE_STORAGE_BUFFER_DYNAMIC => kind == Kind.StorageBlock,
            BrovVulkConstants.VK_DESCRIPTOR_TYPE_INPUT_ATTACHMENT => kind == Kind.InputAttachment,
            BrovVulkConstants.VK_DESCRIPTOR_TYPE_SAMPLE_WEIGHT_IMAGE_QCOM or BrovVulkConstants.VK_DESCRIPTOR_TYPE_BLOCK_MATCH_IMAGE_QCOM => kind == Kind.Sampled,
            BrovVulkConstants.VK_DESCRIPTOR_TYPE_ACCELERATION_STRUCTURE_KHR => kind == Kind.AccelerationStructure,
            _ => false,
        };

        private sealed class FunctionUse
        {
            public readonly HashSet<uint> Variables = new HashSet<uint>();
            public readonly List<uint> Calls = new List<uint>();
        }

        // Drivers discard non-semantic instructions.
        private static HashSet<uint> Referenced(uint* words, int count, int start, List<(uint Id, uint PointerType)> variables, bool entryFound,
            uint entryFunction, HashSet<uint> nonSemantic)
        {
            if (variables.Count == 0)
                return new HashSet<uint>();

            HashSet<uint> candidates = new HashSet<uint>();
            foreach ((uint id, uint _) in variables)
                candidates.Add(id);

            HashSet<uint> used = new HashSet<uint>();
            Dictionary<uint, FunctionUse> functions = new Dictionary<uint, FunctionUse>();
            FunctionUse? current = null;
            for (int i = start; i < count;)
            {
                int len = (int)(words[i] >> 16);
                int op = (int)(words[i] & 0xFFFF);
                if (op == OpFunction && len >= 3)
                    functions[words[i + 2]] = current = new FunctionUse();
                else if (op == OpFunctionEnd)
                    current = null;
                else if (op == OpFunctionCall && len >= 4 && current != null)
                    current.Calls.Add(words[i + 3]);

                if (op != OpExtInst || len < 4 || !nonSemantic.Contains(words[i + 3]))
                {
                    HashSet<uint> into = current?.Variables ?? used;
                    for (int w = 1; w < len; w++)
                    {
                        if ((op != OpVariable || w != 2) && !IsLiteral(op, w) && candidates.Contains(words[i + w]))
                            into.Add(words[i + w]);
                    }
                }
                i += len;
            }

            Stack<uint> pending = new Stack<uint>();
            if (entryFound && functions.ContainsKey(entryFunction))
                pending.Push(entryFunction);
            else
            {
                foreach (uint function in functions.Keys)
                    pending.Push(function);
            }
            HashSet<uint> seen = new HashSet<uint>();
            while (pending.Count != 0)
            {
                uint function = pending.Pop();
                if (!seen.Add(function) || !functions.TryGetValue(function, out FunctionUse? use))
                    continue;
                used.UnionWith(use.Variables);
                foreach (uint callee in use.Calls)
                    pending.Push(callee);
            }
            return used;
        }

        private static bool IsLiteral(int op, int w) => op switch
        {
            OpTypeInt or OpTypeFloat or OpLine or OpSelectionMerge => w >= 2,
            OpTypePointer or OpTypeForwardPointer => w == 2,
            OpTypeVector or OpTypeMatrix or OpTypeImage or OpConstant or OpSpecConstant or OpConstantSampler or OpLoopMerge or OpSwitch
                or OpStore or OpCopyMemory => w >= 3,
            OpSpecConstantOp or OpVariable or OpFunction => w == 3,
            OpExtInst => w == 4,
            OpLoad or OpCompositeExtract or OpCopyMemorySized => w >= 4,
            OpCompositeInsert or OpVectorShuffle => w >= 5,
            _ => false,
        };

        private static bool ModelMatches(uint model, uint stage) => stage switch
        {
            (uint)BrovVulkConstants.VK_SHADER_STAGE_VERTEX_BIT => model == ModelVertex,
            (uint)BrovVulkConstants.VK_SHADER_STAGE_TESSELLATION_CONTROL_BIT => model == ModelTessellationControl,
            (uint)BrovVulkConstants.VK_SHADER_STAGE_TESSELLATION_EVALUATION_BIT => model == ModelTessellationEvaluation,
            (uint)BrovVulkConstants.VK_SHADER_STAGE_GEOMETRY_BIT => model == ModelGeometry,
            (uint)BrovVulkConstants.VK_SHADER_STAGE_FRAGMENT_BIT => model == ModelFragment,
            (uint)BrovVulkConstants.VK_SHADER_STAGE_COMPUTE_BIT => model == ModelGLCompute,
            (uint)BrovVulkConstants.VK_SHADER_STAGE_TASK_BIT_EXT => model == ModelTaskNV || model == ModelTaskEXT,
            (uint)BrovVulkConstants.VK_SHADER_STAGE_MESH_BIT_EXT => model == ModelMeshNV || model == ModelMeshEXT,
            _ => false,
        };

        private static ReadOnlySpan<byte> Literal(uint* words, int at, int available)
        {
            ReadOnlySpan<byte> bytes = new ReadOnlySpan<byte>(words + at, available * 4);
            int end = bytes.IndexOf((byte)0);
            return end < 0 ? bytes : bytes.Slice(0, end);
        }

        private static uint Constant(List<uint> globals, Dictionary<(uint, ulong), uint> made, ref uint bound, uint type, uint width, ulong value)
        {
            if (made.TryGetValue((type, value), out uint id))
                return id;

            id = bound++;
            made[(type, value)] = id;
            if (width == 64)
                Emit(globals, OpConstant, type, id, (uint)value, (uint)(value >> 32));
            else
                Emit(globals, OpConstant, type, id, (uint)value);
            return id;
        }

        private static bool EscapesBounds(uint* words, int i, int len, int op, Dictionary<uint, ulong[]> descriptors)
        {
            int from, to, step = 1;
            switch (op)
            {
                case OpStore:
                case OpCopyMemory:
                case OpCopyMemorySized:
                case OpAtomicStore:
                case OpCooperativeMatrixStoreKHR:
                    from = 1;
                    to = Math.Min(len - 1, 2);
                    break;
                case OpFunctionCall:
                    from = 4;
                    to = len - 1;
                    break;
                case OpReturnValue:
                    from = 1;
                    to = Math.Min(len - 1, 1);
                    break;
                case OpSelect:
                    from = 4;
                    to = Math.Min(len - 1, 5);
                    break;
                case OpPhi:
                    from = 3;
                    to = len - 1;
                    step = 2;
                    break;
                case OpPtrAccessChain:
                case OpInBoundsPtrAccessChain:
                case OpCopyObject:
                case OpBitcast:
                case OpConvertPtrToU:
                case OpCooperativeMatrixLoadKHR:
                    from = 3;
                    to = Math.Min(len - 1, 3);
                    break;
                case OpArrayLength:
                case OpImageTexelPointer:
                    return len >= 4 && descriptors.TryGetValue(words[i + 3], out ulong[]? left) && left.Length != 0;
                default:
                    if (op >= OpPtrEqual && op <= OpPtrDiff)
                    {
                        from = 3;
                        to = Math.Min(len - 1, 4);
                        break;
                    }
                    if (op >= 227 && op <= 242 && op != OpAtomicStore)
                    {
                        from = 3;
                        to = Math.Min(len - 1, 3);
                        break;
                    }
                    return false;
            }

            for (int w = from; w <= to; w += step)
            {
                if (descriptors.ContainsKey(words[i + w]))
                    return true;
            }
            return false;
        }

        private static readonly byte[] MinimumLengths = BuildMinimumLengths();

        private static byte[] BuildMinimumLengths()
        {
            byte[] lengths = new byte[0x10000];
            for (int op = 0; op < lengths.Length; op++)
                lengths[op] = (byte)MinimumLengthOf(op);
            return lengths;
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        private static int MinimumLength(int op) => MinimumLengths[op & 0xFFFF];

        private static int MinimumLengthOf(int op) => op switch
        {
            OpCapability or OpTypeBool or OpTypeStruct or OpTypeSampler or OpTypeAccelerationStructureKHR or OpDecorationGroup
                or OpGroupDecorate or OpGroupMemberDecorate or OpLabel or OpReturnValue => 2,
            OpExtInstImport or OpMemoryModel or OpDecorate or OpDecorateId or OpTypeFloat or OpTypeFunction or OpTypeSampledImage
                or OpTypeRuntimeArray or OpTypeForwardPointer or OpString or OpStore or OpCopyMemory or OpPhi => 3,
            OpEntryPoint or OpMemberDecorate or OpDecorateString or OpTypeInt or OpTypeVector or OpTypeMatrix or OpTypeArray
                or OpTypePointer or OpConstant or OpVariable or OpFunctionCall or OpAccessChain or OpInBoundsAccessChain or OpLoad
                or OpCopyMemorySized or OpBitcast or OpConvertPtrToU or OpConvertUToPtr or OpCopyObject or OpAtomicFlagClear => 4,
            OpMemberDecorateString or OpFunction or OpPtrAccessChain or OpInBoundsPtrAccessChain or OpArrayLength or OpExtInst
                or OpAtomicStore => 5,
            OpImageTexelPointer or OpSelect or OpAtomicFlagTestAndSet or 227 or 232 or 233 => 6,
            OpAtomicFMinEXT or OpAtomicFMaxEXT or OpAtomicFAddEXT or 229 or (>= 234 and <= 242) => 7,
            OpTypeImage or 230 or 231 => 9,
            _ => 1,
        };

        // Debug and annotation operands can look like typed result IDs.
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        private static uint DefinedId(uint* words, int i, int len, int op, bool typed, bool inFunctions)
        {
            if (typed && inFunctions)
                return words[i + 2];
            if (len < 2)
                return 0;
            if (IsTypeDeclaration(op) || op == OpLabel || op == OpString || op == OpExtInstImport || op == OpDecorationGroup)
                return words[i + 1];
            return typed && !IsPreamble(op) && !IsAnnotation(op) ? words[i + 2] : 0;
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        private static bool HasId(ulong[] ids, uint id) => id >> 6 < (uint)ids.Length && (ids[id >> 6] & (1UL << (int)(id & 63))) != 0;

        private static bool IsPreamble(int op) => op is OpSourceContinued or OpSource or OpSourceExtension or OpName or OpMemberName or OpString
            or OpLine or OpExtension or OpExtInstImport or OpMemoryModel or OpEntryPoint or OpExecutionMode or OpCapability or OpNoLine
            or OpModuleProcessed or OpExecutionModeId;

        private static bool IsAnnotation(int op) => op is OpDecorate or OpMemberDecorate or OpDecorationGroup or OpGroupDecorate
            or OpGroupMemberDecorate or OpDecorateId or OpDecorateString or OpMemberDecorateString;

        private static bool IsLogicalPointer(uint type, Dictionary<uint, (uint Storage, uint Pointee)> pointers) =>
            pointers.TryGetValue(type, out (uint Storage, uint Pointee) pointer) && pointer.Storage != StoragePhysicalStorageBuffer;

        private static bool IsTypeDeclaration(int op) => (op >= 19 && op <= 38) || op == 322 || op == 327 || op == 4456 || op == 4472
            || op == OpTypeAccelerationStructureKHR || op == 5358;

        private static bool DeclaresValue(int op) => op == 1 || (op >= 41 && op <= 52) || op == OpVariable;

        private sealed class Layouts
        {
            public readonly Dictionary<uint, uint> IntSigned = new Dictionary<uint, uint>();
            public readonly Dictionary<uint, uint> FloatWidth = new Dictionary<uint, uint>();
            public readonly Dictionary<uint, (uint Component, uint Count)> Vectors = new Dictionary<uint, (uint, uint)>();
            public readonly Dictionary<uint, (uint Column, uint Count)> Matrices = new Dictionary<uint, (uint, uint)>();
            public readonly Dictionary<uint, uint[]> Structs = new Dictionary<uint, uint[]>();
            public readonly Dictionary<uint, uint> ArrayStrides = new Dictionary<uint, uint>();
            public readonly Dictionary<(uint Struct, uint Member), uint> Offsets = new Dictionary<(uint, uint), uint>();
            public readonly Dictionary<(uint Struct, uint Member), uint> MatrixStrides = new Dictionary<(uint, uint), uint>();
            public readonly Dictionary<(uint Struct, uint Member), bool> Majors = new Dictionary<(uint, uint), bool>();
            public bool Conflict;
            public readonly List<(uint Id, uint Return, uint[] Parameters)> FunctionTypes = new List<(uint, uint, uint[])>();
        }

        // Resolve pointers only at memory accesses. Stored pointers remain guest addresses.
        private sealed class Resolver
        {
            private readonly BrovVulkAddressSpace _space;
            private readonly Layouts _layouts;
            private readonly Dictionary<uint, uint> _types;
            private readonly ulong[] _typeIds;
            private readonly Dictionary<uint, uint> _intWidth;
            private readonly Dictionary<uint, (uint Element, uint Length)> _arrays;
            private readonly Dictionary<uint, ulong> _constants;
            private readonly Dictionary<uint, (uint Storage, uint Pointee)> _pointers;
            private readonly HashSet<uint> _nonSemantic;
            private readonly HashSet<uint> _psbPointerTypes = new HashSet<uint>();
            private readonly List<uint> _instruction = new List<uint>();
            private uint _u64, _bool, _pointer, _functionType, _function;
            private bool _used;

            public Resolver(BrovVulkAddressSpace space, Layouts layouts, Dictionary<uint, uint> types, ulong[] typeIds, Dictionary<uint, uint> intWidth,
                Dictionary<uint, (uint Element, uint Length)> arrays, Dictionary<uint, ulong> constants, Dictionary<uint, (uint Storage, uint Pointee)> pointers,
                HashSet<uint> nonSemantic)
            {
                _space = space;
                _layouts = layouts;
                _types = types;
                _typeIds = typeIds;
                _intWidth = intWidth;
                _arrays = arrays;
                _constants = constants;
                _pointers = pointers;
                _nonSemantic = nonSemantic;
                foreach (KeyValuePair<uint, (uint Storage, uint Pointee)> pointer in pointers)
                {
                    if (pointer.Value.Storage == StoragePhysicalStorageBuffer)
                        _psbPointerTypes.Add(pointer.Key);
                }
            }

            public void Declare(List<uint> globals, ref uint bound, ref uint boolType)
            {
                foreach (KeyValuePair<uint, uint> width in _intWidth)
                {
                    if (width.Value == 64 && _layouts.IntSigned.TryGetValue(width.Key, out uint signed) && signed == 0)
                        _u64 = width.Key;
                }
                if (_u64 == 0)
                {
                    _u64 = bound++;
                    Emit(globals, OpTypeInt, _u64, 64u, 0u);
                }
                if (boolType == 0)
                {
                    boolType = bound++;
                    Emit(globals, OpTypeBool, boolType);
                }
                _bool = boolType;
                foreach (KeyValuePair<uint, (uint Storage, uint Pointee)> pointer in _pointers)
                {
                    if (pointer.Value.Storage == StoragePhysicalStorageBuffer && pointer.Value.Pointee == _u64)
                        _pointer = pointer.Key;
                }
                if (_pointer == 0)
                {
                    _pointer = bound++;
                    Emit(globals, OpTypePointer, _pointer, StoragePhysicalStorageBuffer, _u64);
                }
                foreach ((uint id, uint result, uint[] parameters) in _layouts.FunctionTypes)
                {
                    if (result == _u64 && parameters.Length == 2 && parameters[0] == _u64 && parameters[1] == _u64)
                        _functionType = id;
                }
                if (_functionType == 0)
                {
                    _functionType = bound++;
                    Emit(globals, OpTypeFunction, _functionType, _u64, _u64, _u64);
                }
                _function = bound++;
            }

            private bool IsPsb(uint id) => _types.TryGetValue(id, out uint type) && _psbPointerTypes.Contains(type);

            public bool TryAccess(uint* words, int i, int len, int op, List<uint> body, List<uint> globals, Dictionary<(uint, ulong), uint> made,
                ref uint bound, out string? refusal)
            {
                refusal = null;
                int pointerAt, secondAt = -1, memoryAt = -1;
                switch (op)
                {
                    case OpLoad:
                        pointerAt = 3;
                        memoryAt = 4;
                        break;
                    case OpStore:
                        pointerAt = 1;
                        memoryAt = 3;
                        break;
                    case OpCopyMemory:
                        pointerAt = 1;
                        secondAt = 2;
                        memoryAt = 3;
                        break;
                    case OpCopyMemorySized:
                        pointerAt = 1;
                        secondAt = 2;
                        memoryAt = 4;
                        break;
                    case OpAtomicStore:
                    case OpAtomicFlagClear:
                        pointerAt = 1;
                        break;
                    default:
                        if (IsAtomic(op))
                        {
                            pointerAt = 3;
                            break;
                        }
                        if (Escapes(words, i, len, op))
                            refusal = "a physical storage buffer pointer is used by an instruction this pass cannot bound";
                        return false;
                }

                if (len <= pointerAt || !_types.ContainsKey(words[i + pointerAt]) || (secondAt > 0 && (len <= secondAt || !_types.ContainsKey(words[i + secondAt]))))
                {
                    refusal = "an access through a pointer of unknown type";
                    return false;
                }
                bool first = IsPsb(words[i + pointerAt]);
                bool second = secondAt > 0 && IsPsb(words[i + secondAt]);
                if (!first && !second)
                    return false;

                uint scalar;
                ulong bytes;
                uint pointee = _pointers[_types[words[i + (first ? pointerAt : secondAt)]]].Pointee;
                if (HoldsMatrix(pointee))
                {
                    refusal = "a matrix accessed through a physical storage buffer pointer";
                    return false;
                }
                if (op == OpCopyMemorySized)
                {
                    if (len < 4 || !_constants.TryGetValue(words[i + 3], out bytes))
                    {
                        refusal = "a copy through a physical storage buffer pointer whose size is not a constant";
                        return false;
                    }
                    scalar = 1;
                }
                else if (!TrySize(pointee, 0, out bytes, out scalar))
                {
                    refusal = "an access through a physical storage buffer pointer to a type without an explicit layout";
                    return false;
                }
                // The driver copies each member using the layout of its own side.
                if (op == OpCopyMemory && _pointers[_types[words[i + 1]]].Pointee != _pointers[_types[words[i + 2]]].Pointee)
                {
                    refusal = "a copy between pointers to different types";
                    return false;
                }
                if (pointerAt == 3 || op == OpAtomicStore || op == OpAtomicFlagClear)
                {
                    if (op != OpLoad && (!AtomicWidth(words, i, len, op, out uint width) || width != bytes || width != scalar))
                    {
                        refusal = "an atomic whose width differs from the type it points to";
                        return false;
                    }
                }
                if (bytes == 0 || bytes > BrovVulkAddressSpace.SinkBytes)
                {
                    refusal = $"an access of {bytes} bytes through a physical storage buffer pointer";
                    return false;
                }

                List<uint> instruction = _instruction;
                instruction.Clear();
                instruction.AddRange(new ReadOnlySpan<uint>(words + i, len));
                if (first)
                    instruction[pointerAt] = Resolve(words[i + pointerAt], bytes, scalar, body, globals, made, ref bound);
                if (second)
                    instruction[secondAt] = Resolve(words[i + secondAt], bytes, scalar, body, globals, made, ref bound);
                if (memoryAt > 0)
                {
                    int next = Align(instruction, memoryAt, scalar);
                    if (op == OpCopyMemory && next < instruction.Count)
                        Align(instruction, next, scalar);
                }
                instruction[0] = ((uint)instruction.Count << 16) | (uint)op;
                body.AddRange(instruction);
                _used = true;
                return true;
            }

            // Matrix stride and order come from the enclosing struct member.
            private bool HoldsMatrix(uint type)
            {
                for (int depth = 0; depth < 8 && _arrays.TryGetValue(type, out (uint Element, uint Length) array); depth++)
                    type = array.Element;
                return _layouts.Matrices.ContainsKey(type);
            }

            private bool AtomicWidth(uint* words, int i, int len, int op, out uint width)
            {
                width = 0;
                if (op == OpAtomicFlagTestAndSet || op == OpAtomicFlagClear)
                {
                    width = 4;
                    return true;
                }
                uint type = op == OpAtomicStore ? (len >= 5 && _types.TryGetValue(words[i + 4], out uint stored) ? stored : 0) : words[i + 1];
                if (!_intWidth.TryGetValue(type, out uint bits) && !_layouts.FloatWidth.TryGetValue(type, out bits))
                    return false;
                width = bits / 8;
                return true;
            }

            private static bool IsAtomic(int op) => (op >= 227 && op <= 242) || op == OpAtomicFlagTestAndSet || op == OpAtomicFMinEXT
                || op == OpAtomicFMaxEXT || op == OpAtomicFAddEXT;

            private bool Escapes(uint* words, int i, int len, int op)
            {
                switch (op)
                {
                    case OpFunctionCall:
                    case OpVariable:
                    case OpLoad:
                    case OpStore:
                    case OpAccessChain:
                    case OpInBoundsAccessChain:
                    case OpPtrAccessChain:
                    case OpInBoundsPtrAccessChain:
                    case OpCompositeConstruct:
                    case OpCompositeExtract:
                    case OpCompositeInsert:
                    case OpCopyObject:
                    case OpConvertPtrToU:
                    case OpBitcast:
                    case OpSelect:
                    case OpPhi:
                    case OpReturnValue:
                    case OpCopyLogical:
                    case OpPtrEqual:
                    case OpPtrNotEqual:
                    case OpPtrDiff:
                        return false;
                }
                if (op == OpExtInst && len >= 4 && _nonSemantic.Contains(words[i + 3]))
                    return false;
                for (int w = len >= 3 && HasId(_typeIds, words[i + 1]) ? 3 : 1; w < len; w++)
                {
                    if (IsPsb(words[i + w]))
                        return true;
                }
                return false;
            }

            private uint Resolve(uint pointer, ulong bytes, uint scalar, List<uint> body, List<uint> globals, Dictionary<(uint, ulong), uint> made, ref uint bound)
            {
                uint address = bound++;
                Emit(body, OpConvertPtrToU, _u64, address, pointer);
                if (scalar > 1)
                {
                    uint masked = bound++;
                    Emit(body, OpBitwiseAnd, _u64, masked, address, Constant(globals, made, ref bound, _u64, 64, ~(ulong)(scalar - 1)));
                    address = masked;
                }
                uint host = bound++;
                Emit(body, OpFunctionCall, _u64, host, _function, address, Constant(globals, made, ref bound, _u64, 64, bytes));
                uint result = bound++;
                Emit(body, OpConvertUToPtr, _types[pointer], result, host);
                return result;
            }

            private static int Align(List<uint> instruction, int at, uint scalar)
            {
                if (at >= instruction.Count)
                {
                    instruction.Add(MemoryAligned);
                    instruction.Add(scalar);
                    return instruction.Count;
                }
                uint mask = instruction[at];
                if ((mask & MemoryAligned) != 0)
                    instruction[at + 1] = scalar;
                else
                {
                    instruction[at] = mask | MemoryAligned;
                    instruction.Insert(at + 1, scalar);
                }
                int operands = 0;
                foreach (uint bit in MemoryOperandBits)
                    operands += (instruction[at] & bit) != 0 ? 1 : 0;
                return at + 1 + operands;
            }

            private bool TrySize(uint type, int depth, out ulong bytes, out uint scalar)
            {
                bytes = 0;
                scalar = 1;
                if (depth > 16)
                    return false;
                if (_intWidth.TryGetValue(type, out uint width) || _layouts.FloatWidth.TryGetValue(type, out width))
                {
                    if (width == 0 || width % 8 != 0 || width > 64)
                        return false;
                    bytes = scalar = width / 8;
                    return true;
                }
                if (_pointers.TryGetValue(type, out (uint Storage, uint Pointee) pointer))
                {
                    bytes = scalar = 8;
                    return pointer.Storage == StoragePhysicalStorageBuffer;
                }
                if (_layouts.Vectors.TryGetValue(type, out (uint Component, uint Count) vector))
                {
                    if (!TrySize(vector.Component, depth + 1, out ulong component, out scalar))
                        return false;
                    bytes = component * vector.Count;
                    return true;
                }
                if (_layouts.Matrices.TryGetValue(type, out (uint Column, uint Count) _))
                {
                    bytes = MatrixFootprint(type, depth, out scalar);
                    return bytes != 0;
                }
                if (_arrays.TryGetValue(type, out (uint Element, uint Length) array))
                {
                    if (!_layouts.ArrayStrides.TryGetValue(type, out uint arrayStride) || !_constants.TryGetValue(array.Length, out ulong length)
                        || length == 0 || length > uint.MaxValue || !TrySize(array.Element, depth + 1, out ulong element, out scalar))
                        return false;
                    bytes = (length - 1) * arrayStride + element;
                    return true;
                }
                if (_layouts.Structs.TryGetValue(type, out uint[]? members))
                {
                    for (uint k = 0; k < (uint)members.Length; k++)
                    {
                        if (!_layouts.Offsets.TryGetValue((type, k), out uint offset))
                            return false;
                        ulong member;
                        uint memberScalar;
                        if (_layouts.Matrices.ContainsKey(members[k]))
                        {
                            if (!_layouts.MatrixStrides.TryGetValue((type, k), out uint memberStride))
                                return false;
                            member = Footprint(members[k], memberStride, _layouts.Majors.TryGetValue((type, k), out bool rowMajor) && rowMajor, depth, out memberScalar);
                            if (member == 0)
                                return false;
                        }
                        else if (!TrySize(members[k], depth + 1, out member, out memberScalar))
                            return false;
                        bytes = Math.Max(bytes, offset + member);
                        scalar = Math.Max(scalar, memberScalar);
                    }
                    return members.Length != 0;
                }
                return false;
            }

            // Use the largest footprint because a pointer may have lost its original layout.
            private ulong MatrixFootprint(uint matrix, int depth, out uint scalar)
            {
                ulong bytes = 0;
                scalar = 1;
                foreach (KeyValuePair<(uint Struct, uint Member), uint> entry in _layouts.MatrixStrides)
                {
                    if (!_layouts.Structs.TryGetValue(entry.Key.Struct, out uint[]? members) || entry.Key.Member >= (uint)members.Length)
                        continue;
                    uint held = members[entry.Key.Member];
                    for (int k = 0; k < 8 && _arrays.TryGetValue(held, out (uint Element, uint Length) array); k++)
                        held = array.Element;
                    if (held != matrix)
                        continue;
                    ulong footprint = Footprint(matrix, entry.Value, _layouts.Majors.TryGetValue(entry.Key, out bool rowMajor) && rowMajor, depth, out uint component);
                    if (footprint == 0)
                        return 0;
                    bytes = Math.Max(bytes, footprint);
                    scalar = component;
                }
                return bytes;
            }

            private ulong Footprint(uint matrix, uint stride, bool rowMajor, int depth, out uint scalar)
            {
                scalar = 1;
                if (stride == 0 || !_layouts.Matrices.TryGetValue(matrix, out (uint Column, uint Count) shape)
                    || !_layouts.Vectors.TryGetValue(shape.Column, out (uint Component, uint Count) column)
                    || !TrySize(column.Component, depth + 1, out ulong component, out scalar))
                    return 0;
                ulong columns = shape.Count, rows = column.Count;
                return rowMajor ? (rows - 1) * stride + columns * component : (columns - 1) * stride + rows * component;
            }

            // Emit bvk_resolve. Empty slots route to the sink through the zero leaf and record.
            public void Finish(List<uint> body, List<uint> globals, Dictionary<(uint, ulong), uint> made, ref uint bound)
            {
                if (!_used)
                    return;

                uint C(ulong value, ref uint b) => Constant(globals, made, ref b, _u64, 64, value);
                uint cBase = C(BrovVulkAddressSpace.Base, ref bound), cLeafShift = C(BrovVulkAddressSpace.LeafShift, ref bound);
                uint cTopCount = C(_space.TopCount, ref bound), cZero = C(0, ref bound), cEight = C(8, ref bound);
                uint cTop = C(_space.TopAddress, ref bound), cZeroLeaf = C(_space.ZeroLeafAddress, ref bound);
                uint cGranuleShift = C(BrovVulkAddressSpace.GranuleShift, ref bound), cSlotMask = C(BrovVulkAddressSpace.SlotMask, ref bound);
                uint cSixteen = C(16, ref bound), cSink = C(_space.SinkAddress, ref bound);

                uint a = bound++, n = bound++, label = bound++;
                Emit(body, OpFunction, _u64, _function, 0u, _functionType);
                Emit(body, OpFunctionParameter, _u64, a);
                Emit(body, OpFunctionParameter, _u64, n);
                Emit(body, OpLabel, label);

                uint Op(int code, uint type, uint x, uint y, List<uint> into, ref uint b)
                {
                    uint id = b++;
                    Emit(into, code, type, id, x, y);
                    return id;
                }
                uint Load(uint address, List<uint> into, ref uint b)
                {
                    uint pointer = b++, value = b++;
                    Emit(into, OpConvertUToPtr, _pointer, pointer, address);
                    Emit(into, OpLoad, _u64, value, pointer, MemoryAligned, 8u);
                    return value;
                }
                uint Select(uint condition, uint x, uint y, List<uint> into, ref uint b)
                {
                    uint id = b++;
                    Emit(into, OpSelect, _u64, id, condition, x, y);
                    return id;
                }

                uint relative = Op(OpISub, _u64, a, cBase, body, ref bound);
                uint top = Op(OpShiftRightLogical, _u64, relative, cLeafShift, body, ref bound);
                uint inRange = Op(OpULessThan, _bool, top, cTopCount, body, ref bound);
                uint topIndex = Select(inRange, top, cZero, body, ref bound);
                uint topSlot = Op(OpIAdd, _u64, cTop, Op(OpIMul, _u64, topIndex, cEight, body, ref bound), body, ref bound);
                uint leaf = Select(inRange, Load(topSlot, body, ref bound), cZeroLeaf, body, ref bound);
                uint slot = Op(OpBitwiseAnd, _u64, Op(OpShiftRightLogical, _u64, relative, cGranuleShift, body, ref bound), cSlotMask, body, ref bound);
                uint record = Load(Op(OpIAdd, _u64, leaf, Op(OpIMul, _u64, slot, cEight, body, ref bound), body, ref bound), body, ref bound);
                uint guest = Load(record, body, ref bound);
                uint hostBase = Load(Op(OpIAdd, _u64, record, cEight, body, ref bound), body, ref bound);
                uint size = Load(Op(OpIAdd, _u64, record, cSixteen, body, ref bound), body, ref bound);
                uint offset = Op(OpISub, _u64, a, guest, body, ref bound);
                uint after = Op(OpUGreaterThanEqual, _bool, a, guest, body, ref bound);
                uint inside = Op(OpULessThanEqual, _bool, offset, size, body, ref bound);
                uint fits = Op(OpULessThanEqual, _bool, n, Op(OpISub, _u64, size, offset, body, ref bound), body, ref bound);
                uint ok = Op(OpLogicalAnd, _bool, Op(OpLogicalAnd, _bool, after, inside, body, ref bound), fits, body, ref bound);
                uint result = Select(ok, Op(OpIAdd, _u64, hostBase, offset, body, ref bound), cSink, body, ref bound);
                Emit(body, OpReturnValue, result);
                Emit(body, OpFunctionEnd);
            }
        }
    }
}
