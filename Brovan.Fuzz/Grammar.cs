// Seeds and dictionary read from the generated tables, so they track vk.xml. Random bytes stop
// at the first length check.

using System.Buffers.Binary;
using System.Text;
using Brovan.Core.Emulation.OS.Windows;

namespace Brovan.Fuzz;

internal sealed class WireWriter
{
    private readonly List<byte> _bytes = new();

    public int Length => _bytes.Count;

    public WireWriter U32(uint v)
    {
        Span<byte> b = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(b, v);
        _bytes.AddRange(b);
        return this;
    }

    public WireWriter U64(ulong v)
    {
        Span<byte> b = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(b, v);
        _bytes.AddRange(b);
        return this;
    }

    public WireWriter Raw(ReadOnlySpan<byte> v) { _bytes.AddRange(v); return this; }

    public WireWriter Zeros(int n) { for (int i = 0; i < n; i++) _bytes.Add(0); return this; }

    public byte[] Done() => _bytes.ToArray();
}

internal static class Grammar
{
    public static int StructCount => BrovVulkStructMeta.Members.Length;

    public static int CommandCount => BrovVulkApi.CommandCount;

    public static IEnumerable<int> PNextAllowedSids()
    {
        for (int sid = 0; sid < BrovVulkStructMeta.PNext.Length; sid++)
            if (BrovVulkStructMeta.PNext[sid])
                yield return sid;
    }

    public static byte[] Struct(int sid, uint arrayLen = 0, int chainDepth = 0)
    {
        WireWriter w = new WireWriter();
        Emit(sid, w, arrayLen, chainDepth, 0, null, 0);
        return w.Done();
    }

    public static byte[] Struct(int sid, IReadOnlyDictionary<int, ulong> set)
    {
        WireWriter w = new WireWriter();
        Emit(sid, w, 0, 0, 0, set, 0);
        return w.Done();
    }

    public static int StructOf(uint sType) => Array.IndexOf(BrovVulkStructMeta.STypes, sType);

    private const int MaxEmitDepth = 6;

    private static void Emit(int sid, WireWriter w, uint arrayLen, int chainDepth, int depth,
                             IReadOnlyDictionary<int, ulong>? set, int at)
    {
        if (sid < 0 || sid >= BrovVulkStructMeta.Members.Length)
            return;

        BvkM[] members = BrovVulkStructMeta.Members[sid];

        // VerifyArrayLen wants the count member and the array to agree.
        HashSet<int> lenOffsets = new();
        foreach (BvkM m in members)
            if (m.LenOffset >= 0)
                lenOffsets.Add(m.LenOffset);

        bool deep = depth < MaxEmitDepth;
        uint Count(int lenOffset) =>
            set != null && set.TryGetValue(at + lenOffset, out ulong v) ? (uint)v : deep ? arrayLen : 0;

        foreach (BvkM d in members)
        {
            switch (d.Kind)
            {
                case BvkMK.Scalar:
                    if (d.Offset == 0 && d.Size == 4 && BrovVulkStructMeta.STypes[sid] != 0)
                        w.U32(BrovVulkStructMeta.STypes[sid]);
                    else if (lenOffsets.Contains(d.Offset) && d.Size == 4)
                        w.U32(Count(d.Offset));
                    else if (lenOffsets.Contains(d.Offset) && d.Size == 8)
                        w.U64(Count(d.Offset));
                    else if (set == null)
                        w.Zeros(d.Size);
                    else
                        w.Raw(Scalar(d.Size, set, at + d.Offset));
                    break;

                case BvkMK.Handle:
                    w.U32(set != null && set.TryGetValue(at + d.Offset, out ulong id) ? (uint)id : 0);
                    break;

                case BvkMK.StructValue:
                    Emit(d.Sub, w, arrayLen, chainDepth, depth + 1, set, at + d.Offset);
                    break;

                case BvkMK.StructPtr:
                    if (deep && d.Sub >= 0) { w.U32(1); Emit(d.Sub, w, arrayLen, chainDepth, depth + 1, null, 0); }
                    else w.U32(0);
                    break;

                case BvkMK.StructArray:
                {
                    uint n = Count(d.LenOffset);
                    w.U32(n);
                    for (uint k = 0; k < n; k++) Emit(d.Sub, w, arrayLen, chainDepth, depth + 1, null, 0);
                    break;
                }

                case BvkMK.HandleArray:
                {
                    uint n = Count(d.LenOffset);
                    w.U32(n);
                    for (uint k = 0; k < n; k++) w.U32(0);
                    break;
                }

                case BvkMK.ScalarArray:
                {
                    uint n = Count(d.LenOffset);
                    w.U32(n);
                    w.Zeros((int)n * Math.Max(d.Size, 1));
                    break;
                }

                case BvkMK.StringZ:
                    w.U32(4).Raw("vk\0\0"u8);
                    break;

                case BvkMK.StringArray:
                {
                    uint n = Count(d.LenOffset);
                    w.U32(n);
                    for (uint k = 0; k < n; k++) w.U32(4).Raw("vk\0\0"u8);
                    break;
                }

                case BvkMK.BlobPtr:
                {
                    uint n = Count(d.LenOffset);
                    w.U32(n);
                    w.Zeros((int)n);
                    break;
                }

                case BvkMK.SelectArray:
                    // The selector is zero, so RebuildAt reads nothing here.
                    break;

                case BvkMK.PNext:
                    if (chainDepth > 0 && deep)
                    {
                        int child = FirstChainable();
                        if (child >= 0)
                        {
                            w.U32(1).U32((uint)child);
                            Emit(child, w, arrayLen, chainDepth - 1, depth + 1, null, 0);
                            break;
                        }
                    }
                    w.U32(0);
                    break;

                case BvkMK.Ignore:
                    break;
            }
        }
    }

    // Pointer-free value structs are flattened into scalar members.
    private static byte[] Scalar(int size, IReadOnlyDictionary<int, ulong> set, int at)
    {
        byte[] bytes = new byte[size];
        foreach ((int offset, ulong value) in set)
        {
            int rel = offset - at;
            if (rel >= 0 && rel < size)
                BitConverter.GetBytes(value).AsSpan(0, Math.Min(value > uint.MaxValue ? 8 : 4, size - rel)).CopyTo(bytes.AsSpan(rel));
        }
        return bytes;
    }

    private static int _chainable = -2;

    private static int FirstChainable()
    {
        if (_chainable != -2)
            return _chainable;

        _chainable = -1;
        for (int sid = 0; sid < BrovVulkStructMeta.PNext.Length; sid++)
        {
            if (!BrovVulkStructMeta.PNext[sid])
                continue;
            bool simple = true;
            foreach (BvkM m in BrovVulkStructMeta.Members[sid])
                if (m.Kind is BvkMK.StructArray or BvkMK.HandleArray or BvkMK.ScalarArray
                           or BvkMK.StringArray or BvkMK.BlobPtr or BvkMK.SelectArray or BvkMK.StructPtr)
                { simple = false; break; }
            if (simple) { _chainable = sid; break; }
        }
        return _chainable;
    }

    public static int CommandId(string name) => Array.IndexOf(BrovVulkApi.CommandNames, name);

    private static readonly string[][] Shapes = Array.ConvertAll(BrovVulkWireShapes.Shapes,
        s => s?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? Array.Empty<string>());

    public static string[] ShapeOf(int command) => Shapes[command];

    public static byte[] Command(int command, Func<string, uint> handle, Func<int, byte[]>? body = null,
                                 Func<string, uint>? count = null, bool pairs = false)
    {
        WireWriter w = new WireWriter();
        foreach (string token in ShapeOf(command))
        {
            string arg = token.Length > 2 && token[1] == ':' ? token[2..] : "";
            switch (token[0])
            {
                case 'h':
                    w.U32(handle(arg));
                    break;
                case 'u':
                    if (token == "u8") w.U64(0); else w.U32(0);
                    break;
                case 'x':
                    w.Zeros(int.Parse(arg));
                    break;
                case 's':
                {
                    int sid = int.Parse(arg);
                    w.U32(1).Raw(body?.Invoke(sid) ?? Struct(sid));
                    break;
                }
                case 'p':
                    if (pairs)
                    {
                        w.U32(1).U32(1);
                        if (arg.Length != 0)
                            w.U32(BrovVulkStructMeta.STypes[int.Parse(arg)]);
                    }
                    else w.U32(0).U32(0);
                    break;
                case 'o':
                {
                    uint n = count?.Invoke(token) ?? 0;
                    w.U32(n);
                    if (arg.StartsWith("g:", StringComparison.Ordinal))
                        for (uint k = 0; k < n; k++) w.U32(BrovVulkGenDispatch.GuestIdBase + k);
                    break;
                }
                case 'c':
                    w.U32(BrovVulkStructMeta.STypes[int.Parse(arg)]).U32(0);
                    break;
                case 'a':
                case 'v':
                case 'V':
                    w.U32(0);
                    break;
            }
        }
        return w.Done();
    }

    public static string? Creates(int command)
    {
        foreach (string token in ShapeOf(command))
        {
            if (token.StartsWith("H:", StringComparison.Ordinal))
                return token[2..];
            if (token.StartsWith("o:", StringComparison.Ordinal))
                return token.StartsWith("o:g:", StringComparison.Ordinal) ? token[4..] : token[2..];
        }
        return null;
    }

    public static string Dictionary()
    {
        StringBuilder sb = new();
        sb.AppendLine("# Generated from BrovVulkStructMeta / BrovVulkApi (source-generated from vk.xml).");
        sb.AppendLine("# Regenerate with:  dotnet run -c Release -- dict <path>");
        sb.AppendLine();

        sb.AppendLine("# --- VkStructureType values, little endian ---");
        HashSet<uint> seen = new();
        foreach (uint st in BrovVulkStructMeta.STypes)
            if (st != 0 && seen.Add(st))
                sb.AppendLine($"stype_{st}=\"{Escape(BitConverter.GetBytes(st))}\"");

        sb.AppendLine();
        sb.AppendLine("# --- struct ids accepted in a pNext slot ---");
        foreach (int sid in PNextAllowedSids())
            sb.AppendLine($"sid_{sid}=\"{Escape(BitConverter.GetBytes((uint)sid))}\"");

        sb.AppendLine();
        sb.AppendLine("# --- boundary scalars ---");
        foreach (uint v in new uint[] { 0, 1, 2, 3, 4, 8, 16, 31, 32, 33, 63, 64, 255, 256, 1023, 1024,
                                        0xFFFF, 0x10000, 1u << 20, (1u << 20) + 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF })
            sb.AppendLine($"u32_{v}=\"{Escape(BitConverter.GetBytes(v))}\"");
        foreach (ulong v in new ulong[] { ulong.MaxValue, 1UL << 30, (1UL << 30) + 1, 1UL << 32, 0x4000_0000UL })
            sb.AppendLine($"u64_{v}=\"{Escape(BitConverter.GetBytes(v))}\"");

        sb.AppendLine();
        sb.AppendLine("# --- BrovVulk framing ---");
        sb.AppendLine($"batch_id=\"{Escape(BitConverter.GetBytes(BrovVulkDevice.BatchId))}\"");
        sb.AppendLine($"posted_batch_id=\"{Escape(BitConverter.GetBytes(BrovVulkGenDispatch.PostedBatchId))}\"");
        sb.AppendLine($"guest_id_base=\"{Escape(BitConverter.GetBytes(BrovVulkGenDispatch.GuestIdBase))}\"");
        for (int id = 0; id < CommandCount; id++)
            if (BrovVulkWireShapes.Shapes[id] != null)
                sb.AppendLine($"cmd_{id}=\"{Escape(BitConverter.GetBytes((uint)id))}\"");

        sb.AppendLine();
        sb.AppendLine($"spirv_magic=\"{Escape(BitConverter.GetBytes(Spirv.Magic))}\"");
        foreach (int op in new[] { Spirv.OpName, Spirv.OpMemoryModel, Spirv.OpEntryPoint, Spirv.OpExecutionMode,
                                   Spirv.OpCapability, Spirv.OpTypeVoid, Spirv.OpTypeBool, Spirv.OpTypeInt,
                                   Spirv.OpTypeFloat, Spirv.OpTypeVector, Spirv.OpTypeMatrix, Spirv.OpTypeArray,
                                   Spirv.OpTypeStruct, Spirv.OpTypePointer, Spirv.OpTypeFunction, Spirv.OpConstant,
                                   Spirv.OpSpecConstant, Spirv.OpFunction, Spirv.OpFunctionEnd, Spirv.OpVariable,
                                   Spirv.OpLoad, Spirv.OpStore, Spirv.OpAccessChain, Spirv.OpDecorate,
                                   Spirv.OpMemberDecorate, Spirv.OpEmitVertex, Spirv.OpLabel, Spirv.OpKill,
                                   Spirv.OpReturn, Spirv.OpDecorateId, Spirv.OpDecorateString })
            for (uint words = 1; words <= 6; words++)
                sb.AppendLine($"spirv_{op}_{words}=\"{Escape(BitConverter.GetBytes((words << 16) | (uint)op))}\"");

        return sb.ToString();
    }

    private static string Escape(byte[] bytes)
    {
        StringBuilder sb = new();
        foreach (byte b in bytes)
            sb.Append(b is >= 0x20 and < 0x7F && b != (byte)'"' && b != (byte)'\\'
                ? ((char)b).ToString()
                : $"\\x{b:x2}");
        return sb.ToString();
    }
}
