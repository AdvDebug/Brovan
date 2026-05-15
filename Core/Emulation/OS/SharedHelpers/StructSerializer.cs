using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS
{
    public enum PointerContentType { UnicodeString, AsciiString, ByteArray, Struct }

    [AttributeUsage(AttributeTargets.Field)]
    public class EmulatedPointerAttribute : Attribute
    {
        public PointerContentType ContentType { get; set; }
        public EmulatedPointerAttribute(PointerContentType ContentType) => this.ContentType = ContentType;
    }

    [AttributeUsage(AttributeTargets.Field)]
    public class EmulatedInlineAttribute : Attribute
    {
        public int Size { get; }
        public bool Ascii { get; set; }
        public EmulatedInlineAttribute(int Size) => this.Size = Size;
    }

    public enum WriteStructError
    {
        None, NullDestination, DestinationNotMapped, PointerAllocationFailed,
        PointerDestinationNotMapped, UnsupportedFieldType, InvalidStructLayout,
        RecursionDepthExceeded, StringAllocationFailed
    }

    public sealed class WriteStructResult
    {
        public static readonly WriteStructResult Ok = new(true, WriteStructError.None, null);
        public bool Success { get; }
        public WriteStructError Error { get; }
        public string Detail { get; }

        private WriteStructResult(bool Success, WriteStructError Error, string Detail)
        {
            this.Success = Success;
            this.Error = Error;
            this.Detail = Detail;
        }

        public static WriteStructResult Fail(WriteStructError Error, string Detail = null) => new(false, Error, Detail);

        public override string ToString() => Success ? "OK" : $"FAIL({Error}){(Detail != null ? ": " + Detail : "")}";
    }

    public static class StructSerializer
    {
        private const int MaxDepth = 4;

        // Cached per-field metadata, built once, reused on every call.
        private sealed class FieldDesc
        {
            public readonly FieldInfo Field;
            public readonly EmulatedPointerAttribute PtrAttr;
            public readonly EmulatedInlineAttribute InlineAttr;
            public readonly int Offset;
            public readonly bool HasOffset;

            public FieldDesc(FieldInfo F)
            {
                Field = F;
                PtrAttr = F.GetCustomAttribute<EmulatedPointerAttribute>();
                InlineAttr = F.GetCustomAttribute<EmulatedInlineAttribute>();
                FieldOffsetAttribute Off = F.GetCustomAttribute<FieldOffsetAttribute>();
                HasOffset = Off != null;
                Offset = Off?.Value ?? -1;
            }
        }

        // Cached per-type metadata (fields, layout, and pre-computed sizes for x86 + x64)
        private sealed class TypeDesc
        {
            public readonly FieldDesc[] Fields;
            public readonly bool IsExplicit;
            public readonly int Size32;
            public readonly int Size64;

            public TypeDesc(Type T)
            {
                FieldInfo[] Raw = T.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
                bool Expl = T.GetCustomAttribute<StructLayoutAttribute>()?.Value == LayoutKind.Explicit;

                Fields = Array.ConvertAll(Raw, F => new FieldDesc(F));

                if (!Expl)
                    foreach (FieldDesc D in Fields) { if (D.HasOffset) { Expl = true; break; } }

                if (Expl)
                    Array.Sort(Fields, (A, B) => A.Offset.CompareTo(B.Offset));

                IsExplicit = Expl;
                Size32 = ComputeSize(Fields, Expl, false);
                Size64 = ComputeSize(Fields, Expl, true);
            }

            private static int ComputeSize(FieldDesc[] Fields, bool IsExplicit, bool Is64)
            {
                if (IsExplicit)
                {
                    int Max = 0;
                    foreach (FieldDesc D in Fields)
                        Max = Math.Max(Max, (D.HasOffset ? D.Offset : 0) + FieldSize(D, Is64));
                    return Max;
                }
                int Total = 0;
                foreach (FieldDesc D in Fields) Total += FieldSize(D, Is64);
                return Total;
            }

            public static int FieldSize(FieldDesc D, bool Is64)
            {
                Type Ft = D.Field.FieldType;

                if (Ft.IsArray)
                {
                    if (D.InlineAttr == null)
                        return Is64 ? 8 : 4;

                    Type Et = Ft.GetElementType();

                    if (Et == typeof(byte) || Et == typeof(sbyte))
                        return D.InlineAttr.Size;

                    int ElemSize = GetElementSize(Et, Is64);
                    return ElemSize <= 0 ? 0 : ElemSize * D.InlineAttr.Size;
                }

                return GetElementSize(Ft, Is64);
            }

            internal static int GetElementSize(Type Ft, bool Is64)
            {
                if (Ft.IsEnum)
                    Ft = Enum.GetUnderlyingType(Ft);

                if (Ft == typeof(bool) || Ft == typeof(byte) || Ft == typeof(sbyte)) return 1;
                if (Ft == typeof(ushort) || Ft == typeof(short)) return 2;
                if (Ft == typeof(uint) || Ft == typeof(int) || Ft == typeof(float)) return 4;
                if (Ft == typeof(ulong) || Ft == typeof(long) || Ft == typeof(double)) return 8;

                if (Ft == typeof(string) || Ft == typeof(byte[]))
                    return Is64 ? 8 : 4;

                if (Ft.IsValueType && !Ft.IsPrimitive)
                    return Is64 ? GetDesc(Ft).Size64 : GetDesc(Ft).Size32;

                return 0;
            }
        }

        private static readonly Dictionary<Type, TypeDesc> Cache = new();

        private static TypeDesc GetDesc(Type T)
        {
            if (Cache.TryGetValue(T, out TypeDesc D)) return D;
            return Cache[T] = new TypeDesc(T);
        }

        // --- Public API ---

        /// <summary>
        /// Get a struct size.
        /// </summary>
        /// <typeparam name="T">Struct</typeparam>
        /// <param name="Emulator">The emulator instance to determine architecture.</param>
        /// <returns>return the size.</returns>
        public static uint GetStructSize<T>(BinaryEmulator Emulator) where T : struct
        {
            bool Is64 = Emulator._binary.Architecture == BinaryArchitecture.x64;
            return (uint)GetStructSize(typeof(T), Is64);
        }

        /// <summary>
        /// Get a struct size.
        /// </summary>
        /// <typeparam name="T">Struct</typeparam>
        /// <param name="Is64">An indicator whether the architecture is x64.</param>
        /// <returns>return the size.</returns>
        public static int GetStructSize<T>(bool Is64) where T : struct
        {
            return GetStructSize(typeof(T), Is64);
        }

        private static int GetStructSize(Type T, bool Is64)
        {
            TypeDesc Desc = GetDesc(T);
            return Is64 ? Desc.Size64 : Desc.Size32;
        }

        private static void WriteZeroes(BinaryWriter Bw, int Count)
        {
            for (int I = 0; I < Count; I++)
                Bw.Write((byte)0);
        }

        /// <summary>
        /// Serializes <paramref name="Value"/> into emulated memory at <paramref name="Address"/>.
        /// </summary>
        /// <param name="Emulator">The emulator instance to write into.</param>
        /// <param name="Address">The emulated address to write the struct to.</param>
        /// <param name="Value">The struct value to serialize.</param>
        /// <returns>Returns <see cref="WriteStructResult.Ok"/> on success, otherwise a failure result describing the error.</returns>
        public static WriteStructResult WriteStruct<T>(BinaryEmulator Emulator, ulong Address, T Value) where T : struct
        {
            if (Address == 0)
                return WriteStructResult.Fail(WriteStructError.NullDestination, $"Destination address is NULL for {typeof(T).Name}");

            bool Is64 = Emulator._binary.Architecture == BinaryArchitecture.x64;

            using MemoryStream Ms = new();
            using BinaryWriter Bw = new(Ms, Encoding.Unicode, leaveOpen: true);

            WriteStructResult R = BuildFields(Emulator, Bw, Value, 0, Is64);
            if (!R.Success) return R;

            Bw.Flush();
            byte[] Bytes = Ms.ToArray();

            if (!Emulator.IsRegionMapped(Address, (ulong)Bytes.Length))
                return WriteStructResult.Fail(WriteStructError.DestinationNotMapped, $"{typeof(T).Name} (0x{Bytes.Length:X} bytes) at 0x{Address:X} is not fully mapped");
            if (!Emulator.WriteMemory(Address, Bytes))
                return WriteStructResult.Fail(WriteStructError.DestinationNotMapped, $"WriteMemory failed for {typeof(T).Name} at 0x{Address:X}");

            return WriteStructResult.Ok;
        }

        /// <summary>
        /// Deserializes a struct of type <typeparamref name="T"/> from emulated memory at <paramref name="Address"/>.
        /// </summary>
        /// <param name="Emulator">The emulator instance to read from.</param>
        /// <param name="Address">The emulated address to read the struct from.</param>
        /// <param name="Value">The deserialized struct value on success.</param>
        /// <returns>Returns true if successful, otherwise false.</returns>
        public static bool ParseStruct<T>(BinaryEmulator Emulator, ulong Address, out T Value) where T : struct
        {
            Value = default;
            if (Address == 0) return false;

            bool Is64 = Emulator._binary.Architecture == BinaryArchitecture.x64;
            TypeDesc Desc = GetDesc(typeof(T));
            int Size = Is64 ? Desc.Size64 : Desc.Size32;
            if (Size <= 0) return false;

            byte[] Raw = Emulator.ReadMemory(Address, (uint)Size);
            if (Raw == null || Raw.Length != Size) return false;

            object Boxed = Value;
            if (!ReadFields(Emulator, Raw, 0, ref Boxed, 0, Is64)) return false;

            Value = (T)Boxed;
            return true;
        }

        /// <summary>
        /// Deserializes a struct of type <typeparamref name="T"/> from a byte array directly./>.
        /// </summary>
        /// <param name="Emulator">The emulator instance to read from.</param>
        /// <param name="Data">The data to deserialize the struct.</param>
        /// <param name="Value">The deserialized struct value on success.</param>
        /// <returns>Returns true if successful, otherwise false.</returns>
        /// <remarks>
        /// This is mostly used in the fuzzing, this is never used in the emulator itself.
        /// </remarks>
        public static bool ParseStruct<T>(BinaryEmulator Emulator, byte[] Data, out T Value) where T : struct
        {
            Value = default;

            bool Is64 = Emulator._binary.Architecture == BinaryArchitecture.x64;
            TypeDesc Desc = GetDesc(typeof(T));
            int Size = Is64 ? Desc.Size64 : Desc.Size32;

            if (Data == null || Data.Length != Size) return false;

            if (Size <= 0) return false;

            object Boxed = Value;
            if (!ReadFields(Emulator, Data, 0, ref Boxed, 0, Is64)) return false;

            Value = (T)Boxed;
            return true;
        }

        // --- Private workers ---

        private static WriteStructResult BuildFields(BinaryEmulator Emulator, BinaryWriter Bw, object Value, int Depth, bool Is64)
        {
            if (Depth > MaxDepth)
                return WriteStructResult.Fail(WriteStructError.RecursionDepthExceeded, $"Recursion depth exceeded at depth {Depth}");

            Type T = Value.GetType();
            TypeDesc Desc = GetDesc(T);
            long Start = Bw.BaseStream.Position;

            foreach (FieldDesc D in Desc.Fields)
            {
                object FieldVal = D.Field.GetValue(Value);
                Type Ft = D.Field.FieldType;

                if (Desc.IsExplicit || D.HasOffset)
                {
                    long Target = Start + D.Offset;
                    if (Target < Bw.BaseStream.Position)
                        return WriteStructResult.Fail(WriteStructError.InvalidStructLayout, $"Field {D.Field.Name} in {T.Name}: offset 0x{D.Offset:X} is behind write cursor");
                    while (Bw.BaseStream.Position < Target) Bw.Write((byte)0);
                }

                if (FieldVal == null)
                    continue;

                if (Ft == typeof(bool)) { Bw.Write((byte)((bool)FieldVal ? 1 : 0)); continue; }
                if (Ft == typeof(byte)) { Bw.Write((byte)FieldVal); continue; }
                if (Ft == typeof(sbyte)) { Bw.Write((sbyte)FieldVal); continue; }
                if (Ft == typeof(ushort)) { Bw.Write((ushort)FieldVal); continue; }
                if (Ft == typeof(short)) { Bw.Write((short)FieldVal); continue; }
                if (Ft == typeof(uint)) { Bw.Write((uint)FieldVal); continue; }
                if (Ft == typeof(int)) { Bw.Write((int)FieldVal); continue; }
                if (Ft == typeof(float)) { Bw.Write((float)FieldVal); continue; }
                if (Ft == typeof(ulong)) { Bw.Write((ulong)FieldVal); continue; }
                if (Ft == typeof(long)) { Bw.Write((long)FieldVal); continue; }
                if (Ft == typeof(double)) { Bw.Write((double)FieldVal); continue; }

                if (Ft.IsEnum)
                {
                    Type U = Enum.GetUnderlyingType(Ft);
                    object C = Convert.ChangeType(FieldVal, U);
                    if (C != null)
                    {
                        if (U == typeof(byte)) { Bw.Write((byte)C); continue; }
                        if (U == typeof(sbyte)) { Bw.Write((sbyte)C); continue; }
                        if (U == typeof(ushort)) { Bw.Write((ushort)C); continue; }
                        if (U == typeof(short)) { Bw.Write((short)C); continue; }
                        if (U == typeof(uint)) { Bw.Write((uint)C); continue; }
                        if (U == typeof(int)) { Bw.Write((int)C); continue; }
                        if (U == typeof(ulong)) { Bw.Write((ulong)C); continue; }
                        if (U == typeof(long)) { Bw.Write((long)C); continue; }
                    }
                    return WriteStructResult.Fail(WriteStructError.UnsupportedFieldType, $"Enum {Ft.Name} has unknown underlying type {U.Name}");
                }

                if (Ft.IsArray)
                {
                    Type Et = Ft.GetElementType();

                    if (D.InlineAttr != null)
                    {
                        Array Arr = FieldVal as Array;

                        if (Et == typeof(byte))
                        {
                            byte[] Inline = new byte[D.InlineAttr.Size];
                            if (FieldVal is byte[] Src && Src.Length > 0)
                                Buffer.BlockCopy(Src, 0, Inline, 0, Math.Min(Src.Length, D.InlineAttr.Size));
                            Bw.Write(Inline);
                            continue;
                        }

                        int ElemSize = TypeDesc.GetElementSize(Et, Is64);
                        if (ElemSize <= 0)
                            return WriteStructResult.Fail(WriteStructError.UnsupportedFieldType, $"Inline array field {D.Field.Name} has unsupported element type {Et?.FullName}");

                        int Count = D.InlineAttr.Size;

                        for (int I = 0; I < Count; I++)
                        {
                            object ElemVal = Arr != null && I < Arr.Length ? Arr.GetValue(I) : null;

                            if (ElemVal == null)
                            {
                                WriteZeroes(Bw, ElemSize);
                                continue;
                            }

                            if (Et.IsValueType && !Et.IsPrimitive && !Et.IsEnum)
                            {
                                using MemoryStream SubMs = new();
                                using BinaryWriter SubBw = new(SubMs, Encoding.Unicode, leaveOpen: true);

                                WriteStructResult Inner = BuildFields(Emulator, SubBw, ElemVal, Depth + 1, Is64);
                                if (!Inner.Success) return Inner;

                                SubBw.Flush();
                                byte[] SubBytes = SubMs.ToArray();

                                if (SubBytes.Length != ElemSize)
                                    return WriteStructResult.Fail(WriteStructError.InvalidStructLayout, $"Inline array field {D.Field.Name}[{I}] serialized to 0x{SubBytes.Length:X} bytes, expected 0x{ElemSize:X}");

                                Bw.Write(SubBytes);
                                continue;
                            }

                            Type WriteType = Et.IsEnum ? Enum.GetUnderlyingType(Et) : Et;
                            object WriteVal = Et.IsEnum ? Convert.ChangeType(ElemVal, WriteType) : ElemVal;

                            if (WriteType == typeof(bool)) { Bw.Write((byte)((bool)WriteVal ? 1 : 0)); continue; }
                            if (WriteType == typeof(byte)) { Bw.Write((byte)WriteVal); continue; }
                            if (WriteType == typeof(sbyte)) { Bw.Write((sbyte)WriteVal); continue; }
                            if (WriteType == typeof(ushort)) { Bw.Write((ushort)WriteVal); continue; }
                            if (WriteType == typeof(short)) { Bw.Write((short)WriteVal); continue; }
                            if (WriteType == typeof(uint)) { Bw.Write((uint)WriteVal); continue; }
                            if (WriteType == typeof(int)) { Bw.Write((int)WriteVal); continue; }
                            if (WriteType == typeof(float)) { Bw.Write((float)WriteVal); continue; }
                            if (WriteType == typeof(ulong)) { Bw.Write((ulong)WriteVal); continue; }
                            if (WriteType == typeof(long)) { Bw.Write((long)WriteVal); continue; }
                            if (WriteType == typeof(double)) { Bw.Write((double)WriteVal); continue; }

                            return WriteStructResult.Fail(WriteStructError.UnsupportedFieldType, $"Inline array field {D.Field.Name} has unsupported element type {Et.FullName}");
                        }

                        continue;
                    }

                    ulong Ptr = 0;

                    if (Et == typeof(byte))
                    {
                        if (FieldVal is byte[] RawB && RawB.Length > 0)
                        {
                            Ptr = Emulator.MapUniqueAddress((ulong)RawB.Length, MemoryProtection.ReadWrite);
                            if (Ptr == 0) return WriteStructResult.Fail(WriteStructError.PointerAllocationFailed, $"AllocateMemory failed for byte[] field {D.Field.Name}");
                            if (!Emulator.WriteMemory(Ptr, RawB)) return WriteStructResult.Fail(WriteStructError.PointerDestinationNotMapped, $"WriteMemory failed for byte[] field {D.Field.Name} at 0x{Ptr:X}");
                        }

                        if (Is64) Bw.Write(Ptr); else Bw.Write((uint)Ptr);
                        continue;
                    }

                    return WriteStructResult.Fail(WriteStructError.UnsupportedFieldType, $"Array field {D.Field.Name} requires [EmulatedInline] or explicit pointer handling");
                }

                if (Ft == typeof(string))
                {
                    if (D.InlineAttr != null)
                    {
                        Encoding Enc = D.InlineAttr.Ascii ? Encoding.ASCII : Encoding.Unicode;
                        byte[] Enc2 = FieldVal is string S ? Enc.GetBytes(S) : Array.Empty<byte>();
                        byte[] Inline = new byte[D.InlineAttr.Size];
                        Buffer.BlockCopy(Enc2, 0, Inline, 0, Math.Min(Enc2.Length, D.InlineAttr.Size));
                        Bw.Write(Inline);
                        continue;
                    }
                    ulong StrPtr = 0;
                    if (D.PtrAttr != null && FieldVal is string Str)
                    {
                        Encoding Enc = D.PtrAttr.ContentType == PointerContentType.AsciiString ? Encoding.ASCII : Encoding.Unicode;
                        byte[] Enc2 = Enc.GetBytes(Str);
                        byte[] Full = new byte[Enc2.Length + (Enc == Encoding.ASCII ? 1 : 2)];
                        Buffer.BlockCopy(Enc2, 0, Full, 0, Enc2.Length);
                        StrPtr = Emulator.MapUniqueAddress((ulong)Full.Length, MemoryProtection.ReadWrite);
                        if (StrPtr == 0) return WriteStructResult.Fail(WriteStructError.StringAllocationFailed, $"AllocateMemory failed for string field {D.Field.Name}");
                        if (!Emulator.WriteMemory(StrPtr, Full)) return WriteStructResult.Fail(WriteStructError.PointerDestinationNotMapped, $"WriteMemory failed for string field {D.Field.Name} at 0x{StrPtr:X}");
                    }
                    if (Is64) Bw.Write(StrPtr); else Bw.Write((uint)StrPtr);
                    continue;
                }

                if (Ft == typeof(byte[]))
                {
                    if (D.InlineAttr != null)
                    {
                        byte[] Inline = new byte[D.InlineAttr.Size];
                        if (FieldVal is byte[] Src && Src.Length > 0)
                            Buffer.BlockCopy(Src, 0, Inline, 0, Math.Min(Src.Length, D.InlineAttr.Size));
                        Bw.Write(Inline);
                        continue;
                    }
                    ulong BytePtr = 0;
                    if (FieldVal is byte[] RawB && RawB.Length > 0)
                    {
                        BytePtr = Emulator.MapUniqueAddress((ulong)RawB.Length, MemoryProtection.ReadWrite);
                        if (BytePtr == 0) return WriteStructResult.Fail(WriteStructError.PointerAllocationFailed, $"AllocateMemory failed for byte[] field {D.Field.Name}");
                        if (!Emulator.WriteMemory(BytePtr, RawB)) return WriteStructResult.Fail(WriteStructError.PointerDestinationNotMapped, $"WriteMemory failed for byte[] field {D.Field.Name} at 0x{BytePtr:X}");
                    }
                    if (Is64) Bw.Write(BytePtr); else Bw.Write((uint)BytePtr);
                    continue;
                }

                if (Ft.IsValueType && !Ft.IsPrimitive)
                {
                    if (D.PtrAttr != null && D.PtrAttr.ContentType == PointerContentType.Struct)
                    {
                        using MemoryStream SubMs = new();
                        using BinaryWriter SubBw = new(SubMs, Encoding.Unicode, leaveOpen: true);
                        WriteStructResult Inner = BuildFields(Emulator, SubBw, FieldVal, Depth + 1, Is64);
                        if (!Inner.Success) return Inner;
                        SubBw.Flush();
                        byte[] SubBytes = SubMs.ToArray();
                        ulong Ptr = Emulator.MapUniqueAddress((ulong)SubBytes.Length, MemoryProtection.ReadWrite);
                        if (Ptr == 0) return WriteStructResult.Fail(WriteStructError.PointerAllocationFailed, $"AllocateMemory failed for struct pointer field {D.Field.Name}");
                        if (!Emulator.IsRegionMapped(Ptr, (ulong)SubBytes.Length)) return WriteStructResult.Fail(WriteStructError.PointerDestinationNotMapped, $"Allocated region 0x{Ptr:X} for {Ft.Name} is not mapped");
                        if (!Emulator.WriteMemory(Ptr, SubBytes)) return WriteStructResult.Fail(WriteStructError.PointerDestinationNotMapped, $"WriteMemory failed for struct pointer field {D.Field.Name} at 0x{Ptr:X}");
                        if (Is64) Bw.Write(Ptr); else Bw.Write((uint)Ptr);
                    }
                    else
                    {
                        WriteStructResult Inner = BuildFields(Emulator, Bw, FieldVal, Depth + 1, Is64);
                        if (!Inner.Success) return Inner;
                    }
                    continue;
                }

                return WriteStructResult.Fail(WriteStructError.UnsupportedFieldType, $"Field {D.Field.Name} has unsupported type {Ft.FullName}");
            }

            if (Desc.IsExplicit)
            {
                long End = Start + (Is64 ? Desc.Size64 : Desc.Size32);
                while (Bw.BaseStream.Position < End) Bw.Write((byte)0);
            }

            return WriteStructResult.Ok;
        }

        private static bool ReadFields(BinaryEmulator Emulator, byte[] Raw, int Base, ref object Value, int Depth, bool Is64)
        {
            if (Depth > MaxDepth) return false;

            Type T = Value.GetType();
            TypeDesc Desc = GetDesc(T);
            int Cursor = Base;

            foreach (FieldDesc D in Desc.Fields)
            {
                Type Ft = D.Field.FieldType;
                int Off = (Desc.IsExplicit || D.HasOffset) ? Base + D.Offset : Cursor;

                if (Ft == typeof(bool)) { D.Field.SetValue(Value, Raw[Off] != 0); Cursor = Off + 1; continue; }
                if (Ft == typeof(byte)) { D.Field.SetValue(Value, Raw[Off]); Cursor = Off + 1; continue; }
                if (Ft == typeof(sbyte)) { D.Field.SetValue(Value, (sbyte)Raw[Off]); Cursor = Off + 1; continue; }
                if (Ft == typeof(ushort)) { D.Field.SetValue(Value, BitConverter.ToUInt16(Raw, Off)); Cursor = Off + 2; continue; }
                if (Ft == typeof(short)) { D.Field.SetValue(Value, BitConverter.ToInt16(Raw, Off)); Cursor = Off + 2; continue; }
                if (Ft == typeof(uint)) { D.Field.SetValue(Value, BitConverter.ToUInt32(Raw, Off)); Cursor = Off + 4; continue; }
                if (Ft == typeof(int)) { D.Field.SetValue(Value, BitConverter.ToInt32(Raw, Off)); Cursor = Off + 4; continue; }
                if (Ft == typeof(float)) { D.Field.SetValue(Value, BitConverter.ToSingle(Raw, Off)); Cursor = Off + 4; continue; }
                if (Ft == typeof(ulong)) { D.Field.SetValue(Value, BitConverter.ToUInt64(Raw, Off)); Cursor = Off + 8; continue; }
                if (Ft == typeof(long)) { D.Field.SetValue(Value, BitConverter.ToInt64(Raw, Off)); Cursor = Off + 8; continue; }
                if (Ft == typeof(double)) { D.Field.SetValue(Value, BitConverter.ToDouble(Raw, Off)); Cursor = Off + 8; continue; }

                if (Ft.IsEnum)
                {
                    Type U = Enum.GetUnderlyingType(Ft);
                    ulong W = U == typeof(byte) || U == typeof(sbyte) ? 1UL
                            : U == typeof(short) || U == typeof(ushort) ? 2UL
                            : U == typeof(int) || U == typeof(uint) ? 4UL
                            : U == typeof(long) || U == typeof(ulong) ? 8UL : 0UL;
                    if (W == 0) return false;
                    ulong V = W == 1 ? Raw[Off]
                            : W == 2 ? BitConverter.ToUInt16(Raw, Off)
                            : W == 4 ? BitConverter.ToUInt32(Raw, Off)
                                     : BitConverter.ToUInt64(Raw, Off);
                    D.Field.SetValue(Value, Enum.ToObject(Ft, Convert.ChangeType(V, U)));
                    Cursor = (int)(Off + (int)W);
                    continue;
                }

                if (Ft == typeof(string))
                {
                    if (D.InlineAttr != null)
                    {
                        Encoding Enc = D.InlineAttr.Ascii ? Encoding.ASCII : Encoding.Unicode;
                        int Len = D.InlineAttr.Size;
                        int Step = D.InlineAttr.Ascii ? 1 : 2;
                        while (Len >= Step && Raw[Off + Len - Step] == 0 && (Step == 1 || Raw[Off + Len - Step + 1] == 0))
                            Len -= Step;
                        D.Field.SetValue(Value, Enc.GetString(Raw, Off, Len));
                        Cursor = Off + D.InlineAttr.Size;
                        continue;
                    }
                    int PtrSz = Is64 ? 8 : 4;
                    ulong StrP = Is64 ? BitConverter.ToUInt64(Raw, Off) : BitConverter.ToUInt32(Raw, Off);
                    D.Field.SetValue(Value, D.PtrAttr != null && StrP != 0 ? ReadNullTerminatedString(Emulator, StrP, D.PtrAttr.ContentType == PointerContentType.AsciiString ? Encoding.ASCII : Encoding.Unicode) : null);
                    Cursor = Off + PtrSz;
                    continue;
                }

                if (Ft.IsArray)
                {
                    Type Et = Ft.GetElementType();

                    if (D.InlineAttr != null)
                    {
                        if (Et == typeof(byte))
                        {
                            byte[] Inline = new byte[D.InlineAttr.Size];
                            Buffer.BlockCopy(Raw, Off, Inline, 0, D.InlineAttr.Size);
                            D.Field.SetValue(Value, Inline);
                            Cursor = Off + D.InlineAttr.Size;
                            continue;
                        }

                        int ElemSize = TypeDesc.GetElementSize(Et, Is64);
                        if (ElemSize <= 0) return false;

                        int Count = D.InlineAttr.Size;
                        Array Arr = Array.CreateInstance(Et, Count);

                        for (int I = 0; I < Count; I++)
                        {
                            int ElemOff = Off + (I * ElemSize);

                            if (Et.IsValueType && !Et.IsPrimitive && !Et.IsEnum)
                            {
                                object Elem = Activator.CreateInstance(Et);
                                if (!ReadFields(Emulator, Raw, ElemOff, ref Elem, Depth + 1, Is64)) return false;
                                Arr.SetValue(Elem, I);
                                continue;
                            }

                            if (Et.IsEnum)
                            {
                                Type U = Enum.GetUnderlyingType(Et);
                                object Elem =
                                    U == typeof(byte) ? Raw[ElemOff] :
                                    U == typeof(sbyte) ? (sbyte)Raw[ElemOff] :
                                    U == typeof(ushort) ? BitConverter.ToUInt16(Raw, ElemOff) :
                                    U == typeof(short) ? BitConverter.ToInt16(Raw, ElemOff) :
                                    U == typeof(uint) ? BitConverter.ToUInt32(Raw, ElemOff) :
                                    U == typeof(int) ? BitConverter.ToInt32(Raw, ElemOff) :
                                    U == typeof(ulong) ? BitConverter.ToUInt64(Raw, ElemOff) :
                                    U == typeof(long) ? BitConverter.ToInt64(Raw, ElemOff) :
                                    null;

                                if (Elem == null) return false;
                                Arr.SetValue(Enum.ToObject(Et, Elem), I);
                                continue;
                            }

                            object Prim =
                                Et == typeof(bool) ? Raw[ElemOff] != 0 :
                                Et == typeof(byte) ? Raw[ElemOff] :
                                Et == typeof(sbyte) ? (sbyte)Raw[ElemOff] :
                                Et == typeof(ushort) ? BitConverter.ToUInt16(Raw, ElemOff) :
                                Et == typeof(short) ? BitConverter.ToInt16(Raw, ElemOff) :
                                Et == typeof(uint) ? BitConverter.ToUInt32(Raw, ElemOff) :
                                Et == typeof(int) ? BitConverter.ToInt32(Raw, ElemOff) :
                                Et == typeof(float) ? BitConverter.ToSingle(Raw, ElemOff) :
                                Et == typeof(ulong) ? BitConverter.ToUInt64(Raw, ElemOff) :
                                Et == typeof(long) ? BitConverter.ToInt64(Raw, ElemOff) :
                                Et == typeof(double) ? BitConverter.ToDouble(Raw, ElemOff) :
                                null;

                            if (Prim == null) return false;
                            Arr.SetValue(Prim, I);
                        }

                        D.Field.SetValue(Value, Arr);
                        Cursor = Off + (ElemSize * Count);
                        continue;
                    }

                    D.Field.SetValue(Value, null);
                    Cursor = Off + (Is64 ? 8 : 4);
                    continue;
                }

                if (Ft == typeof(byte[]))
                {
                    if (D.InlineAttr != null)
                    {
                        byte[] Inline = new byte[D.InlineAttr.Size];
                        Buffer.BlockCopy(Raw, Off, Inline, 0, D.InlineAttr.Size);
                        D.Field.SetValue(Value, Inline);
                        Cursor = Off + D.InlineAttr.Size;
                        continue;
                    }
                    D.Field.SetValue(Value, null);
                    Cursor = Off + (Is64 ? 8 : 4);
                    continue;
                }

                if (Ft.IsValueType && !Ft.IsPrimitive)
                {
                    TypeDesc ND = GetDesc(Ft);
                    int NS = Is64 ? ND.Size64 : ND.Size32;

                    if (D.PtrAttr != null && D.PtrAttr.ContentType == PointerContentType.Struct)
                    {
                        int PtrSz = Is64 ? 8 : 4;
                        ulong Ptr = Is64 ? BitConverter.ToUInt64(Raw, Off) : BitConverter.ToUInt32(Raw, Off);
                        if (Ptr != 0)
                        {
                            byte[] NR = Emulator.ReadMemory(Ptr, (uint)NS);
                            if (NR == null || NR.Length != NS) return false;
                            object Inner = Activator.CreateInstance(Ft);
                            if (!ReadFields(Emulator, NR, 0, ref Inner, Depth + 1, Is64)) return false;
                            D.Field.SetValue(Value, Inner);
                        }
                        Cursor = Off + PtrSz;
                    }
                    else
                    {
                        object Nested = Activator.CreateInstance(Ft);
                        if (!ReadFields(Emulator, Raw, Off, ref Nested, Depth + 1, Is64)) return false;
                        D.Field.SetValue(Value, Nested);
                        Cursor = Off + NS;
                    }
                    continue;
                }

                return false;
            }

            return true;
        }

        /// <summary>
        /// Read a null-terminated string from the emulated memory in chunks.
        /// </summary>
        /// <param name="Emulator">Emulator instance.</param>
        /// <param name="Address">Address to start reading from.</param>
        /// <param name="Enc">Encoding to use when converting the bytes to string.</param>
        /// <returns>returns the string if successful, otherwise false.</returns>
        /// <remarks>
        /// This function expects the memory inside the emulated program to be null-terminated.
        /// </remarks>
        private static string ReadNullTerminatedString(BinaryEmulator Emulator, ulong Address, Encoding Enc)
        {
            const uint MaxReadSize = 1024;
            uint ChunkSize = 8;
            bool Unicode = Enc.Equals(Encoding.Unicode) || Enc.Equals(Encoding.BigEndianUnicode);
            int CharSize = Unicode ? 2 : 1;
            List<byte> Buf = new List<byte>(128);
            ulong Cursor = Address;
            uint TotalRead = 0;

            byte[] Carry = Array.Empty<byte>();

            while (TotalRead < MaxReadSize)
            {
                uint Remaining = MaxReadSize - TotalRead;
                uint BytesToRead = ChunkSize > Remaining ? Remaining : ChunkSize;

                if (!Emulator.IsRegionMapped(Cursor, BytesToRead))
                    break;

                byte[] Chunk = Emulator.ReadMemory(Cursor, BytesToRead);
                if (Chunk == null || Chunk.Length == 0) break;

                byte[] Combined = new byte[Carry.Length + Chunk.Length];

                if (Carry.Length > 0)
                    Buffer.BlockCopy(Carry, 0, Combined, 0, Carry.Length);

                Buffer.BlockCopy(Chunk, 0, Combined, Carry.Length, Chunk.Length);

                int ProcessBytes = (Combined.Length / CharSize) * CharSize;

                for (int I = 0; I + CharSize <= ProcessBytes; I += CharSize)
                {
                    if (Unicode)
                    {
                        if (Combined[I] == 0 && Combined[I + 1] == 0)
                            goto Success;

                        Buf.Add(Combined[I]);
                        Buf.Add(Combined[I + 1]);
                    }
                    else
                    {
                        if (Combined[I] == 0)
                            goto Success;

                        Buf.Add(Combined[I]);
                    }
                }

                int Leftover = Combined.Length - ProcessBytes;

                if (Leftover > 0)
                {
                    Carry = new byte[Leftover];
                    Buffer.BlockCopy(Combined, ProcessBytes, Carry, 0, Leftover);
                }
                else
                {
                    Carry = Array.Empty<byte>();
                }

                Cursor += (ulong)Chunk.Length;

                if (Chunk.Length < BytesToRead)
                    break;

                TotalRead += (uint)Chunk.Length;

                if (ChunkSize < 64)
                {
                    ChunkSize += ChunkSize;
                }
            }

            return null;

        Success:
            return Enc.GetString(Buf.ToArray());
        }
    }
}