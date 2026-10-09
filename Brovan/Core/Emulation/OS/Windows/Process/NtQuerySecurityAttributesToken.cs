using System;
using System.Buffers.Binary;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtQuerySecurityAttributesToken : IWinSyscall
    {
        private const uint MaxQueriedAttributes = 0x400;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong TokenHandle = Instance.WinHelper.GetArg(0);
            ulong AttributesPtr = Instance.WinHelper.GetArg(1);
            uint NumberOfAttrs = (uint)Instance.WinHelper.GetArg(2);
            ulong Buffer = Instance.WinHelper.GetArg(3);
            uint BufferLength = (uint)Instance.WinHelper.GetArg(4);
            ulong ReturnLengthPtr = Instance.WinHelper.GetArg(5);

            bool Is64 = Instance.WinHelper.PointerSize == 8;
            uint NameSize = UnicodeStringSize(Is64);

            NTSTATUS Status = NtQueryInformationToken.ResolveToken(Instance, TokenHandle, out WinToken Token);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (NumberOfAttrs != 0 && AttributesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (NumberOfAttrs > MaxQueriedAttributes)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            WinTokenSecurityAttribute[] Selected = Token.SecurityAttributes;
            if (NumberOfAttrs != 0)
            {
                Selected = new WinTokenSecurityAttribute[NumberOfAttrs];
                for (uint Index = 0; Index < NumberOfAttrs; Index++)
                {
                    if (!Instance.WinHelper.TryReadUnicodeString(AttributesPtr + Index * NameSize, out string Name, out NTSTATUS ReadStatus))
                        return ReadStatus;

                    WinTokenSecurityAttribute? Found = FindAttribute(Token.SecurityAttributes, Name);
                    if (Found == null)
                    {
                        if (ReturnLengthPtr != 0 && !Instance._emulator.WriteMemory(ReturnLengthPtr, 0u))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_NOT_FOUND;
                    }

                    Selected[Index] = Found;
                }
            }

            uint RequiredSize = GetAttributesInformationSize(Selected, Is64);

            if (ReturnLengthPtr != 0 && !Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Buffer == 0 || BufferLength < RequiredSize)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            Span<byte> Data = Instance.WinHelper.Shared.GetSpan(RequiredSize).Slice(0, (int)RequiredSize);
            WriteAttributesInformation(Data, Buffer, Selected, Is64);

            if (!Instance.WriteMemory(Buffer, Data))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        // TOKEN_SECURITY_ATTRIBUTES_INFORMATION and its TOKEN_SECURITY_ATTRIBUTE_V1 array, with the data after it.
        internal static uint GetAttributesInformationSize(WinTokenSecurityAttribute[] Attributes, bool Is64)
        {
            uint PointerSize = Is64 ? 8u : 4u;
            uint Size = Align(4 + 4 + PointerSize, PointerSize) + (uint)Attributes.Length * AttributeSize(Is64);

            foreach (WinTokenSecurityAttribute Attribute in Attributes)
            {
                Size += (uint)(Attribute.Name.Length * 2);
                Size = Align(Size, 8);
                if (Attribute.ValueType == WinTokenSecurityAttribute.TypeString)
                {
                    Size += (uint)Attribute.StringValues.Length * UnicodeStringSize(Is64);
                    foreach (string Value in Attribute.StringValues)
                        Size += (uint)(Value.Length * 2);
                }
                else
                {
                    Size += (uint)Attribute.UInt64Values.Length * 8;
                }
            }

            return Align(Size, PointerSize);
        }

        internal static void WriteAttributesInformation(Span<byte> Data, ulong GuestBase, WinTokenSecurityAttribute[] Attributes, bool Is64)
        {
            uint PointerSize = Is64 ? 8u : 4u;
            uint ArrayOffset = Align(4 + 4 + PointerSize, PointerSize);
            uint Cursor = ArrayOffset + (uint)Attributes.Length * AttributeSize(Is64);

            Data.Clear();
            BinaryPrimitives.WriteUInt16LittleEndian(Data, 1);
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(4), (uint)Attributes.Length);
            WritePointer(Data, 8, Attributes.Length == 0 ? 0 : GuestBase + ArrayOffset, Is64);

            for (int Index = 0; Index < Attributes.Length; Index++)
            {
                WinTokenSecurityAttribute Attribute = Attributes[Index];
                int Entry = (int)(ArrayOffset + (uint)Index * AttributeSize(Is64));

                ulong NameAddress = GuestBase + Cursor;
                Cursor += WriteChars(Data, Cursor, Attribute.Name);
                WriteUnicodeString(Data, Entry, (ushort)(Attribute.Name.Length * 2), NameAddress, Is64);

                int Fields = Entry + (int)UnicodeStringSize(Is64);
                BinaryPrimitives.WriteUInt16LittleEndian(Data.Slice(Fields), Attribute.ValueType);
                BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(Fields + 4), Attribute.Flags);
                BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(Fields + 8), (uint)Attribute.ValueCount);

                Cursor = Align(Cursor, 8);
                WritePointer(Data, Is64 ? Entry + 32 : Entry + 20, GuestBase + Cursor, Is64);

                if (Attribute.ValueType == WinTokenSecurityAttribute.TypeString)
                {
                    uint StringSize = UnicodeStringSize(Is64);
                    uint Strings = Cursor;
                    Cursor += (uint)Attribute.StringValues.Length * StringSize;
                    for (int Value = 0; Value < Attribute.StringValues.Length; Value++)
                    {
                        ulong ValueAddress = GuestBase + Cursor;
                        Cursor += WriteChars(Data, Cursor, Attribute.StringValues[Value]);
                        WriteUnicodeString(Data, (int)(Strings + (uint)Value * StringSize), (ushort)(Attribute.StringValues[Value].Length * 2), ValueAddress, Is64);
                    }
                }
                else
                {
                    foreach (ulong Value in Attribute.UInt64Values)
                    {
                        BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice((int)Cursor), Value);
                        Cursor += 8;
                    }
                }
            }
        }

        private static WinTokenSecurityAttribute? FindAttribute(WinTokenSecurityAttribute[] Attributes, string Name)
        {
            foreach (WinTokenSecurityAttribute Attribute in Attributes)
            {
                if (string.Equals(Attribute.Name, Name, StringComparison.OrdinalIgnoreCase))
                    return Attribute;
            }

            return null;
        }

        private static uint AttributeSize(bool Is64) => Is64 ? 40u : 24u;

        private static uint UnicodeStringSize(bool Is64) => Is64 ? 16u : 8u;

        private static uint Align(uint Value, uint Alignment) => (Value + Alignment - 1) & ~(Alignment - 1);

        private static uint WriteChars(Span<byte> Data, uint Offset, string Text)
        {
            int Written = Encoding.Unicode.GetBytes(Text, Data.Slice((int)Offset));
            return (uint)Written;
        }

        private static void WriteUnicodeString(Span<byte> Data, int Offset, ushort Length, ulong Address, bool Is64)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(Data.Slice(Offset), Length);
            BinaryPrimitives.WriteUInt16LittleEndian(Data.Slice(Offset + 2), Length);
            WritePointer(Data, Offset + (Is64 ? 8 : 4), Address, Is64);
        }

        private static void WritePointer(Span<byte> Data, int Offset, ulong Value, bool Is64)
        {
            if (Is64)
                BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(Offset), Value);
            else
                BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(Offset), (uint)Value);
        }
    }
}
