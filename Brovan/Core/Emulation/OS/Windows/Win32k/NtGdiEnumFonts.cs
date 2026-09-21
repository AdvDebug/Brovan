using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;
using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiEnumFonts : IWinSyscall
    {
        // A record is a DWORD step to the next one at +0, an ENUMLOGFONTEXDVW at +12, then a
        // NEWTEXTMETRICEXW. gdi32 walks the reply as a chain of them.
        private const int RecordHeaderSize = 12;
        private const int LogFontSize = 92;
        private const int EnumLogFontExSize = 348;
        private const int DesignVectorSize = 8;
        private const int NewTextMetricExSize = 100;
        private const int MetricsOffset = RecordHeaderSize + EnumLogFontExSize + DesignVectorSize;
        private const int RecordSize = MetricsOffset + NewTextMetricExSize;

        private const int FaceNameChars = 32;
        private const int FullNameChars = 64;

        private const uint ErrorBufferOverflow = 111;
        private const byte DefaultCharSet = 1;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint FaceLength = Instance.WinHelper.GetArg32(3);
            ulong FaceNamePtr = Instance.WinHelper.GetArg(4);
            byte CharSet = (byte)Instance.WinHelper.GetArg32(5);
            ulong CountPtr = Instance.WinHelper.GetArg(6);
            ulong BufferPtr = Instance.WinHelper.GetArg(7);

            if (CountPtr == 0)
                return Fail(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            string FaceName = ReadFaceName(Instance, FaceNamePtr, FaceLength);

            IReadOnlyList<FontFamilyData> Faces = Win32kHelper.GetFontFamilies(Instance, FaceName, CharSet == 0 ? DefaultCharSet : CharSet);
            ulong Required = (ulong)Faces.Count * RecordSize;

            if (BufferPtr == 0)
            {
                if (!WriteCount(Instance, CountPtr, Required))
                    return Fail(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

                Instance.SetLastWinError(Win32kHelper.ERROR_SUCCESS);
                Instance.SetBooleanSyscallReturn(true);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!ReadCount(Instance, CountPtr, out ulong Available))
                return Fail(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            if (Available < Required)
            {
                WriteCount(Instance, CountPtr, Required);
                return Fail(Instance, ErrorBufferOverflow);
            }

            if (Required != 0)
            {
                if (!Instance.IsRegionMapped(BufferPtr, Required))
                    return Fail(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

                byte[] Rented = ArrayPool<byte>.Shared.Rent((int)Required);
                try
                {
                    Span<byte> Buffer = Rented.AsSpan(0, (int)Required);
                    Buffer.Clear();

                    for (int i = 0; i < Faces.Count; i++)
                        WriteRecord(Buffer.Slice(i * RecordSize, RecordSize), Faces[i]);

                    if (!Instance.WriteMemory(BufferPtr, Buffer))
                        return Fail(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(Rented);
                }
            }

            WriteCount(Instance, CountPtr, Required);
            Instance.SetLastWinError(Win32kHelper.ERROR_SUCCESS);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void WriteRecord(Span<byte> Record, FontFamilyData Face)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(0, 4), RecordSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(4, 4), MetricsOffset - 8);
            BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(8, 4), Face.FontType);

            Span<byte> LogFont = Record.Slice(RecordHeaderSize, EnumLogFontExSize);
            BinaryPrimitives.WriteInt32LittleEndian(LogFont.Slice(0, 4), Face.Metrics.Height);
            BinaryPrimitives.WriteInt32LittleEndian(LogFont.Slice(16, 4), Face.Weight);
            LogFont[20] = Face.Italic ? (byte)1 : (byte)0;
            LogFont[23] = Face.CharSet;
            LogFont[27] = Face.PitchAndFamily;
            WriteString(LogFont.Slice(28, FaceNameChars * 2), Face.FaceName);
            WriteString(LogFont.Slice(LogFontSize, FullNameChars * 2), Face.FullName ?? Face.FaceName);
            WriteString(LogFont.Slice(LogFontSize + FullNameChars * 2, FaceNameChars * 2), Face.Style);

            Span<byte> Metrics = Record.Slice(MetricsOffset, NewTextMetricExSize);
            BinaryPrimitives.WriteInt32LittleEndian(Metrics.Slice(0, 4), Face.Metrics.Height);
            BinaryPrimitives.WriteInt32LittleEndian(Metrics.Slice(4, 4), Face.Metrics.Ascent);
            BinaryPrimitives.WriteInt32LittleEndian(Metrics.Slice(8, 4), Face.Metrics.Descent);
            BinaryPrimitives.WriteInt32LittleEndian(Metrics.Slice(12, 4), Face.Metrics.InternalLeading);
            BinaryPrimitives.WriteInt32LittleEndian(Metrics.Slice(16, 4), Face.Metrics.ExternalLeading);
            BinaryPrimitives.WriteInt32LittleEndian(Metrics.Slice(20, 4), Face.Metrics.AveCharWidth);
            BinaryPrimitives.WriteInt32LittleEndian(Metrics.Slice(24, 4), Face.Metrics.MaxCharWidth);
            BinaryPrimitives.WriteInt32LittleEndian(Metrics.Slice(28, 4), Face.Metrics.Weight);
            BinaryPrimitives.WriteInt32LittleEndian(Metrics.Slice(32, 4), Face.Metrics.Overhang);
            BinaryPrimitives.WriteInt32LittleEndian(Metrics.Slice(36, 4), Face.Metrics.DigitizedAspectX);
            BinaryPrimitives.WriteInt32LittleEndian(Metrics.Slice(40, 4), Face.Metrics.DigitizedAspectY);
            BinaryPrimitives.WriteUInt16LittleEndian(Metrics.Slice(44, 2), Face.Metrics.FirstChar);
            BinaryPrimitives.WriteUInt16LittleEndian(Metrics.Slice(46, 2), Face.Metrics.LastChar);
            BinaryPrimitives.WriteUInt16LittleEndian(Metrics.Slice(48, 2), Face.Metrics.DefaultChar);
            BinaryPrimitives.WriteUInt16LittleEndian(Metrics.Slice(50, 2), Face.Metrics.BreakChar);
            Metrics[52] = Face.Metrics.Italic;
            Metrics[53] = Face.Metrics.Underlined;
            Metrics[54] = Face.Metrics.StruckOut;
            Metrics[55] = Face.Metrics.PitchAndFamily;
            Metrics[56] = Face.Metrics.CharSet;
            BinaryPrimitives.WriteUInt32LittleEndian(Metrics.Slice(60, 4), Face.NtmFlags);
            BinaryPrimitives.WriteUInt32LittleEndian(Metrics.Slice(64, 4), Face.SizeEm);
            BinaryPrimitives.WriteUInt32LittleEndian(Metrics.Slice(68, 4), Face.CellHeight);
            BinaryPrimitives.WriteUInt32LittleEndian(Metrics.Slice(72, 4), Face.AvgWidth);
        }

        private static void WriteString(Span<byte> Target, string Value)
        {
            if (string.IsNullOrEmpty(Value))
                return;

            int Count = Math.Min(Value.Length, Target.Length / 2 - 1);
            for (int i = 0; i < Count; i++)
                BinaryPrimitives.WriteUInt16LittleEndian(Target.Slice(i * 2, 2), Value[i]);
        }

        private static string ReadFaceName(BinaryEmulator Instance, ulong Address, uint Length)
        {
            if (Address == 0 || Length < 2 || Length > FaceNameChars)
                return null;

            int Bytes = ((int)Length - 1) * 2;
            if (!Instance.IsRegionMapped(Address, (ulong)Bytes))
                return null;

            Span<byte> Buffer = stackalloc byte[FaceNameChars * 2];
            Span<byte> Name = Buffer.Slice(0, Bytes);
            if (!Instance.ReadMemory(Address, Name))
                return null;

            return Encoding.Unicode.GetString(Name).TrimEnd('\0');
        }

        // pulCount is a ULONG, four bytes on both architectures.
        private const int CountSize = 4;

        private static bool ReadCount(BinaryEmulator Instance, ulong Address, out ulong Value)
        {
            Value = 0;
            if (!Instance.IsRegionMapped(Address, CountSize))
                return false;

            Value = Instance.ReadMemoryUInt(Address);
            return true;
        }

        private static bool WriteCount(BinaryEmulator Instance, ulong Address, ulong Value)
        {
            return Instance.IsRegionMapped(Address, CountSize)
                && Instance._emulator.WriteMemory(Address, (uint)Value, CountSize);
        }

        private static NTSTATUS Fail(BinaryEmulator Instance, uint Error)
        {
            Instance.SetLastWinError(Error);
            Instance.SetBooleanSyscallReturn(false);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
