using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Brovan.Core.Emulation;
using Brovan.Core.Emulation.Guests;
using Brovan.Core.Emulation.OS.Linux;
using Brovan.Core.Emulation.OS.Windows;
using static Brovan.Core.Helpers.BinaryHelpers;
using static Brovan.Core.Helpers.Utils;
using static Brovan.Helpers;
using static Brovan.Variables;

namespace Brovan
{
    public partial class Handlers
    {
        private static uint GetMappedReadSize(ulong Address, ulong RequestedSize)
        {
            if (Address == 0 || RequestedSize == 0 || Emulator?._memory == null)
                return 0;

            foreach (MemoryRegion Region in Emulator._memory)
            {
                if (Region.Size == 0)
                    continue;

                ulong RegionEnd = Region.BaseAddress + Region.Size;
                if (RegionEnd < Region.BaseAddress)
                    RegionEnd = ulong.MaxValue;

                if (Address < Region.BaseAddress || Address >= RegionEnd)
                    continue;

                ulong Available = RegionEnd - Address;
                return (uint)Math.Min(Math.Min(RequestedSize, Available), uint.MaxValue);
            }

            return 0;
        }

        private static string ReadAsciiZ(ulong address, int maxLen = LdrpLogMaxAscii)
        {
            if (address == 0)
                return string.Empty;

            uint ReadSize = GetMappedReadSize(address, (ulong)Math.Max(maxLen, 0));
            if (ReadSize == 0)
                return $"0x{address:X}";

            try
            {
                byte[] Data = Emulator.ReadMemory(address, ReadSize);
                int Length = Array.IndexOf(Data, (byte)0);
                if (Length < 0)
                    Length = Data.Length;

                return Encoding.ASCII.GetString(Data, 0, Length);
            }
            catch
            {
                return $"0x{address:X}";
            }
        }

        private static string ReadWideZ(ulong address, int maxChars = LdrpLogMaxUnicodeChars)
        {
            if (address == 0)
                return string.Empty;

            uint ReadSize = GetMappedReadSize(address, (ulong)Math.Max(maxChars, 0) * 2UL);
            ReadSize &= ~1U;
            if (ReadSize == 0)
                return $"0x{address:X}";

            try
            {
                byte[] Data = Emulator.ReadMemory(address, ReadSize);
                int Length = Data.Length;
                for (int i = 0; i + 1 < Data.Length; i += 2)
                {
                    if (Data[i] == 0 && Data[i + 1] == 0)
                    {
                        Length = i;
                        break;
                    }
                }

                return Encoding.Unicode.GetString(Data, 0, Length);
            }
            catch
            {
                return $"0x{address:X}";
            }
        }

        private static bool TryReadUnicodeStringStruct(ulong unicodeStringPtr, out string value)
        {
            value = string.Empty;
            if (unicodeStringPtr == 0)
                return true;

            if (!Emulator.IsRegionMapped(unicodeStringPtr, 0x10))
                return false;

            try
            {
                byte[] header = Emulator.ReadMemory(unicodeStringPtr, 0x10);
                if (header == null || header.Length < 0x10)
                    return false;

                ushort length = BitConverter.ToUInt16(header, 0);
                ushort maxLen = BitConverter.ToUInt16(header, 2);
                ulong buffer = BitConverter.ToUInt64(header, 8);

                if (length == 0 || buffer == 0)
                {
                    value = string.Empty;
                    return true;
                }

                if ((length & 1) != 0)
                    return false;

                if (length > maxLen)
                    length = maxLen;

                if (length > (ushort)(LdrpLogMaxUnicodeChars * 2))
                    length = (ushort)(LdrpLogMaxUnicodeChars * 2);

                if (!Emulator.IsRegionMapped(buffer, length))
                    return false;

                byte[] data = Emulator.ReadMemory(buffer, length);
                if (data == null)
                    return false;

                value = Encoding.Unicode.GetString(data);
                return true;
            }
            catch
            {
                return false;
            }
        }

    }
}
