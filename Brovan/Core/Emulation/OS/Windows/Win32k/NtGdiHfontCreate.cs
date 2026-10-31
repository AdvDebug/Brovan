using System.Buffers.Binary;
using Brovan.Core.Emulation.OS.SharedHelpers;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiHfontCreate : IWinSyscall
    {
        // ENUMLOGFONTEXDVW opens with the LOGFONTW the caller asked for.
        private const int MaxEnumLogFontSize = 0x1A4;
        private const int DesignVectorAxesOffset = 0x160;
        private const int StoredEnumLogFontSize = 0x164;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong LogFontPtr = Instance.WinHelper.GetArg(0);
            uint Size = Instance.WinHelper.GetArg32(1);

            if (LogFontPtr == 0 || Size == 0 || Size > MaxEnumLogFontSize)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Span<byte> Data = stackalloc byte[MaxEnumLogFontSize];
            if (!Instance.ReadMemory(LogFontPtr, Data.Slice(0, (int)Size)))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            // NT discards design vector axes.
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(DesignVectorAxesOffset), 0);

            FontDescription Description = new FontDescription(
                BinaryPrimitives.ReadInt32LittleEndian(Data),
                BinaryPrimitives.ReadInt32LittleEndian(Data.Slice(4)),
                BinaryPrimitives.ReadInt32LittleEndian(Data.Slice(16)),
                Data[20] != 0,
                Data[21] != 0,
                Data[22] != 0,
                Data[23],
                Data[27],
                ReadFaceName(Data));

            ulong Handle = Win32kHelper.CreateFont(Instance, Description, Data.Slice(0, StoredEnumLogFontSize).ToArray());
            Instance.SetLastWinError(Handle == 0 ? Win32kHelper.ERROR_INVALID_PARAMETER : 0u);
            Instance.SetRawSyscallReturn(Handle);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static string ReadFaceName(ReadOnlySpan<byte> LogFont)
        {
            ReadOnlySpan<byte> Bytes = LogFont.Slice(WinSysHelper.LogFontFaceNameOffset, WinSysHelper.LogFontFaceNameChars * sizeof(char));
            string Name = Encoding.Unicode.GetString(Bytes);

            int End = Name.IndexOf('\0');
            return End < 0 ? Name : Name.Substring(0, End);
        }
    }
}
