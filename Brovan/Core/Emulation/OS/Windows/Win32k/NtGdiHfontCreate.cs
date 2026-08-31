using System.Buffers.Binary;
using Brovan.Core.Emulation.OS.SharedHelpers;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiHfontCreate : IWinSyscall
    {
        // ENUMLOGFONTEXDVW opens with the LOGFONTW the caller asked for.
        private const uint LogFontSize = 92;
        private const int FaceNameOffset = 28;
        private const int FaceNameChars = 32;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong LogFontPtr = Instance.WinHelper.GetArg(0);

            if (LogFontPtr == 0 || !Instance.IsRegionMapped(LogFontPtr, LogFontSize))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Span<byte> Data = Instance.WinHelper.Shared.GetSpan(LogFontSize).Slice(0, (int)LogFontSize);
            if (!Instance.ReadMemory(LogFontPtr, Data, LogFontSize))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

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

            ulong Handle = Win32kHelper.CreateFont(Instance, Description);
            Instance.SetLastWinError(Handle == 0 ? Win32kHelper.ERROR_INVALID_PARAMETER : 0u);
            Instance.SetRawSyscallReturn(Handle);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static string ReadFaceName(ReadOnlySpan<byte> LogFont)
        {
            ReadOnlySpan<byte> Bytes = LogFont.Slice(FaceNameOffset, FaceNameChars * sizeof(char));
            string Name = Encoding.Unicode.GetString(Bytes);

            int End = Name.IndexOf('\0');
            return End < 0 ? Name : Name.Substring(0, End);
        }
    }
}
