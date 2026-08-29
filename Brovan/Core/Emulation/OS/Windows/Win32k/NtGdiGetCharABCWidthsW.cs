using System;
using System.Buffers;
using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetCharABCWidthsW : IWinSyscall
    {
        private const int AbcSize = 12;
        private const uint IntegerWidths = 0x1;
        private const int FallbackCharWidth = 8;
        private const uint MaxCharacters = 0x10000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            uint FirstCharacter = (uint)Instance.WinHelper.GetArg(1);
            uint Count = (uint)Instance.WinHelper.GetArg(2);
            ulong CharactersPtr = Instance.WinHelper.GetArg(3);
            uint Flags = (uint)Instance.WinHelper.GetArg(4);
            ulong BufferPtr = Instance.WinHelper.GetArg(5);

            if (BufferPtr == 0 || Count == 0 || Count > MaxCharacters || !Win32kHelper.IsKnownDc(Instance, Hdc))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong BufferSize = (ulong)Count * AbcSize;
            if (!Instance.IsRegionMapped(BufferPtr, BufferSize))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            int CharacterBytes = (int)Count * 2;
            if (CharactersPtr != 0 && !Instance.IsRegionMapped(CharactersPtr, (ulong)CharacterBytes))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            byte[] Rented = CharactersPtr != 0 ? ArrayPool<byte>.Shared.Rent(CharacterBytes) : null;

            try
            {
                ReadOnlySpan<byte> Characters = default;
                if (Rented != null)
                {
                    Span<byte> Target = Rented.AsSpan(0, CharacterBytes);
                    if (!Instance.ReadMemory(CharactersPtr, Target, (uint)CharacterBytes))
                    {
                        Instance.SetBooleanSyscallReturn(false);
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                    Characters = Target;
                }

                int[] WidthCache = Win32kHelper.GetCharAdvanceWidthCache(Instance);
                Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(BufferSize);
                bool AsFloat = (Flags & IntegerWidths) == 0;

                for (uint Index = 0; Index < Count; Index++)
                {
                    char Character = Rented != null
                        ? (char)BinaryPrimitives.ReadUInt16LittleEndian(Characters.Slice((int)Index * 2, 2))
                        : (char)(FirstCharacter + Index);

                    int Width = Win32kHelper.GetCharAdvanceWidth(Instance, WidthCache, Character, FallbackCharWidth);

                    Span<byte> Entry = Buffer.Slice((int)(Index * AbcSize), AbcSize);
                    if (AsFloat)
                    {
                        BinaryPrimitives.WriteSingleLittleEndian(Entry.Slice(0, 4), 0f);
                        BinaryPrimitives.WriteSingleLittleEndian(Entry.Slice(4, 4), Width);
                        BinaryPrimitives.WriteSingleLittleEndian(Entry.Slice(8, 4), 0f);
                    }
                    else
                    {
                        BinaryPrimitives.WriteInt32LittleEndian(Entry.Slice(0, 4), 0);
                        BinaryPrimitives.WriteInt32LittleEndian(Entry.Slice(4, 4), Width);
                        BinaryPrimitives.WriteInt32LittleEndian(Entry.Slice(8, 4), 0);
                    }
                }

                if (!Instance.WriteMemory(BufferPtr, Buffer.Slice(0, (int)BufferSize)))
                {
                    Instance.SetBooleanSyscallReturn(false);
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }
            }
            finally
            {
                if (Rented != null)
                    ArrayPool<byte>.Shared.Return(Rented);
            }

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
