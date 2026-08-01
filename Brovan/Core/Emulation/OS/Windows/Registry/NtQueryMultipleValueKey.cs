using Brovan.Core.Helpers;
using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryMultipleValueKey : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong KeyHandle = Instance.WinHelper.GetArg(0);
            ulong ValueEntriesPtr = Instance.WinHelper.GetArg(1);
            uint EntryCount = (uint)Instance.WinHelper.GetArg(2);
            ulong ValueBufferPtr = Instance.WinHelper.GetArg(3);
            ulong BufferLengthPtr = Instance.WinHelper.GetArg(4);
            ulong RequiredBufferLengthPtr = Instance.WinHelper.GetArg(5);

            uint PointerSize = (uint)Instance.WinHelper.PointerSize;

            uint EntryStride = PointerSize == 8 ? 24u : 16u;

            if (BufferLengthPtr == 0 || !Instance.IsRegionMapped(BufferLengthPtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (EntryCount != 0 && (ValueEntriesPtr == 0 || !Instance.IsRegionMapped(ValueEntriesPtr, (ulong)EntryCount * EntryStride)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint BufferLength = Instance._emulator.ReadMemoryUInt(BufferLengthPtr);
            if (BufferLength != 0 && (ValueBufferPtr == 0 || !Instance.IsRegionMapped(ValueBufferPtr, BufferLength)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinRegKey RegKey = Instance.WinHelper.HandleManager.GetObjectByHandle<WinRegKey>(KeyHandle);
            if (RegKey == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            uint Offset = 0;
            bool TooSmall = false;

            for (uint i = 0; i < EntryCount; i++)
            {
                ulong EntryPtr = ValueEntriesPtr + (ulong)i * EntryStride;
                ulong ValueNamePtr = Instance.WinHelper.ReadPointer(EntryPtr);

                if (!Instance.WinHelper.TryReadUnicodeString(ValueNamePtr, out string ValueName, out NTSTATUS NameStatus))
                    return NameStatus;

                if (!Instance.WinHelper.TryGetRegistryValue(RegKey, ValueName, out ValueNode Value))
                    return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                byte[] Data = Value.Data ?? Array.Empty<byte>();
                uint DataLength = (uint)Data.Length;

                if (!TooSmall && Offset + DataLength <= BufferLength)
                {
                    if (DataLength != 0 && !Instance._emulator.WriteMemory(ValueBufferPtr + Offset, Data.AsSpan()))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(EntryPtr + PointerSize, DataLength)
                        || !Instance._emulator.WriteMemory(EntryPtr + PointerSize + 4, Offset)
                        || !Instance._emulator.WriteMemory(EntryPtr + PointerSize + 8, (uint)Value.Type))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }
                else
                {
                    TooSmall = true;
                }

                Offset = AlignUp(Offset + DataLength, 4);
            }

            if (RequiredBufferLengthPtr != 0)
            {
                if (!Instance.IsRegionMapped(RequiredBufferLengthPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Instance._emulator.WriteMemory(RequiredBufferLengthPtr, Offset);
            }

            if (TooSmall)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            Instance._emulator.WriteMemory(BufferLengthPtr, Offset);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static uint AlignUp(uint Value, uint Alignment)
        {
            uint Mask = Alignment - 1;
            return (Value + Mask) & ~Mask;
        }
    }
}
