using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtQuerySecurityAttributesToken : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong TokenHandle = Instance.WinHelper.GetArg(0);
            ulong AttributesPtr = Instance.WinHelper.GetArg(1);
            uint NumberOfAttrs = (uint)Instance.WinHelper.GetArg(2);
            ulong Buffer = Instance.WinHelper.GetArg(3);
            uint BufferLength = (uint)Instance.WinHelper.GetArg(4);
            ulong ReturnLengthPtr = Instance.WinHelper.GetArg(5);

            const uint RequiredSize = 0x10;

            long SignedTokenHandle = unchecked((long)TokenHandle);
            if (SignedTokenHandle != -4 && SignedTokenHandle != -5 && SignedTokenHandle != -6 && !Instance.WinHelper.HandleManager.HandleExists(TokenHandle, HandleType.TokenHandle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (NumberOfAttrs != 0 && AttributesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (AttributesPtr != 0 && NumberOfAttrs != 0 && !Instance.IsRegionMapped(AttributesPtr, NumberOfAttrs * 8UL))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (ReturnLengthPtr != 0)
            {
                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredSize);
            }

            if (Buffer == 0)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            if (BufferLength < RequiredSize)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            if (!Instance.IsRegionMapped(Buffer, RequiredSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance._emulator.WriteMemory(Buffer + 0x0, (ushort)0, 2); // Version
            Instance._emulator.WriteMemory(Buffer + 0x2, (ushort)0, 2); // Reserved
            Instance._emulator.WriteMemory(Buffer + 0x4, 0u, 4); // AttributeCount
            Instance._emulator.WriteMemory(Buffer + 0x8, 0UL, 8); // Attribute pointer

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
