using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtQuerySecurityObject : IWinSyscall
    {
        private const uint OwnerSecurityInformation = 0x00000001;
        private const uint GroupSecurityInformation = 0x00000002;
        private const uint DaclSecurityInformation = 0x00000004;
        private const ushort SecurityDescriptorRevision = 1;
        private const ushort SeDaclPresent = 0x0004;
        private const ushort SeSelfRelative = 0x8000;
        private const int SelfRelativeSecurityDescriptorSize = 20;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong Handle = Instance.WinHelper.GetArg(0);
                uint SecurityInformation = (uint)Instance.WinHelper.GetArg(1);
                ulong SecurityDescriptorPtr = Instance.WinHelper.GetArg(2);
                uint Length = (uint)Instance.WinHelper.GetArg(3);
                ulong LengthNeededPtr = Instance.WinHelper.GetArg(4);

                return QuerySecurityObject(Instance, Handle, SecurityInformation, SecurityDescriptorPtr, Length, LengthNeededPtr);
            }
            else
            {
                ulong Handle = Instance.WinHelper.GetArg32(0);
                uint SecurityInformation = Instance.WinHelper.GetArg32(1);
                ulong SecurityDescriptorPtr = Instance.WinHelper.GetArg32(2);
                uint Length = Instance.WinHelper.GetArg32(3);
                ulong LengthNeededPtr = Instance.WinHelper.GetArg32(4);

                return QuerySecurityObject(Instance, Handle, SecurityInformation, SecurityDescriptorPtr, Length, LengthNeededPtr);
            }
        }

        private static NTSTATUS QuerySecurityObject(BinaryEmulator Instance, ulong Handle, uint SecurityInformation, ulong SecurityDescriptorPtr, uint Length, ulong LengthNeededPtr)
        {
            if (!IsKnownHandle(Instance, Handle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (SecurityInformation == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!WriteLengthNeeded(Instance, LengthNeededPtr, (uint)SelfRelativeSecurityDescriptorSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Length < SelfRelativeSecurityDescriptorSize)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            if (SecurityDescriptorPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(SecurityDescriptorPtr, SelfRelativeSecurityDescriptorSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            byte[] SecurityDescriptor = BuildSelfRelativeSecurityDescriptor(SecurityInformation);
            if (!Instance._emulator.WriteMemory(SecurityDescriptorPtr, SecurityDescriptor))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"NtQuerySecurityObject: Handle=0x{Handle:X}, SecurityInformation=0x{SecurityInformation:X}, Length=0x{Length:X}.", LogFlags.Syscall);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool IsKnownHandle(BinaryEmulator Instance, ulong Handle)
        {
            return HandleManager.IsCurrentProcessPseudoHandle(Handle) ||
                   HandleManager.IsCurrentThreadPseudoHandle(Handle) ||
                   Handle == uint.MaxValue ||
                   Handle == HandleManager.KNOWN_DLLS_DIRECTORY ||
                   Handle == HandleManager.KNOWN_DLLS32_DIRECTORY ||
                   Handle == HandleManager.BASE_NAMED_OBJECTS_DIRECTORY ||
                   Handle == HandleManager.RPC_CONTROL_DIRECTORY ||
                   Instance.WinHelper.HandleExists(Handle);
        }

        private static bool WriteLengthNeeded(BinaryEmulator Instance, ulong LengthNeededPtr, uint LengthNeeded)
        {
            if (LengthNeededPtr == 0)
                return true;

            if (!Instance.IsRegionMapped(LengthNeededPtr, 4))
                return false;

            return Instance._emulator.WriteMemory(LengthNeededPtr, LengthNeeded);
        }

        private static byte[] BuildSelfRelativeSecurityDescriptor(uint SecurityInformation)
        {
            byte[] Buffer = new byte[SelfRelativeSecurityDescriptorSize];
            ushort Control = SeSelfRelative;

            if ((SecurityInformation & DaclSecurityInformation) != 0)
                Control |= SeDaclPresent;

            Buffer[0] = (byte)SecurityDescriptorRevision;
            Buffer[1] = 0;
            WriteUInt16(Buffer, 2, Control);

            if ((SecurityInformation & OwnerSecurityInformation) != 0)
                WriteUInt32(Buffer, 4, 0);
            if ((SecurityInformation & GroupSecurityInformation) != 0)
                WriteUInt32(Buffer, 8, 0);
            WriteUInt32(Buffer, 12, 0);
            WriteUInt32(Buffer, 16, 0);

            return Buffer;
        }

        private static void WriteUInt16(byte[] Buffer, int Offset, ushort Value)
        {
            Buffer[Offset] = (byte)Value;
            Buffer[Offset + 1] = (byte)(Value >> 8);
        }

        private static void WriteUInt32(byte[] Buffer, int Offset, uint Value)
        {
            Buffer[Offset] = (byte)Value;
            Buffer[Offset + 1] = (byte)(Value >> 8);
            Buffer[Offset + 2] = (byte)(Value >> 16);
            Buffer[Offset + 3] = (byte)(Value >> 24);
        }
    }
}
