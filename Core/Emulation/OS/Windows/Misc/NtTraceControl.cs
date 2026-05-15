using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtTraceControl : IWinSyscall
    {
        private const uint EtwRegisterUserModeGuid = 0x0F;
        private const uint EtwAddNotificationEvent = 0x1B;
        private const uint EtwSetProviderTraits = 0x1E;
        private const uint EtwRegisterUserModeGuidLength = 0xA0;
        private const uint EtwRegisterUserModeGuidHeaderLength = 0x28;
        private const uint EtwEnableNotificationLength = 0x78;
        private const uint EtwMaxOutputLength = 0x10000;
        private const ulong EtwRegistrationHandleOffset = 0x18;
        private const ulong EtwRegistrationCallbackOffset = 0x20;
        private const ulong EtwSetProviderTraitsHandleOffset = 0x00;
        private const ulong EtwSetProviderTraitsPointerOffset = 0x08;
        private const ulong EtwSetProviderTraitsSizeOffset = 0x10;
        private const uint EventModifyState = 0x0002;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            uint FunctionCode = (uint)Instance.WinHelper.GetArg64(0);
            ulong InBuffer = Instance.WinHelper.GetArg64(1);
            uint InBufferLength = (uint)Instance.WinHelper.GetArg64(2);
            ulong OutBuffer = Instance.WinHelper.GetArg64(3);
            uint OutBufferLength = (uint)Instance.WinHelper.GetArg64(4);
            ulong ReturnLengthPtr = Instance.WinHelper.GetArg64(5);

            if (ReturnLengthPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (InBuffer != 0 && InBufferLength != 0 && !Instance.IsRegionMapped(InBuffer, InBufferLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (OutBuffer != 0 && OutBufferLength != 0 && !Instance.IsRegionMapped(OutBuffer, OutBufferLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance._emulator.WriteMemory(ReturnLengthPtr, 0u);

            NTSTATUS Status = FunctionCode switch
            {
                EtwRegisterUserModeGuid => HandleRegisterUserModeGuid(Instance, InBuffer, InBufferLength, OutBuffer, OutBufferLength, ReturnLengthPtr),
                EtwAddNotificationEvent => HandleAddNotificationEvent(Instance, InBuffer, InBufferLength),
                EtwSetProviderTraits => HandleSetProviderTraits(Instance, InBuffer, InBufferLength, OutBuffer, OutBufferLength),
                _ => NTSTATUS.STATUS_INVALID_DEVICE_REQUEST
            };

            Instance.TriggerEventMessage($"[+] NtTraceControl: Function=0x{FunctionCode:X}, In=0x{InBuffer:X}/0x{InBufferLength:X}, Out=0x{OutBuffer:X}/0x{OutBufferLength:X}, Status={Status}.", LogFlags.Syscall);
            return Status;
        }

        private static NTSTATUS HandleRegisterUserModeGuid(BinaryEmulator Instance, ulong InBuffer, uint InBufferLength, ulong OutBuffer, uint OutBufferLength, ulong ReturnLengthPtr)
        {
            if (InBuffer == 0 || OutBuffer == 0 || InBufferLength != EtwRegisterUserModeGuidLength)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (OutBufferLength > EtwMaxOutputLength)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (OutBufferLength < EtwRegisterUserModeGuidLength)
            {
                Instance._emulator.WriteMemory(ReturnLengthPtr, EtwRegisterUserModeGuidLength);
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;
            }

            Span<byte> Header = Instance.WinHelper.ReadMemorySpan(InBuffer, EtwRegisterUserModeGuidHeaderLength);
            if (Header.Length < EtwRegisterUserModeGuidHeaderLength)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Guid ProviderGuid = new Guid(Header.Slice(0, 16));
            uint NotificationType = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0x10, 4));
            ushort RegistrationIndex = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(0x14, 2));
            ulong Callback = Instance.ReadMemoryULong(InBuffer + EtwRegistrationCallbackOffset);

            WinEtwRegistration Registration = new WinEtwRegistration
            {
                ProviderGuid = ProviderGuid,
                NotificationType = NotificationType,
                RegistrationIndex = RegistrationIndex,
                Callback = Callback
            };

            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(Registration, AccessMask.GiveTemp);
            Instance.WinHelper.WinHandles.Add(Handle);
            Instance.WinHelper.WinEtwRegistrations.Add(Registration);

            if (!Instance.WriteMemory(OutBuffer, Header))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.WriteZeroMemory(OutBuffer + EtwRegisterUserModeGuidHeaderLength, EtwRegisterUserModeGuidLength - EtwRegisterUserModeGuidHeaderLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance._emulator.WriteMemory(OutBuffer + EtwRegistrationHandleOffset, Handle.Handle, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance._emulator.WriteMemory(ReturnLengthPtr, EtwRegisterUserModeGuidLength);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleAddNotificationEvent(BinaryEmulator Instance, ulong InBuffer, uint InBufferLength)
        {
            if (InBuffer == 0 || InBufferLength != 4)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint EventHandle32 = Instance.ReadMemoryUInt(InBuffer);
            if (EventHandle32 == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Instance.WinHelper.EtwNotificationEventHandle != 0)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            WinEvent Event = Instance.WinHelper.GetEventByHandle(EventHandle32, (AccessMask)EventModifyState);
            if (Event == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            Instance.WinHelper.EtwNotificationEventHandle = EventHandle32;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleSetProviderTraits(BinaryEmulator Instance, ulong InBuffer, uint InBufferLength, ulong OutBuffer, uint OutBufferLength)
        {
            if (InBuffer == 0 || InBufferLength != 0x18)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (OutBuffer == 0 || OutBufferLength < EtwEnableNotificationLength || OutBufferLength > EtwMaxOutputLength)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong RegistrationHandle = Instance.ReadMemoryULong(InBuffer + EtwSetProviderTraitsHandleOffset);
            ulong TraitsPtr = Instance.ReadMemoryULong(InBuffer + EtwSetProviderTraitsPointerOffset);
            ushort TraitsSize = Instance._emulator.ReadMemoryUShort(InBuffer + EtwSetProviderTraitsSizeOffset);

            if (TraitsPtr == 0 || TraitsSize == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(TraitsPtr, TraitsSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinEtwRegistration Registration = Instance.WinHelper.HandleManager.GetObjectByHandle<WinEtwRegistration>(RegistrationHandle);
            if (Registration == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (Registration.Traits != null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            byte[] Traits = Instance.ReadMemory(TraitsPtr, TraitsSize);
            if (!ValidateProviderTraits(Traits))
                return NTSTATUS.STATUS_FILE_CORRUPT_ERROR;

            Registration.Traits = Traits;

            if (!Instance.WinHelper.WriteZeroMemory(OutBuffer, OutBufferLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool ValidateProviderTraits(byte[] Traits)
        {
            if (Traits.Length < 3)
                return false;

            ushort Size = BitConverter.ToUInt16(Traits, 0);
            if (Size != Traits.Length)
                return false;

            int Offset = 2;
            while (Offset < Traits.Length && Traits[Offset] != 0)
                Offset++;

            if (Offset >= Traits.Length)
                return false;

            Offset++;
            while (Offset < Traits.Length)
            {
                if (Traits.Length - Offset < 3)
                    return false;

                ushort TraitSize = BitConverter.ToUInt16(Traits, Offset);
                if (TraitSize < 3 || Offset + TraitSize > Traits.Length)
                    return false;

                Offset += TraitSize;
            }

            return Offset == Traits.Length;
        }
    }
}
