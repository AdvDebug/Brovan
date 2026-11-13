using System;
using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAlpcQueryInformationMessage : IWinSyscall
    {
        private const uint AlpcMessageHandleInformation = 3;
        private const uint HandleInformationSize = 20;

        // The checks and their order follow NtAlpcQueryInformationMessage and AlpcpQueryHandleInformationMessage.
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong PortHandle = Instance.WinHelper.GetArg(0);
            ulong MessagePtr = Instance.WinHelper.GetArg(1);
            uint InformationClass = (uint)Instance.WinHelper.GetArg(2);
            ulong InformationPtr = Instance.WinHelper.GetArg(3);
            uint Length = (uint)Instance.WinHelper.GetArg(4);
            ulong ReturnLengthPtr = Instance.WinHelper.GetArg(5);

            // Brovan does not serve the SID, ModifiedId and completion classes.
            if (InformationClass < AlpcMessageHandleInformation)
                return NTSTATUS.STATUS_INVALID_INFO_CLASS;

            NTSTATUS Status = AlpcMessaging.TryReadMessageIds(Instance, MessagePtr, out uint MessageId, out uint CallbackId);
            if (Status != NTSTATUS.STATUS_SUCCESS && Status != NTSTATUS.STATUS_INVALID_PARAMETER)
                return Status;

            if (Length != 0)
            {
                if ((InformationPtr & 3) != 0)
                    return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

                Status = Instance.WinHelper.ProbeForWrite(InformationPtr, Length);
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;
            }

            if (ReturnLengthPtr != 0)
            {
                Status = Instance.WinHelper.ProbeForWrite(ReturnLengthPtr, sizeof(uint));
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;
            }

            if (MessageId == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Status = Instance.WinHelper.ReferenceObjectByHandle(PortHandle, AccessMask.ReadControl, out WinPort Port, out ulong PortKey, out _);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Status = AlpcMessaging.LookupMessage(Port, PortKey, MessageId, CallbackId, out _, out AlpcHandleBlob Blob);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (InformationClass != AlpcMessageHandleInformation)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Length != HandleInformationSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            Span<byte> Information = stackalloc byte[(int)HandleInformationSize];
            if (!Instance.ReadMemory(InformationPtr, Information.Slice(0, sizeof(uint))))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint Index = BinaryPrimitives.ReadUInt32LittleEndian(Information);
            if (Blob == null || Index >= (uint)Blob.Handles.Length)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            AlpcHeldHandle Held = Blob.Handles[Index];
            if (!AlpcMessaging.TryOpenHandle(Instance, Held, out ulong Delivering))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if ((Instance.Settings.Flags & LogFlags.General) != 0)
                Instance.TriggerEventMessage($"[+] ALPC handle 0x{Delivering:X} given from \"{Port.Name}\" (message {MessageId}, index {Index}).", LogFlags.General);

            BinaryPrimitives.WriteUInt32LittleEndian(Information.Slice(0x04), 0);
            BinaryPrimitives.WriteUInt32LittleEndian(Information.Slice(0x08), (uint)Delivering);
            BinaryPrimitives.WriteUInt32LittleEndian(Information.Slice(0x0C), AlpcObjectType(Held.Object));
            BinaryPrimitives.WriteUInt32LittleEndian(Information.Slice(0x10), (uint)Held.Access);
            if (!Instance.WriteMemory(InformationPtr, Information))
            {
                Instance.WinHelper.CloseHandle(Delivering);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if (ReturnLengthPtr != 0 && !Instance.WinHelper.WriteUInt32(ReturnLengthPtr, HandleInformationSize))
            {
                Instance.WinHelper.CloseHandle(Delivering);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static uint AlpcObjectType(IHandleObject Object)
        {
            switch (Object?.ObjectType)
            {
                case HandleType.FileHandle: return 0x0001;
                case HandleType.ThreadHandle: return 0x0004;
                case HandleType.SemaphoreHandle: return 0x0008;
                case HandleType.EventHandle: return 0x0010;
                case HandleType.ProcessHandle: return 0x0020;
                case HandleType.MutexHandle: return 0x0040;
                case HandleType.SectionHandle: return 0x0080;
                case HandleType.RegistryKeyHandle: return 0x0100;
                case HandleType.TokenHandle: return 0x0200;
                case HandleType.JobHandle: return 0x0800;
                default: return 0x0001;
            }
        }
    }
}
