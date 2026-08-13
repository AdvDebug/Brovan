using System.Collections.Generic;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAlpcQueryInformationMessage : IWinSyscall
    {
        private const uint AlpcMessageHandleInformation = 3;
        private const int HandleInformationSize = 20;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong PortHandle = Instance.WinHelper.GetArg(0);
            uint InformationClass = (uint)Instance.WinHelper.GetArg(2);
            ulong InformationPtr = Instance.WinHelper.GetArg(3);
            uint Length = (uint)Instance.WinHelper.GetArg(4);
            ulong ReturnLengthPtr = Instance.WinHelper.GetArg(5);

            WinPort Port = Instance.WinHelper.HandleManager.GetObjectByHandle<WinPort>(PortHandle);
            if (Port == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (InformationClass != AlpcMessageHandleInformation)
                return NTSTATUS.STATUS_INVALID_INFO_CLASS;

            if (ReturnLengthPtr != 0 && Instance.IsRegionMapped(ReturnLengthPtr, 4))
                Instance._emulator.WriteMemory(ReturnLengthPtr, (uint)HandleInformationSize);

            if (Length < HandleInformationSize)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            if (InformationPtr == 0 || !Instance.IsRegionMapped(InformationPtr, HandleInformationSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            List<ulong> Delivered = Port.DeliveredHandles;
            if (Delivered == null || Delivered.Count == 0)
                return NTSTATUS.STATUS_NO_MORE_ENTRIES;

            uint Index = Instance._emulator.ReadMemoryUInt(InformationPtr);
            if (Index >= (uint)Delivered.Count)
                return NTSTATUS.STATUS_NO_MORE_ENTRIES;

            ulong Delivering = Delivered[(int)Index];

            if ((Instance.Settings.Flags & LogFlags.General) != 0)
                Instance.TriggerEventMessage($"[+] ALPC handle 0x{Delivering:X} claimed from \"{Port.Name}\" (index {Index}).", LogFlags.General);

            Instance._emulator.WriteMemory(InformationPtr + 0x00, Index);
            Instance._emulator.WriteMemory(InformationPtr + 0x04, 0u);
            Instance._emulator.WriteMemory(InformationPtr + 0x08, (uint)Delivering);
            Instance._emulator.WriteMemory(InformationPtr + 0x0C, AlpcObjectType(Instance, Delivering));
            Instance._emulator.WriteMemory(InformationPtr + 0x10, (uint)AccessMask.StandardRightsAll);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static uint AlpcObjectType(BinaryEmulator Instance, ulong Handle)
        {
            IHandleObject Object = Instance.WinHelper.HandleManager.GetObjectByHandle(Handle);

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
