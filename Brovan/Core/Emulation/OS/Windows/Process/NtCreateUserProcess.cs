using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateUserProcess : IWinSyscall
    {
        private const uint PsCreateSuccess = 4;

        private const ulong PsAttributeClientId = 3 | 0x10000;
        private const ulong PsAttributeImageName = 5 | 0x20000;

        private const int CreateInfoStateOffset = 0x08;
        private const int CreateInfoSuccessFileHandleOffset = 0x18;
        private const int CreateInfoSuccessSectionHandleOffset = 0x20;
        private const int MaxAttributes = 32;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ProcessHandlePtr = Instance.WinHelper.GetArg(0);
            ulong ThreadHandlePtr = Instance.WinHelper.GetArg(1);
            ulong ProcessParameters = Instance.WinHelper.GetArg(8);
            ulong CreateInfo = Instance.WinHelper.GetArg(9);
            ulong AttributeList = Instance.WinHelper.GetArg(10);

            bool Is64 = Instance._binary.Architecture == BinaryArchitecture.x64;
            int PointerSize = Is64 ? 8 : 4;

            if (ProcessParameters == 0 || !Instance.IsRegionMapped(ProcessParameters, 0x40))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            string ImageNameHint = ReadImageNameAttribute(Instance, AttributeList, Is64);

            if (!GuestProcessLauncher.TryLaunch(Instance, ProcessParameters, ImageNameHint, out WinProcess Process, out NTSTATUS Status))
                return Status;

            WinSpawnedThread Thread = new WinSpawnedThread
            {
                Process = Process,
                ThreadId = Process.PID,
            };

            Instance.WinHelper.WinProcesses.Add(Process);

            ulong ProcessHandle = Instance.WinHelper.HandleManager.AddHandle(Process, AccessMask.GenericAll).Handle;
            ulong ThreadHandle = Instance.WinHelper.HandleManager.AddHandle(Thread, AccessMask.GenericAll).Handle;

            if (ProcessHandlePtr != 0 && Instance.IsRegionMapped(ProcessHandlePtr, (ulong)PointerSize))
                Instance._emulator.WriteMemory(ProcessHandlePtr, ProcessHandle, (uint)PointerSize);

            if (ThreadHandlePtr != 0 && Instance.IsRegionMapped(ThreadHandlePtr, (ulong)PointerSize))
                Instance._emulator.WriteMemory(ThreadHandlePtr, ThreadHandle, (uint)PointerSize);

            WriteCreateInfoSuccess(Instance, CreateInfo, Is64);
            WriteClientIdAttribute(Instance, AttributeList, Is64, Process.PID, Thread.ThreadId);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void WriteCreateInfoSuccess(BinaryEmulator Instance, ulong CreateInfo, bool Is64)
        {
            if (CreateInfo == 0 || !Instance.IsRegionMapped(CreateInfo, 0x58))
                return;

            Instance._emulator.WriteMemory(CreateInfo + CreateInfoStateOffset, PsCreateSuccess, 4);

            if (!Is64)
                return;

            Instance._emulator.WriteMemory(CreateInfo + CreateInfoSuccessFileHandleOffset, 0UL, 8);
            Instance._emulator.WriteMemory(CreateInfo + CreateInfoSuccessSectionHandleOffset, 0UL, 8);
        }

        private static void WriteClientIdAttribute(BinaryEmulator Instance, ulong AttributeList, bool Is64, uint ProcessId, uint ThreadId)
        {
            if (!TryFindAttribute(Instance, AttributeList, Is64, PsAttributeClientId, out ulong ValuePointer, out ulong Size))
                return;

            int PointerSize = Is64 ? 8 : 4;
            if (ValuePointer == 0 || Size < (ulong)(PointerSize * 2) || !Instance.IsRegionMapped(ValuePointer, Size))
                return;

            Instance._emulator.WriteMemory(ValuePointer, ProcessId, (uint)PointerSize);
            Instance._emulator.WriteMemory(ValuePointer + (ulong)PointerSize, ThreadId, (uint)PointerSize);
        }

        private static string ReadImageNameAttribute(BinaryEmulator Instance, ulong AttributeList, bool Is64)
        {
            if (!TryFindAttribute(Instance, AttributeList, Is64, PsAttributeImageName, out ulong ValuePointer, out ulong Size))
                return null;

            if (ValuePointer == 0 || Size == 0 || Size > 0x8000 || !Instance.IsRegionMapped(ValuePointer, Size))
                return null;

            return Instance._emulator.ReadMemoryString(ValuePointer, (int)Size, Encoding.Unicode)?.TrimEnd('\0');
        }

        private static bool TryFindAttribute(BinaryEmulator Instance, ulong AttributeList, bool Is64, ulong Attribute, out ulong ValuePointer, out ulong Size)
        {
            ValuePointer = 0;
            Size = 0;

            int PointerSize = Is64 ? 8 : 4;
            int EntrySize = PointerSize * 4;

            if (AttributeList == 0 || !Instance.IsRegionMapped(AttributeList, (ulong)PointerSize))
                return false;

            ulong TotalLength = Is64 ? Instance.ReadMemoryULong(AttributeList) : Instance.ReadMemoryUInt(AttributeList);
            if (TotalLength <= (uint)PointerSize)
                return false;

            ulong Count = (TotalLength - (ulong)PointerSize) / (ulong)EntrySize;
            if (Count == 0 || Count > MaxAttributes || !Instance.IsRegionMapped(AttributeList, TotalLength))
                return false;

            for (ulong i = 0; i < Count; i++)
            {
                ulong Entry = AttributeList + (ulong)PointerSize + i * (ulong)EntrySize;
                ulong EntryAttribute = Is64 ? Instance.ReadMemoryULong(Entry) : Instance.ReadMemoryUInt(Entry);
                if (EntryAttribute != Attribute)
                    continue;

                Size = Is64 ? Instance.ReadMemoryULong(Entry + (ulong)PointerSize) : Instance.ReadMemoryUInt(Entry + (ulong)PointerSize);
                ValuePointer = Is64 ? Instance.ReadMemoryULong(Entry + (ulong)(PointerSize * 2)) : Instance.ReadMemoryUInt(Entry + (ulong)(PointerSize * 2));
                return true;
            }

            return false;
        }
    }
}
