using System.Collections.Generic;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetKeyboardLayoutList : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint Items = (uint)Instance.WinHelper.GetArg(0);
            ulong ListPtr = Instance.WinHelper.GetArg(1);
            uint EntrySize = Instance.IsX86Guest ? 4u : 8u;

            IReadOnlyList<uint> Layouts = Win32kHelper.GetKeyboardLayouts(Instance);

            if (Items == 0 || ListPtr == 0)
            {
                Instance.SetRawSyscallReturn((uint)Layouts.Count);
                return NTSTATUS.STATUS_SUCCESS;
            }

            uint Written = Items < (uint)Layouts.Count ? Items : (uint)Layouts.Count;
            if (Written != 0 && !Instance.IsRegionMapped(ListPtr, (ulong)Written * EntrySize))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            for (uint Index = 0; Index < Written; Index++)
                Instance._emulator.WriteMemory(ListPtr + Index * EntrySize, Layouts[(int)Index], EntrySize);

            Instance.SetRawSyscallReturn(Written);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
