using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiInit : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            const ulong GdiSharedHandleTableOffset64 = 0xF8;
            const ulong GdiSharedHandleTableOffset32 = 0x94;
            const ulong GdiSharedMemorySize64 = 0x1811B0;

            ulong NativePeb = Instance.NativePEB;
            if (NativePeb == 0)
                return NTSTATUS.STATUS_WAIT_1;

            ulong GdiSharedHandleTable = Instance.ReadMemoryULong(NativePeb + GdiSharedHandleTableOffset64);
            if (GdiSharedHandleTable == 0)
            {
                GdiSharedHandleTable = Instance.MapUniqueAddress(GdiSharedMemorySize64, MemoryProtection.ReadWrite);
                if (GdiSharedHandleTable == 0)
                    return NTSTATUS.STATUS_NO_MEMORY;

                Instance._emulator.WriteMemory(NativePeb + GdiSharedHandleTableOffset64, GdiSharedHandleTable, 8);

                // The SysWOW64 gdi32 reads the table through the native PEB, the 32-bit field is kept for anything that still looks there.
                if (Instance._binary.Architecture != BinaryArchitecture.x64 && Instance.PEB != 0)
                    Instance._emulator.WriteMemory(Instance.PEB + GdiSharedHandleTableOffset32, (uint)GdiSharedHandleTable);

                Win32kHelper.PublishStockObjects(Instance, GdiSharedHandleTable);
            }

            Instance.WinHelper.PublishSystemColors();
            return NTSTATUS.STATUS_WAIT_1;
        }
    }
}