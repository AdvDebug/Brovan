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
            const ulong GdiSharedMemoryObjectsOffset64 = 0x1800B0;
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
            {
                if (Instance.PEB != 0)
                    Instance._emulator.WriteMemory(Instance.PEB + GdiSharedHandleTableOffset32, 0u);

                return NTSTATUS.STATUS_WAIT_1;
            }

            ulong GdiSharedHandleTable = Instance.ReadMemoryULong(Instance.PEB + GdiSharedHandleTableOffset64);
            if (GdiSharedHandleTable == 0)
            {
                GdiSharedHandleTable = Instance.MapUniqueAddress(GdiSharedMemorySize64, MemoryProtection.ReadWrite);
                if (GdiSharedHandleTable == 0)
                    return NTSTATUS.STATUS_NO_MEMORY;

                Instance._emulator.WriteMemory(GdiSharedHandleTable + GdiSharedMemoryObjectsOffset64 + (0x12UL * 8), 1UL, 8);
                Instance._emulator.WriteMemory(GdiSharedHandleTable + GdiSharedMemoryObjectsOffset64 + (0x13UL * 8), 1UL, 8);
                Instance._emulator.WriteMemory(Instance.PEB + GdiSharedHandleTableOffset64, GdiSharedHandleTable, 8);
            }

            return NTSTATUS.STATUS_WAIT_1;
        }
    }
}