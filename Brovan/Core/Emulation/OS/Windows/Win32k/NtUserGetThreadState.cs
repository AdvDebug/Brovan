using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetThreadState : IWinSyscall
    {
        private const uint ThreadStateCaptureWindow = 0x2;
        private const uint ThreadStateWin32ThreadInfo = 0xE;
        private const ulong Win32ThreadInfoSlabSizeX64 = 0x2000;
        private const ulong Win32ThreadInfoBiasX64 = 0x800;
        private const ulong Win32ThreadInfoSlabSizeX86 = 0x1000;
        private const ulong Win32ThreadInfoBiasX86 = 0x400;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint Routine;

            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                Routine = (uint)Instance.WinHelper.GetArg(0);
            }
            else
            {
                Routine = (uint)Instance.WinHelper.GetArg(0);
            }

            if (Routine == ThreadStateCaptureWindow)
            {
                Instance.SetRawSyscallReturn(Win32kHelper.GetCaptureWindow(Instance));
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Routine != ThreadStateWin32ThreadInfo)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null || WinEmulatedThread.GetState(Thread).Teb == 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_UNSUCCESSFUL;
            }

            ulong ThreadInfo = EnsureWin32ThreadInfo(Instance, Thread);
            if (ThreadInfo == 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_UNSUCCESSFUL;
            }

            PopulateWin32ThreadInfo(Instance, Thread, ThreadInfo);
            Instance.SetRawSyscallReturn(ThreadInfo);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static ulong EnsureWin32ThreadInfo(BinaryEmulator Instance, EmulatedThread Thread)
        {
            if (WinEmulatedThread.GetState(Thread).Win32ThreadInfo != 0)
                return WinEmulatedThread.GetState(Thread).Win32ThreadInfo;

            ulong TebThreadInfo = GetThreadInfo(Instance, Thread);
            if (TebThreadInfo != 0)
            {
                WinEmulatedThread.GetState(Thread).Win32ThreadInfo = TebThreadInfo;
                return TebThreadInfo;
            }

            ulong SlabSize = Instance._binary.Architecture == BinaryArchitecture.x64 ? Win32ThreadInfoSlabSizeX64 : Win32ThreadInfoSlabSizeX86;
            ulong Bias = Instance._binary.Architecture == BinaryArchitecture.x64 ? Win32ThreadInfoBiasX64 : Win32ThreadInfoBiasX86;
            ulong SlabBase = Instance.MapUniqueAddress(SlabSize, MemoryProtection.ReadWrite);
            if (SlabBase == 0)
                return 0;

            if (!Instance.WinHelper.WriteZeroMemory(SlabBase, (uint)SlabSize))
                return 0;

            WinEmulatedThread.GetState(Thread).Win32ThreadInfo = SlabBase + Bias;
            return WinEmulatedThread.GetState(Thread).Win32ThreadInfo;
        }

        private static ulong GetThreadInfo(BinaryEmulator Instance, EmulatedThread Thread)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
                return Instance.ReadMemoryULong(WinEmulatedThread.GetState(Thread).Teb + 0x78);

            return Instance.ReadMemoryUInt(WinEmulatedThread.GetState(Thread).Teb + 0x40);
        }

        private static void PopulateWin32ThreadInfo(BinaryEmulator Instance, EmulatedThread Thread, ulong ThreadInfo)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                uint Low = (uint)(ThreadInfo & 0xFFFFFFFFul);
                uint High = (uint)((ThreadInfo >> 32) & 0xFFFFFFFFul);
                Instance._emulator.WriteMemory(WinEmulatedThread.GetState(Thread).Teb + 0x78, ThreadInfo);
                Instance._emulator.WriteMemory(WinEmulatedThread.GetState(Thread).Teb + 0xE8, Low, 4);
                Instance._emulator.WriteMemory(WinEmulatedThread.GetState(Thread).Teb + 0xF0, High, 4);
                Instance.WinHelper.EnsureUserClientThreadInfo(Thread, ThreadInfo);
                return;
            }

            uint ThreadInfo32 = (uint)ThreadInfo;
            Instance._emulator.WriteMemory(WinEmulatedThread.GetState(Thread).Teb + 0x40, ThreadInfo32);
            Instance._emulator.WriteMemory(WinEmulatedThread.GetState(Thread).Teb + 0x78, ThreadInfo32);
            Instance._emulator.WriteMemory(WinEmulatedThread.GetState(Thread).Teb + 0x7C, 0u);
            Instance.WinHelper.EnsureUserClientThreadInfo(Thread, ThreadInfo);
        }
    }
}
