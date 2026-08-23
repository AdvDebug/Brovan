using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserUnregisterClass : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ClassNamePtr = Instance.WinHelper.GetArg(0);
            ulong InstanceHandle = Instance.WinHelper.GetArg(1);
            ulong ClassMenuNamePtr = Instance.WinHelper.GetArg(2);

            bool Read = Instance.WinHelper.TryReadUnicodeString(ClassNamePtr, out string ClassName, out _);
            bool Removed = Read && Instance.WinHelper.UnregisterWindowClass(InstanceHandle, ClassName);

            // user32 frees every pointer this returns, so it must be written even when the class had no menu name.
            if (Removed && ClassMenuNamePtr != 0)
            {
                uint PointerSize = (uint)Instance.WinHelper.PointerSize;
                if (!Instance.IsRegionMapped(ClassMenuNamePtr, PointerSize * 3))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                for (uint Index = 0; Index < 3; Index++)
                    Instance.WinHelper.WritePointer(ClassMenuNamePtr + Index * PointerSize, 0);
            }

            Instance.SetRawSyscallReturn(Removed ? 1u : 0u);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
