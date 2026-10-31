using System.Runtime.InteropServices;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiModifyWorldTransform : IWinSyscall
    {
        private const int XformFloats = 6;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            ulong XformPtr = Instance.WinHelper.GetArg(1);
            uint Mode = Instance.WinHelper.GetArg32(2);

            Span<float> Xform = stackalloc float[XformFloats];
            if (XformPtr != 0 ? !Instance.ReadMemory(XformPtr, MemoryMarshal.AsBytes(Xform)) : Mode != Win32kHelper.WorldTransformIdentity)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetRawSyscallReturn(Win32kHelper.TryModifyWorldTransform(Instance, Hdc, Xform, Mode) ? 1UL : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
