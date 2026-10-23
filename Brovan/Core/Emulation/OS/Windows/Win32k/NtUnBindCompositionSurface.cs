namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUnBindCompositionSurface : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong SurfaceHandle = Instance.WinHelper.GetArg(0);
            bool KeepBuffers = (uint)Instance.WinHelper.GetArg(1) != 0;

            NTSTATUS Status = Instance.WinHelper.ReferenceObjectByHandle(SurfaceHandle, AccessMask.CompositionSurfaceBind, out DxgkCompositionSurface Surface);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            // NT: keeping the buffers only ends the active binding, and the buffer on screen stays.
            if (!KeepBuffers)
                Surface.ReleaseBuffers(Instance, Instance.WinHelper.DxgkProcess);
            else if (Surface.ActiveBuffer is DxgkCompositionBuffer Active)
                Active.Active = false;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
