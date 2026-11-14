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
            ulong Window = Surface.ActiveBuffer?.Window ?? 0;
            if (!KeepBuffers)
                Surface.ReleaseBuffers(Instance, Instance.WinHelper.DxgkProcess);
            else if (Surface.ActiveBuffer is DxgkCompositionBuffer Active)
                Active.Active = false;

            // NT changes the window's surface even when it holds another one (UserRemoveWindowedSwapChain).
            if (Window != 0 && Instance.WinHelper.GetWindow(Window) is WinWindow Target && Win32kHelper.MaskFunctionId(Target.Fnid) != Win32kHelper.FnidDesktop)
            {
                if (KeepBuffers)
                {
                    Target.SwapChainReplaceable |= Target.SwapChainSurface != null;
                }
                else
                {
                    ReferencedNtObject.Hold(Instance, ref Target.SwapChainSurface, null);
                    Target.SwapChainReplaceable = false;
                }
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
