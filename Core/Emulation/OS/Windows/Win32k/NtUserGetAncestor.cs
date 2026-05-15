using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetAncestor : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            const uint GA_PARENT = 1;
            const uint GA_ROOT = 2;
            const uint GA_ROOTOWNER = 3;

            ulong Hwnd = Instance.WinHelper.GetArg64(0);
            uint Flags = (uint)Instance.WinHelper.GetArg64(1, true);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong Result = 0;

            switch (Flags)
            {
                case GA_PARENT:
                    Result = Window.ParentHwnd;
                    break;

                case GA_ROOT:
                    Result = GetRoot(Instance, Window);
                    break;

                case GA_ROOTOWNER:
                    Result = GetRootOwner(Instance, Window);
                    break;

                default:
                    Result = 0;
                    break;
            }

            Instance.SetRawSyscallReturn(Result);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static ulong GetRoot(BinaryEmulator Instance, WinWindow Window)
        {
            WinWindow Current = Window;

            while (Current.ParentHwnd != 0)
            {
                WinWindow Parent = Instance.WinHelper.GetWindow(Current.ParentHwnd);
                if (Parent == null)
                    break;

                Current = Parent;
            }

            return Current.Hwnd;
        }

        private static ulong GetRootOwner(BinaryEmulator Instance, WinWindow Window)
        {
            WinWindow Current = Window;

            while (true)
            {
                if (Current.ParentHwnd != 0)
                {
                    WinWindow Parent = Instance.WinHelper.GetWindow(Current.ParentHwnd);
                    if (Parent != null)
                    {
                        Current = Parent;
                        continue;
                    }
                }

                if (Current.OwnerHwnd != 0)
                {
                    WinWindow Owner = Instance.WinHelper.GetWindow(Current.OwnerHwnd);
                    if (Owner != null)
                    {
                        Current = Owner;
                        continue;
                    }
                }

                break;
            }

            return Current.Hwnd;
        }
    }
}