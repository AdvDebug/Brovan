using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserBuildHwndList : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ParentHwnd = Instance.WinHelper.GetArg(1);
            bool EnumChildren = Instance.WinHelper.GetArg(2) != 0;
            uint ThreadId = (uint)Instance.WinHelper.GetArg(4);
            uint MaxCount = (uint)Instance.WinHelper.GetArg(5);
            ulong ListPtr = Instance.WinHelper.GetArg(6);
            ulong NeededPtr = Instance.WinHelper.GetArg(7);

            if (NeededPtr == 0 || !Instance.IsRegionMapped(NeededPtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            List<ulong> Roots;
            if (ParentHwnd == 0)
            {
                Roots = Instance.WinHelper.TopLevelWindows;
            }
            else
            {
                WinWindow Parent = Instance.WinHelper.GetWindow(ParentHwnd);
                if (Parent == null)
                {
                    Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
                }

                Roots = Parent.Children;
            }

            List<ulong> Handles = new List<ulong>();
            Collect(Instance, Roots, EnumChildren, ThreadId, Handles);

            // The list user32 walks is terminated by a null entry, and the count covers it.
            uint Needed = (uint)Handles.Count + 1;
            if (!Instance._emulator.WriteMemory(NeededPtr, Needed, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Needed > MaxCount)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            uint PointerSize = (uint)Instance.WinHelper.PointerSize;
            uint ListBytes = Needed * PointerSize;

            if (ListPtr == 0 || !Instance.IsRegionMapped(ListPtr, ListBytes))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Span<byte> Data = Instance.WinHelper.Shared.GetSpan(ListBytes);
            Data = Data.Slice(0, (int)ListBytes);
            Data.Clear();

            for (int i = 0; i < Handles.Count; i++)
            {
                Span<byte> Slot = Data.Slice(i * (int)PointerSize, (int)PointerSize);
                if (PointerSize == 8)
                    BinaryPrimitives.WriteUInt64LittleEndian(Slot, Handles[i]);
                else
                    BinaryPrimitives.WriteUInt32LittleEndian(Slot, (uint)Handles[i]);
            }

            if (!Instance.WriteMemory(ListPtr, Data))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance.SetLastWinError(0);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void Collect(BinaryEmulator Instance, List<ulong> Windows, bool Recurse, uint ThreadId, List<ulong> Handles)
        {
            for (int i = 0; i < Windows.Count; i++)
            {
                WinWindow Window = Instance.WinHelper.GetWindow(Windows[i]);
                if (Window == null)
                    continue;

                if (ThreadId == 0 || Window.OwnerThreadId == ThreadId)
                    Handles.Add(Window.Hwnd);

                if (Recurse && Window.Children.Count != 0)
                    Collect(Instance, Window.Children, true, ThreadId, Handles);
            }
        }
    }
}
