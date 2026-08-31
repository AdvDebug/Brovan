using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetMsgBox : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);

            WinWindow Window = Hwnd == 0 ? null : Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            // The dialog controls already carry the text by the time user32 marks the box.
            Instance.TriggerEventMessage(() => $"[*] MessageBox: \"{Window.Title}\" | {CollectText(Instance, Window)}", LogFlags.General);

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static string CollectText(BinaryEmulator Instance, WinWindow Window)
        {
            StringBuilder Text = new StringBuilder();

            for (int Index = 0; Index < Window.Children.Count; Index++)
            {
                WinWindow Child = Instance.WinHelper.GetWindow(Window.Children[Index]);
                if (Child == null || string.IsNullOrEmpty(Child.Title))
                    continue;

                // A dialog template names an icon by ordinal, and user32 hands that through as the text.
                if (Child.Title[0] == '\uFFFF')
                    continue;

                if (Text.Length != 0)
                    Text.Append(" | ");

                Text.Append(Child.Title);
            }

            return Text.ToString();
        }
    }
}
