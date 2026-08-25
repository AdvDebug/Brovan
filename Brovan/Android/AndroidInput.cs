using Brovan.Core.Emulation.OS.SharedHelpers;

namespace Brovan.Android
{
    internal enum PointerAction
    {
        Move = 0,
        Down = 1,
        Up = 2,
    }

    internal enum PointerButton
    {
        Left = 0,
        Middle = 1,
        Right = 2,
    }

    internal static class AndroidInput
    {
        private const uint WM_SIZE = 0x0005;
        private const uint WM_SETFOCUS = 0x0007;
        private const uint WM_KILLFOCUS = 0x0008;
        private const uint WM_KEYDOWN = 0x0100;
        private const uint WM_KEYUP = 0x0101;
        private const uint WM_SYSKEYDOWN = 0x0104;
        private const uint WM_SYSKEYUP = 0x0105;
        private const uint WM_MOUSEMOVE = 0x0200;
        private const uint WM_LBUTTONDOWN = 0x0201;
        private const uint WM_LBUTTONUP = 0x0202;
        private const uint WM_RBUTTONDOWN = 0x0204;
        private const uint WM_RBUTTONUP = 0x0205;
        private const uint WM_MBUTTONDOWN = 0x0207;
        private const uint WM_MBUTTONUP = 0x0208;
        private const uint WM_MOUSEWHEEL = 0x020A;

        private const uint VK_MENU = 0x12;

        private static bool _altHeld;

        public static void Pointer(PointerAction action, PointerButton button, int x, int y, uint buttons)
        {
            uint message = action switch
            {
                PointerAction.Down => button switch
                {
                    PointerButton.Middle => WM_MBUTTONDOWN,
                    PointerButton.Right => WM_RBUTTONDOWN,
                    _ => WM_LBUTTONDOWN,
                },
                PointerAction.Up => button switch
                {
                    PointerButton.Middle => WM_MBUTTONUP,
                    PointerButton.Right => WM_RBUTTONUP,
                    _ => WM_LBUTTONUP,
                },
                _ => WM_MOUSEMOVE,
            };

            HostEventQueue.Enqueue(message, buttons, MakeLParam(x, y));
        }

        // Travel the finger reported, not the difference between two cursor positions: the cursor stops at the
        // edge of the surface and a guest turning on the spot would run out of room to turn.
        public static void MouseTravel(int deltaX, int deltaY)
        {
            HostEventQueue.EnqueueRawMouseMotion(deltaX, deltaY);
        }

        public static void Scroll(int delta, int x, int y, uint buttons)
        {
            HostEventQueue.Enqueue(WM_MOUSEWHEEL, buttons | ((ulong)(ushort)(short)delta << 16), MakeLParam(x, y));
        }

        public static void Key(bool down, uint virtualKey, uint scanCode)
        {
            if (virtualKey == VK_MENU)
                _altHeld = down;

            uint message = down
                ? (_altHeld ? WM_SYSKEYDOWN : WM_KEYDOWN)
                : (_altHeld ? WM_SYSKEYUP : WM_KEYUP);

            HostEventQueue.Enqueue(message, virtualKey, BuildKeyLParam(scanCode, virtualKey, down, _altHeld));
        }

        public static void Focus(bool focused)
        {
            HostEventQueue.Enqueue(focused ? WM_SETFOCUS : WM_KILLFOCUS, 0, 0);
        }

        public static void Resize(int width, int height)
        {
            HostEventQueue.Enqueue(WM_SIZE, 0, MakeLParam(width, height));
            HostEventQueue.MarkRepaint();
        }

        private static ulong MakeLParam(int low, int high)
        {
            return (ulong)(uint)(((high & 0xFFFF) << 16) | (low & 0xFFFF));
        }

        private static ulong BuildKeyLParam(uint scanCode, uint virtualKey, bool down, bool altHeld)
        {
            ulong lParam = 1;
            lParam |= (ulong)(scanCode & 0xFF) << 16;

            if (IsExtendedKey(virtualKey))
                lParam |= 1UL << 24;

            if (altHeld)
                lParam |= 1UL << 29;

            if (!down)
                lParam |= (1UL << 30) | (1UL << 31);

            return lParam;
        }

        private static bool IsExtendedKey(uint virtualKey)
        {
            switch (virtualKey)
            {
                case 0x21: // VK_PRIOR
                case 0x22: // VK_NEXT
                case 0x23: // VK_END
                case 0x24: // VK_HOME
                case 0x25: // VK_LEFT
                case 0x26: // VK_UP
                case 0x27: // VK_RIGHT
                case 0x28: // VK_DOWN
                case 0x2C: // VK_SNAPSHOT
                case 0x2D: // VK_INSERT
                case 0x2E: // VK_DELETE
                case 0x6F: // VK_DIVIDE
                case 0x90: // VK_NUMLOCK
                case 0xA3: // VK_RCONTROL
                case 0xA5: // VK_RMENU
                    return true;
                default:
                    return false;
            }
        }
    }
}
