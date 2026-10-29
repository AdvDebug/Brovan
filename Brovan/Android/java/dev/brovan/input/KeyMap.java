package dev.brovan.input;

import android.view.KeyEvent;

public final class KeyMap {

    public static final int RIGHT_ALT_PRESSED = 0x0001;
    public static final int LEFT_ALT_PRESSED = 0x0002;
    public static final int RIGHT_CTRL_PRESSED = 0x0004;
    public static final int LEFT_CTRL_PRESSED = 0x0008;
    public static final int SHIFT_PRESSED = 0x0010;
    public static final int NUMLOCK_ON = 0x0020;
    public static final int SCROLLLOCK_ON = 0x0040;
    public static final int CAPSLOCK_ON = 0x0080;

    private KeyMap() {
    }

    public static int controlKeyState(int metaState) {
        int state = 0;
        if ((metaState & KeyEvent.META_ALT_RIGHT_ON) != 0) state |= RIGHT_ALT_PRESSED;
        if ((metaState & KeyEvent.META_ALT_LEFT_ON) != 0) state |= LEFT_ALT_PRESSED;
        if ((metaState & KeyEvent.META_CTRL_RIGHT_ON) != 0) state |= RIGHT_CTRL_PRESSED;
        if ((metaState & KeyEvent.META_CTRL_LEFT_ON) != 0) state |= LEFT_CTRL_PRESSED;
        if ((metaState & KeyEvent.META_SHIFT_ON) != 0) state |= SHIFT_PRESSED;
        if ((metaState & KeyEvent.META_NUM_LOCK_ON) != 0) state |= NUMLOCK_ON;
        if ((metaState & KeyEvent.META_SCROLL_LOCK_ON) != 0) state |= SCROLLLOCK_ON;
        if ((metaState & KeyEvent.META_CAPS_LOCK_ON) != 0) state |= CAPSLOCK_ON;
        return state;
    }

    public static int toVirtualKey(int keyCode) {
        if (keyCode >= KeyEvent.KEYCODE_A && keyCode <= KeyEvent.KEYCODE_Z) {
            return 0x41 + (keyCode - KeyEvent.KEYCODE_A);
        }

        if (keyCode >= KeyEvent.KEYCODE_0 && keyCode <= KeyEvent.KEYCODE_9) {
            return 0x30 + (keyCode - KeyEvent.KEYCODE_0);
        }

        if (keyCode >= KeyEvent.KEYCODE_F1 && keyCode <= KeyEvent.KEYCODE_F12) {
            return 0x70 + (keyCode - KeyEvent.KEYCODE_F1);
        }

        if (keyCode >= KeyEvent.KEYCODE_NUMPAD_0 && keyCode <= KeyEvent.KEYCODE_NUMPAD_9) {
            return 0x60 + (keyCode - KeyEvent.KEYCODE_NUMPAD_0);
        }

        switch (keyCode) {
            case KeyEvent.KEYCODE_DEL: return 0x08;
            case KeyEvent.KEYCODE_TAB: return 0x09;
            case KeyEvent.KEYCODE_ENTER:
            case KeyEvent.KEYCODE_NUMPAD_ENTER: return 0x0D;
            case KeyEvent.KEYCODE_SHIFT_LEFT: return 0xA0;
            case KeyEvent.KEYCODE_SHIFT_RIGHT: return 0xA1;
            case KeyEvent.KEYCODE_CTRL_LEFT: return 0xA2;
            case KeyEvent.KEYCODE_CTRL_RIGHT: return 0xA3;
            case KeyEvent.KEYCODE_ALT_LEFT: return 0x12;
            case KeyEvent.KEYCODE_ALT_RIGHT: return 0xA5;
            case KeyEvent.KEYCODE_CAPS_LOCK: return 0x14;
            case KeyEvent.KEYCODE_ESCAPE: return 0x1B;
            case KeyEvent.KEYCODE_SPACE: return 0x20;
            case KeyEvent.KEYCODE_PAGE_UP: return 0x21;
            case KeyEvent.KEYCODE_PAGE_DOWN: return 0x22;
            case KeyEvent.KEYCODE_MOVE_END: return 0x23;
            case KeyEvent.KEYCODE_MOVE_HOME: return 0x24;
            case KeyEvent.KEYCODE_DPAD_LEFT: return 0x25;
            case KeyEvent.KEYCODE_DPAD_UP: return 0x26;
            case KeyEvent.KEYCODE_DPAD_RIGHT: return 0x27;
            case KeyEvent.KEYCODE_DPAD_DOWN: return 0x28;
            case KeyEvent.KEYCODE_INSERT: return 0x2D;
            case KeyEvent.KEYCODE_FORWARD_DEL: return 0x2E;
            case KeyEvent.KEYCODE_NUMPAD_MULTIPLY: return 0x6A;
            case KeyEvent.KEYCODE_NUMPAD_ADD: return 0x6B;
            case KeyEvent.KEYCODE_NUMPAD_SUBTRACT: return 0x6D;
            case KeyEvent.KEYCODE_NUMPAD_DOT: return 0x6E;
            case KeyEvent.KEYCODE_NUMPAD_DIVIDE: return 0x6F;
            case KeyEvent.KEYCODE_NUM_LOCK: return 0x90;
            case KeyEvent.KEYCODE_SCROLL_LOCK: return 0x91;
            case KeyEvent.KEYCODE_SEMICOLON: return 0xBA;
            case KeyEvent.KEYCODE_EQUALS: return 0xBB;
            case KeyEvent.KEYCODE_COMMA: return 0xBC;
            case KeyEvent.KEYCODE_MINUS: return 0xBD;
            case KeyEvent.KEYCODE_PERIOD: return 0xBE;
            case KeyEvent.KEYCODE_SLASH: return 0xBF;
            case KeyEvent.KEYCODE_GRAVE: return 0xC0;
            case KeyEvent.KEYCODE_LEFT_BRACKET: return 0xDB;
            case KeyEvent.KEYCODE_BACKSLASH: return 0xDC;
            case KeyEvent.KEYCODE_RIGHT_BRACKET: return 0xDD;
            case KeyEvent.KEYCODE_APOSTROPHE: return 0xDE;
            default: return 0;
        }
    }
}
