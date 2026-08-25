package dev.brovan.input;

import android.os.Handler;
import android.os.Looper;

import dev.brovan.BrovanNative;

/**
 * Where the guest's cursor was last put. The touchpad and the surface both move it, and the on-screen
 * mouse buttons click wherever it currently is.
 */
public final class PointerState {

    /** Games that poll the button state instead of reading messages miss a press with no duration. */
    private static final long CLICK_HOLD_MS = 70;

    private static final Handler handler = new Handler(Looper.getMainLooper());

    private static volatile int x;
    private static volatile int y;
    private static volatile float speed = 1f;

    private PointerState() {
    }

    /** Scales every finger movement, so the whole pointer feels the same wherever it is driven from. */
    public static void setSpeed(float value) {
        speed = value;
    }

    public static float speed() {
        return speed;
    }

    public static void moved(int px, int py) {
        x = px;
        y = py;
    }

    public static void click(int button) {
        press(button, true);
        handler.postDelayed(() -> press(button, false), CLICK_HOLD_MS);
    }

    public static void press(int button, boolean down) {
        int mask = button == BrovanNative.BUTTON_RIGHT ? BrovanNative.MK_RBUTTON
                : button == BrovanNative.BUTTON_MIDDLE ? BrovanNative.MK_MBUTTON : BrovanNative.MK_LBUTTON;

        BrovanNative.injectPointer(down ? BrovanNative.POINTER_DOWN : BrovanNative.POINTER_UP,
                button, x, y, down ? mask : 0);
    }
}
