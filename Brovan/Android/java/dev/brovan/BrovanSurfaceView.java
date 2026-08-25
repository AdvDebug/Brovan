package dev.brovan;

import android.content.Context;
import android.util.AttributeSet;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.SurfaceHolder;
import android.view.SurfaceView;

import dev.brovan.input.PointerState;

/**
 * Feeds the emulator its Surface and turns touch and key events into the Win32 messages the guest expects.
 *
 * The Activity hosting this view must declare
 * android:configChanges="orientation|screenSize|screenLayout|keyboardHidden|density"
 * so it is not recreated: a Surface swap invalidates the VkSurfaceKHR the guest already holds, and the
 * emulator cannot rebuild a swapchain behind a running guest.
 */
public class BrovanSurfaceView extends SurfaceView implements SurfaceHolder.Callback {

    /** How a finger on the guest picture is turned into pointer input. */
    public enum PointerMode {
        DRAG("Touch drags with the button held"),
        HOVER("Drag moves the cursor, tap clicks"),
        TRACKPAD("Whole screen is a trackpad");

        private final String label;

        PointerMode(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    private static final int TAP_SLOP = 40;
    private static final int TAP_TIMEOUT_MS = 400;
    private static final float TRACKPAD_SPEED = 1.6f;
    private static final float HOVER_SPEED = 1f;

    private PointerMode mode = PointerMode.DRAG;

    private int buttons;
    private float cursorX;
    private float cursorY;
    private float lastX;
    private float lastY;
    private float travelled;
    private float travelX;
    private float travelY;
    private long downAt;
    private boolean secondFinger;
    private boolean moving;
    private int pointerId = MotionEvent.INVALID_POINTER_ID;

    public BrovanSurfaceView(Context context) {
        super(context);
        initialize();
    }

    public BrovanSurfaceView(Context context, AttributeSet attrs) {
        super(context, attrs);
        initialize();
    }

    private void initialize() {
        getHolder().addCallback(this);
        setFocusable(true);
        setFocusableInTouchMode(true);
    }

    @Override
    public void surfaceCreated(SurfaceHolder holder) {
        BrovanNative.setSurface(holder.getSurface(), getResources().getDisplayMetrics().densityDpi);
        BrovanNative.injectFocus(true);
    }

    @Override
    public void surfaceChanged(SurfaceHolder holder, int format, int width, int height) {
        BrovanNative.setSurface(holder.getSurface(), getResources().getDisplayMetrics().densityDpi);
    }

    @Override
    public void surfaceDestroyed(SurfaceHolder holder) {
        BrovanNative.injectFocus(false);
        BrovanNative.clearSurface();
    }

    public void setPointerMode(PointerMode value) {
        mode = value;
    }

    @Override
    protected void onSizeChanged(int width, int height, int oldWidth, int oldHeight) {
        super.onSizeChanged(width, height, oldWidth, oldHeight);
        cursorX = width / 2f;
        cursorY = height / 2f;
        PointerState.moved((int) cursorX, (int) cursorY);
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        switch (event.getActionMasked()) {
            case MotionEvent.ACTION_DOWN: {
                int index = event.getActionIndex();
                pointerId = event.getPointerId(index);
                lastX = event.getX(index);
                lastY = event.getY(index);
                travelled = 0f;
                downAt = event.getEventTime();
                secondFinger = false;
                moving = mode == PointerMode.DRAG;

                if (moving) {
                    cursorX = lastX;
                    cursorY = lastY;
                    move();
                    buttons |= BrovanNative.MK_LBUTTON;
                    inject(BrovanNative.POINTER_DOWN);
                }

                return true;
            }

            case MotionEvent.ACTION_POINTER_DOWN:
                // A second finger means the gesture is a right click, so whatever the first one started
                // has to be let go of before it turns into a drag.
                secondFinger = true;
                releaseLeft();
                return true;

            case MotionEvent.ACTION_MOVE: {
                int index = event.findPointerIndex(pointerId);
                if (index < 0) {
                    return true;
                }

                float dx = event.getX(index) - lastX;
                float dy = event.getY(index) - lastY;
                lastX = event.getX(index);
                lastY = event.getY(index);
                travelled += Math.abs(dx) + Math.abs(dy);

                // The cursor stays where it is until the finger has travelled far enough to mean a move,
                // so a tap clicks the spot the guest is already pointing at instead of jumping to the finger.
                if (!moving) {
                    if (travelled < TAP_SLOP) {
                        return true;
                    }

                    moving = true;
                }

                float speed = (mode == PointerMode.TRACKPAD ? TRACKPAD_SPEED : HOVER_SPEED) * PointerState.speed();

                if (mode == PointerMode.DRAG) {
                    cursorX = lastX;
                    cursorY = lastY;
                } else {
                    cursorX = clamp(cursorX + dx * speed, getWidth());
                    cursorY = clamp(cursorY + dy * speed, getHeight());
                }

                reportTravel(dx * speed, dy * speed);
                move();
                return true;
            }

            case MotionEvent.ACTION_UP: {
                boolean tapped = travelled < TAP_SLOP && event.getEventTime() - downAt < TAP_TIMEOUT_MS;
                pointerId = MotionEvent.INVALID_POINTER_ID;
                releaseLeft();

                if (secondFinger) {
                    if (tapped) {
                        PointerState.click(BrovanNative.BUTTON_RIGHT);
                    }
                } else if (mode != PointerMode.DRAG && tapped) {
                    PointerState.click(BrovanNative.BUTTON_LEFT);
                }

                return true;
            }

            case MotionEvent.ACTION_CANCEL:
                pointerId = MotionEvent.INVALID_POINTER_ID;
                releaseLeft();
                return true;

            default:
                return super.onTouchEvent(event);
        }
    }

    // A guest in mouselook reads travel, not the cursor, and the cursor has already stopped at the edge of
    // the surface by the time the finger is still going. The fraction is carried so slow movement is not lost.
    private void reportTravel(float dx, float dy) {
        travelX += dx;
        travelY += dy;

        int wholeX = (int) travelX;
        int wholeY = (int) travelY;
        travelX -= wholeX;
        travelY -= wholeY;

        BrovanNative.injectMouseTravel(wholeX, wholeY);
    }

    private void move() {
        PointerState.moved((int) cursorX, (int) cursorY);
        inject(BrovanNative.POINTER_MOVE);
    }

    private void releaseLeft() {
        if ((buttons & BrovanNative.MK_LBUTTON) == 0) {
            return;
        }

        buttons &= ~BrovanNative.MK_LBUTTON;
        inject(BrovanNative.POINTER_UP);
    }

    private void inject(int action) {
        BrovanNative.injectPointer(action, BrovanNative.BUTTON_LEFT, (int) cursorX, (int) cursorY, buttons);
    }

    private static float clamp(float value, int limit) {
        return Math.max(0f, Math.min(value, limit));
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        int virtualKey = toVirtualKey(keyCode);
        if (virtualKey == 0) {
            return super.onKeyDown(keyCode, event);
        }

        BrovanNative.injectKey(true, virtualKey, event.getScanCode());
        return true;
    }

    @Override
    public boolean onKeyUp(int keyCode, KeyEvent event) {
        int virtualKey = toVirtualKey(keyCode);
        if (virtualKey == 0) {
            return super.onKeyUp(keyCode, event);
        }

        BrovanNative.injectKey(false, virtualKey, event.getScanCode());
        return true;
    }

    /** Android keycodes are positional; the guest speaks Win32 virtual-key codes. */
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
