package dev.brovan;

import android.content.Context;
import android.os.Build;
import android.util.AttributeSet;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputMethodManager;

import java.util.ArrayDeque;

import dev.brovan.input.KeyInputConnection;
import dev.brovan.input.KeyMap;
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
        DRAG,
        HOVER,
        TRACKPAD
    }

    private static final int TAP_SLOP = 40;
    private static final int TAP_TIMEOUT_MS = 400;
    private static final float TRACKPAD_SPEED = 1.6f;
    private static final float HOVER_SPEED = 1f;
    private static final long TYPING_STEP_MS = 40;
    private static final int TYPED_DOWN = 1 << 16;

    private PointerMode mode = PointerMode.DRAG;
    private boolean keyboardWanted;
    private final ArrayDeque<Integer> typing = new ArrayDeque<>();
    private final Runnable typeNext = this::typeNext;
    private KeyCharacterMap typingKeys;

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
        attachLayers(true);
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
        attachLayers(false);
    }

    private void attachLayers(boolean attached) {
        if (GuestLayers.available()) {
            GuestLayers.setParent(attached ? getSurfaceControl() : null);
        }
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

    public void showKeyboard() {
        keyboardWanted = true;
        requestFocus();
        InputMethodManager input = getContext().getSystemService(InputMethodManager.class);
        if (input != null) {
            input.restartInput(this);
        }

        // showSoftInput right after restartInput is dropped, but the insets controller waits for the new connection.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            WindowInsetsController insets = getWindowInsetsController();
            if (insets != null) {
                insets.show(WindowInsets.Type.ime());
                return;
            }
        }

        if (input != null) {
            post(() -> input.showSoftInput(this, 0));
        }
    }

    public void hideKeyboard() {
        keyboardWanted = false;
        InputMethodManager input = getContext().getSystemService(InputMethodManager.class);
        if (input != null) {
            input.hideSoftInputFromWindow(getWindowToken(), 0);
        }
    }

    @Override
    public boolean onCheckIsTextEditor() {
        return keyboardWanted;
    }

    @Override
    public InputConnection onCreateInputConnection(EditorInfo info) {
        return KeyInputConnection.create(this, info, new KeyInputConnection.Target() {
            @Override
            public void type(CharSequence text) {
                BrovanSurfaceView.this.type(text);
            }

            @Override
            public void delete(boolean forward) {
                press(forward ? KeyEvent.KEYCODE_FORWARD_DEL : KeyEvent.KEYCODE_DEL);
            }

            @Override
            public boolean editorAction() {
                press(KeyEvent.KEYCODE_ENTER);
                return true;
            }
        });
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        return key(true, keyCode, event) || super.onKeyDown(keyCode, event);
    }

    @Override
    public boolean onKeyUp(int keyCode, KeyEvent event) {
        return key(false, keyCode, event) || super.onKeyUp(keyCode, event);
    }

    private boolean key(boolean down, int keyCode, KeyEvent event) {
        if (fromSoftKeyboard(event)) {
            return softKey(down, keyCode, event);
        }

        return typing.isEmpty() ? sendKey(down, keyCode, event.getScanCode()) : queueKey(down, keyCode);
    }

    private static boolean fromSoftKeyboard(KeyEvent event) {
        return (event.getFlags() & KeyEvent.FLAG_SOFT_KEYBOARD) != 0
                || event.getDeviceId() == KeyCharacterMap.VIRTUAL_KEYBOARD;
    }

    // A soft keyboard puts Shift in the character key's meta state, so the key is typed with its own Shift presses.
    private boolean softKey(boolean down, int keyCode, KeyEvent event) {
        if (KeyEvent.isModifierKey(keyCode)) {
            return true;
        }

        int character = event.getUnicodeChar();
        if (character != 0 && (character & KeyCharacterMap.COMBINING_ACCENT) == 0) {
            if (down) {
                type(String.valueOf((char) character));
            }
            return true;
        }

        return queueKey(down, keyCode);
    }

    private boolean queueKey(boolean down, int keyCode) {
        if (KeyMap.toVirtualKey(keyCode) == 0) {
            return false;
        }

        queue(down, keyCode);
        return true;
    }

    @Override
    public boolean onKeyMultiple(int keyCode, int repeatCount, KeyEvent event) {
        if (keyCode == KeyEvent.KEYCODE_UNKNOWN && event.getCharacters() != null) {
            type(event.getCharacters());
            return true;
        }

        return super.onKeyMultiple(keyCode, repeatCount, event);
    }

    private void type(CharSequence text) {
        if (typingKeys == null) {
            typingKeys = KeyCharacterMap.load(KeyCharacterMap.VIRTUAL_KEYBOARD);
        }

        char[] one = new char[1];
        for (int i = 0; i < text.length(); i++) {
            one[0] = text.charAt(i);
            KeyEvent[] events = typingKeys.getEvents(one);
            if (events == null) {
                continue;
            }

            for (KeyEvent event : events) {
                queue(event.getAction() == KeyEvent.ACTION_DOWN, event.getKeyCode());
            }
        }
    }

    private void press(int keyCode) {
        queue(true, keyCode);
        queue(false, keyCode);
    }

    // The guest reads the key state when it translates a key, not when it was sent, so typed keys go out one at a time.
    private void queue(boolean down, int keyCode) {
        typing.add(down ? keyCode | TYPED_DOWN : keyCode);
        if (typing.size() == 1) {
            post(typeNext);
        }
    }

    private void typeNext() {
        Integer next = typing.poll();
        if (next == null) {
            return;
        }

        sendKey((next & TYPED_DOWN) != 0, next & ~TYPED_DOWN, 0);
        if (!typing.isEmpty()) {
            postDelayed(typeNext, TYPING_STEP_MS);
        }
    }

    private static boolean sendKey(boolean down, int keyCode, int scanCode) {
        int virtualKey = KeyMap.toVirtualKey(keyCode);
        if (virtualKey == 0) {
            return false;
        }

        BrovanNative.injectKey(down, virtualKey, scanCode);
        return true;
    }
}
