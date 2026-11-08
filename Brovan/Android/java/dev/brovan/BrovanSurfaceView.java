package dev.brovan;

import android.content.Context;
import android.graphics.Point;
import android.graphics.Rect;
import android.os.Build;
import android.util.AttributeSet;
import android.util.DisplayMetrics;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.Surface;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.view.WindowManager;
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

    public static final int AUTO_DPI = 0;

    public static final int BASE_DPI = 96;
    public static final int DPI_STEP = 24;

    private static final int DESKTOP_WIDTH = 1280;
    private static final int DESKTOP_HEIGHT = 720;

    private static final int TAP_SLOP = 40;
    private static final int TAP_TIMEOUT_MS = 400;
    private static final int PAIR_TIMEOUT_MS = 100;
    private static final float PAIR_SPREAD_MM = 30f;
    private static final int NOTCH_TRAVEL_PX = 48;
    private static final float TRACKPAD_SPEED = 1.6f;
    private static final float HOVER_SPEED = 1f;
    private static final long TYPING_STEP_MS = 40;
    private static final int TYPED_DOWN = 1 << 16;

    private PointerMode mode = PointerMode.DRAG;
    private int displayDpi = AUTO_DPI;
    private int reportedDpi;
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
    private boolean pressPending;
    private final Runnable pressLeft = this::pressLeft;
    private int pointerId = MotionEvent.INVALID_POINTER_ID;
    private int pairId = MotionEvent.INVALID_POINTER_ID;
    private float pairX1;
    private float pairY1;
    private float pairX2;
    private float pairY2;
    private boolean scrolling;
    private float scrollY;
    private float scrollCarry;

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
        publishSurface(holder.getSurface());
        BrovanNative.injectFocus(true);
    }

    @Override
    public void surfaceChanged(SurfaceHolder holder, int format, int width, int height) {
        publishSurface(holder.getSurface());
    }

    private void publishSurface(Surface surface) {
        reportedDpi = displayDpi != AUTO_DPI ? displayDpi : autoDpi();
        BrovanNative.setSurface(surface, reportedDpi);
    }

    public void setDisplayDpi(int dpi) {
        displayDpi = dpi;
        Surface surface = getHolder().getSurface();
        if (surface != null && surface.isValid()) {
            publishSurface(surface);
        }
    }

    // Uses the full window size, which stays the same while system bars or a menu shrink the surface.
    private int autoDpi() {
        WindowManager windows = getContext().getSystemService(WindowManager.class);
        int width;
        int height;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Rect bounds = windows.getMaximumWindowMetrics().getBounds();
            width = bounds.width();
            height = bounds.height();
        } else {
            Point size = new Point();
            windows.getDefaultDisplay().getRealSize(size);
            width = size.x;
            height = size.y;
        }
        return autoDpi(width, height, getResources().getDisplayMetrics().densityDpi);
    }

    public int reportedDpi() {
        return reportedDpi;
    }

    private static int autoDpi(int width, int height, int densityDpi) {
        int longSide = Math.max(width, height);
        int shortSide = Math.min(width, height);
        int dpi = Math.min(longSide * BASE_DPI / DESKTOP_WIDTH, shortSide * BASE_DPI / DESKTOP_HEIGHT);
        dpi = Math.min(dpi, densityDpi) / DPI_STEP * DPI_STEP;
        return Math.max(dpi, BASE_DPI);
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
                moving = false;
                pairId = MotionEvent.INVALID_POINTER_ID;
                scrolling = false;

                // The press waits for a second finger, so a right click or a scroll does not click first.
                if (mode == PointerMode.DRAG) {
                    cursorX = lastX;
                    cursorY = lastY;
                    move();
                    pressPending = true;
                    postDelayed(pressLeft, PAIR_TIMEOUT_MS);
                }

                return true;
            }

            case MotionEvent.ACTION_POINTER_DOWN:
                cancelPress();
                if (!secondFinger && event.getPointerCount() == 2 && travelled < TAP_SLOP
                        && event.getEventTime() - downAt <= PAIR_TIMEOUT_MS) {
                    startPair(event, event.getActionIndex());
                } else if (!scrolling) {
                    pairId = MotionEvent.INVALID_POINTER_ID;
                }

                // A second finger means the gesture is a right click or a scroll, so whatever the first one
                // started has to be let go of before it turns into a drag.
                secondFinger = true;
                releaseLeft();
                return true;

            case MotionEvent.ACTION_MOVE: {
                if (scrolling) {
                    scroll(event);
                    return true;
                }

                int index = event.findPointerIndex(pointerId);
                if (index < 0) {
                    return true;
                }

                float dx = event.getX(index) - lastX;
                float dy = event.getY(index) - lastY;
                lastX = event.getX(index);
                lastY = event.getY(index);
                travelled += Math.abs(dx) + Math.abs(dy);

                if (pairId != MotionEvent.INVALID_POINTER_ID && pairHeld(event)) {
                    return true;
                }

                // The cursor stays where it is until the finger has travelled far enough to mean a move,
                // so a tap clicks the spot the guest is already pointing at instead of jumping to the finger.
                if (!moving) {
                    if (travelled < TAP_SLOP) {
                        return true;
                    }

                    if (cancelPress()) {
                        pressLeft();
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
                boolean pressWasPending = cancelPress();
                pointerId = MotionEvent.INVALID_POINTER_ID;
                pairId = MotionEvent.INVALID_POINTER_ID;
                releaseLeft();

                if (scrolling) {
                    scrolling = false;
                } else if (secondFinger) {
                    if (tapped) {
                        PointerState.click(BrovanNative.BUTTON_RIGHT);
                    }
                } else if (pressWasPending || (mode != PointerMode.DRAG && tapped)) {
                    PointerState.click(BrovanNative.BUTTON_LEFT);
                }

                return true;
            }

            case MotionEvent.ACTION_CANCEL:
                cancelPress();
                pointerId = MotionEvent.INVALID_POINTER_ID;
                pairId = MotionEvent.INVALID_POINTER_ID;
                scrolling = false;
                releaseLeft();
                return true;

            default:
                return super.onTouchEvent(event);
        }
    }

    private void pressLeft() {
        pressPending = false;
        moving = true;
        buttons |= BrovanNative.MK_LBUTTON;
        inject(BrovanNative.POINTER_DOWN);
    }

    private boolean cancelPress() {
        if (!pressPending) {
            return false;
        }

        pressPending = false;
        removeCallbacks(pressLeft);
        return true;
    }

    // Two thumbs on a game land apart or one after the other, so only a close pair that lands together can scroll.
    private void startPair(MotionEvent event, int index) {
        int first = event.findPointerIndex(pointerId);
        if (first < 0) {
            return;
        }

        float x1 = event.getX(first);
        float y1 = event.getY(first);
        float x2 = event.getX(index);
        float y2 = event.getY(index);
        DisplayMetrics metrics = getResources().getDisplayMetrics();
        double spreadMm = Math.hypot((x2 - x1) / metrics.xdpi, (y2 - y1) / metrics.ydpi) * 25.4;
        if (spreadMm > PAIR_SPREAD_MM) {
            return;
        }

        pairId = event.getPointerId(index);
        pairX1 = x1;
        pairY1 = y1;
        pairX2 = x2;
        pairY2 = y2;
    }

    // A pinch, a sideways swipe or one finger held still gives the touch back to the pointer.
    private boolean pairHeld(MotionEvent event) {
        int first = event.findPointerIndex(pointerId);
        int second = event.findPointerIndex(pairId);
        if (first < 0 || second < 0) {
            pairId = MotionEvent.INVALID_POINTER_ID;
            return false;
        }

        float x1 = event.getX(first);
        float y1 = event.getY(first);
        float x2 = event.getX(second);
        float y2 = event.getY(second);
        float dx1 = x1 - pairX1;
        float dy1 = y1 - pairY1;
        float dx2 = x2 - pairX2;
        float dy2 = y2 - pairY2;

        if (Math.max(Math.abs(dx1) + Math.abs(dy1), Math.abs(dx2) + Math.abs(dy2)) < TAP_SLOP) {
            return true;
        }

        float meanDx = (dx1 + dx2) / 2f;
        float meanDy = (dy1 + dy2) / 2f;
        double spreadChange = Math.abs(Math.hypot(x2 - x1, y2 - y1) - Math.hypot(pairX2 - pairX1, pairY2 - pairY1));
        if (dy1 * dy2 <= 0f || Math.abs(meanDy) <= Math.abs(meanDx) || spreadChange >= Math.abs(meanDy) / 2f) {
            pairId = MotionEvent.INVALID_POINTER_ID;
            return false;
        }

        scrolling = true;
        scrollY = (y1 + y2) / 2f;
        scrollCarry = 0f;

        if (mode == PointerMode.DRAG) {
            cursorX = (x1 + x2) / 2f;
            cursorY = scrollY;
            move();
        }

        return true;
    }

    private void scroll(MotionEvent event) {
        int first = event.findPointerIndex(pointerId);
        int second = event.findPointerIndex(pairId);
        if (first < 0 || second < 0) {
            return;
        }

        float y = (event.getY(first) + event.getY(second)) / 2f;
        scrollCarry += y - scrollY;
        scrollY = y;

        float notch = NOTCH_TRAVEL_PX * Math.max(reportedDpi, BASE_DPI) / (float) BASE_DPI;
        int notches = (int) (scrollCarry / notch);
        if (notches != 0) {
            scrollCarry -= notches * notch;
            PointerState.scroll(notches);
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
