package dev.brovan;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.MotionEvent;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

import dev.brovan.input.KeyMap;
import dev.brovan.input.VirtualKey;

public class TerminalKeysView extends HorizontalScrollView implements TerminalView.LatchListener {

    private static final long REPEAT_DELAY_MS = 400;
    private static final long REPEAT_INTERVAL_MS = 50;
    private static final int TEXT_COLOR = 0xFFE6E6E6;
    private static final int LATCHED_COLOR = 0xFF3B78FF;
    private static final int BAR_COLOR = 0xFF1A1A1A;
    private static final float KEY_TEXT_SP = 14f;
    private static final float KEY_PADDING_DP = 14f;
    private static final float KEY_HEIGHT_DP = 40f;
    private static final int FUNCTION_KEYS = 12;

    private final LinearLayout row;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private TerminalView terminal;
    private TextView control;
    private TextView alternate;
    private Runnable repeat;

    public TerminalKeysView(Context context) {
        this(context, null);
    }

    public TerminalKeysView(Context context, AttributeSet attrs) {
        super(context, attrs);

        setBackgroundColor(BAR_COLOR);
        setHorizontalScrollBarEnabled(false);
        row = new LinearLayout(context);
        row.setOrientation(LinearLayout.HORIZONTAL);
        addView(row);

        addKey("ESC", VirtualKey.ESCAPE, (char) 0x1B);
        addKey("TAB", VirtualKey.TAB, '\t');
        control = addLatch("CTRL", KeyMap.LEFT_CTRL_PRESSED);
        alternate = addLatch("ALT", KeyMap.LEFT_ALT_PRESSED);
        addKey("←", VirtualKey.LEFT, '\0');
        addKey("↑", VirtualKey.UP, '\0');
        addKey("↓", VirtualKey.DOWN, '\0');
        addKey("→", VirtualKey.RIGHT, '\0');
        addKey("HOME", VirtualKey.HOME, '\0');
        addKey("END", VirtualKey.END, '\0');
        addKey("PGUP", VirtualKey.PAGE_UP, '\0');
        addKey("PGDN", VirtualKey.PAGE_DOWN, '\0');
        addKey("INS", VirtualKey.INSERT, '\0');
        addKey("DEL", VirtualKey.DELETE, '\0');

        for (int number = 1; number <= FUNCTION_KEYS; number++) {
            addKey("F" + number, VirtualKey.valueOf("F" + number), '\0');
        }
    }

    public void attach(TerminalView view) {
        terminal = view;
        view.setLatchListener(this);
    }

    @Override
    public void onLatchChanged(int latched) {
        control.setTextColor((latched & KeyMap.LEFT_CTRL_PRESSED) != 0 ? LATCHED_COLOR : TEXT_COLOR);
        alternate.setTextColor((latched & KeyMap.LEFT_ALT_PRESSED) != 0 ? LATCHED_COLOR : TEXT_COLOR);
    }

    private TextView addLatch(String label, int bits) {
        TextView key = newKey(label);
        key.setOnClickListener(view -> {
            if (terminal != null) {
                terminal.toggleLatch(bits);
            }
        });

        return key;
    }

    // Send on release so swipes do not type keys.
    private void addKey(String label, VirtualKey virtualKey, char character) {
        TextView key = newKey(label);
        boolean[] repeated = new boolean[1];
        Runnable repeating = new Runnable() {
            @Override
            public void run() {
                repeated[0] = true;
                send(virtualKey, character);
                handler.postDelayed(this, REPEAT_INTERVAL_MS);
            }
        };

        key.setOnTouchListener((view, event) -> {
            switch (event.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    stopRepeat();
                    view.setPressed(true);
                    repeated[0] = false;
                    repeat = repeating;
                    handler.postDelayed(repeating, REPEAT_DELAY_MS);
                    return true;

                case MotionEvent.ACTION_UP:
                    view.setPressed(false);
                    handler.removeCallbacks(repeating);
                    if (repeat == repeating) {
                        repeat = null;
                    }
                    if (!repeated[0]) {
                        send(virtualKey, character);
                    }
                    return true;

                case MotionEvent.ACTION_CANCEL:
                    view.setPressed(false);
                    handler.removeCallbacks(repeating);
                    if (repeat == repeating) {
                        repeat = null;
                    }
                    return true;

                default:
                    return true;
            }
        });
    }

    private void send(VirtualKey virtualKey, char character) {
        if (terminal != null) {
            terminal.press(virtualKey.code(), character);
        }
    }

    private void stopRepeat() {
        if (repeat != null) {
            handler.removeCallbacks(repeat);
            repeat = null;
        }
    }

    private TextView newKey(String label) {
        TextView key = new TextView(getContext());
        int padding = dp(KEY_PADDING_DP);
        key.setText(label);
        key.setTextColor(TEXT_COLOR);
        key.setTextSize(TypedValue.COMPLEX_UNIT_SP, KEY_TEXT_SP);
        key.setGravity(Gravity.CENTER);
        key.setPadding(padding, 0, padding, 0);
        key.setMinHeight(dp(KEY_HEIGHT_DP));
        key.setBackgroundResource(android.R.drawable.list_selector_background);
        row.addView(key, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, dp(KEY_HEIGHT_DP)));
        return key;
    }

    private int dp(float value) {
        return Math.round(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value, getResources().getDisplayMetrics()));
    }

    // Hiding the row may skip ACTION_UP.
    @Override
    public void onVisibilityAggregated(boolean isVisible) {
        super.onVisibilityAggregated(isVisible);
        if (!isVisible) {
            stopRepeat();
        }
    }

    @Override
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        stopRepeat();
    }
}
