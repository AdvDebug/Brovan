package dev.brovan.input;

import android.content.Context;
import android.util.AttributeSet;
import android.view.Gravity;
import android.view.View;
import android.widget.FrameLayout;

import java.util.Set;

/**
 * Heads-up touch controls drawn over the guest. Only the controls themselves consume touches, so
 * anywhere else on screen still reaches the guest as an ordinary mouse event.
 */
public class ControlOverlay extends FrameLayout {

    public enum Scheme {
        NONE("Touch only"),
        WASD("Joystick (WASD)"),
        ARROWS("Joystick (arrows)"),
        DPAD("D-pad (arrows)"),
        TOUCHPAD("Mouse touchpad");

        private final String label;

        Scheme(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    private final KeyEmitter keys = new KeyEmitter();

    private Scheme scheme = Scheme.NONE;

    public ControlOverlay(Context context) {
        super(context);
        setClipChildren(false);
    }

    public ControlOverlay(Context context, AttributeSet attrs) {
        super(context, attrs);
        setClipChildren(false);
    }

    public Scheme scheme() {
        return scheme;
    }

    public void apply(Scheme value) {
        scheme = value;
        keys.releaseAll();
        removeAllViews();

        switch (value) {
            case WASD:
                addJoystick(VirtualKey.W, VirtualKey.S, VirtualKey.A, VirtualKey.D);
                addActionButtons();
                break;

            case ARROWS:
                addJoystick(VirtualKey.UP, VirtualKey.DOWN, VirtualKey.LEFT, VirtualKey.RIGHT);
                addActionButtons();
                break;

            case DPAD:
                addDpad();
                addActionButtons();
                break;

            case TOUCHPAD:
                addTouchpad();
                break;

            case NONE:
            default:
                break;
        }
    }

    public void releaseAll() {
        keys.releaseAll();
    }

    private void addJoystick(VirtualKey up, VirtualKey down, VirtualKey left, VirtualKey right) {
        JoystickView joystick = new JoystickView(getContext());
        joystick.setKeys(up, down, left, right);
        joystick.setListener(new JoystickView.Listener() {
            @Override
            public void onDirections(Set<VirtualKey> directions) {
                keys.apply(directions);
            }
        });

        int size = dp(180);
        LayoutParams params = new LayoutParams(size, size, Gravity.BOTTOM | Gravity.START);
        params.leftMargin = dp(24);
        params.bottomMargin = dp(24);
        addView(joystick, params);
    }

    private void addDpad() {
        int button = dp(62);
        int gap = dp(4);
        int originX = dp(28);
        int originY = dp(28);

        addDpadButton(VirtualKey.UP, "▲", originX + button + gap, originY + (button + gap) * 2, button);
        addDpadButton(VirtualKey.DOWN, "▼", originX + button + gap, originY, button);
        addDpadButton(VirtualKey.LEFT, "◀", originX, originY + button + gap, button);
        addDpadButton(VirtualKey.RIGHT, "▶", originX + (button + gap) * 2, originY + button + gap, button);
    }

    private void addDpadButton(VirtualKey key, String label, int leftMargin, int bottomMargin, int size) {
        LayoutParams params = new LayoutParams(size, size, Gravity.BOTTOM | Gravity.START);
        params.leftMargin = leftMargin;
        params.bottomMargin = bottomMargin;
        addView(button(key, label), params);
    }

    private void addActionButtons() {
        int size = dp(70);
        int gap = dp(10);
        int originX = dp(28);
        int originY = dp(28);

        addActionButton(VirtualKey.SPACE, "A", originX + size + gap, originY, size);
        addActionButton(VirtualKey.ENTER, "B", originX, originY + size + gap, size);
        addActionButton(VirtualKey.SHIFT, "X", originX + (size + gap) * 2, originY + size + gap, size);
        addActionButton(VirtualKey.ESCAPE, "Esc", originX + size + gap, originY + (size + gap) * 2, size);
    }

    private void addActionButton(VirtualKey key, String label, int rightMargin, int bottomMargin, int size) {
        LayoutParams params = new LayoutParams(size, size, Gravity.BOTTOM | Gravity.END);
        params.rightMargin = rightMargin;
        params.bottomMargin = bottomMargin;
        addView(button(key, label), params);
    }

    private View button(VirtualKey key, String label) {
        ActionButtonView view = new ActionButtonView(getContext(), key, label);
        view.setListener((pressedKey, down) -> {
            if (down) {
                keys.press(pressedKey);
            } else {
                keys.release(pressedKey);
            }
        });
        return view;
    }

    private void addTouchpad() {
        LayoutParams params = new LayoutParams(dp(260), dp(170), Gravity.BOTTOM | Gravity.END);
        params.rightMargin = dp(24);
        params.bottomMargin = dp(24);
        addView(new TouchpadView(getContext()), params);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
