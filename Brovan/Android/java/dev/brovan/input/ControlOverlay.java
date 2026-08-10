package dev.brovan.input;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.widget.FrameLayout;

import java.util.Set;

/**
 * Heads-up touch controls drawn over the guest. Only the controls themselves consume touches, so
 * anywhere else on screen still reaches the guest as an ordinary mouse event.
 *
 * Every scheme, built-in or custom, is rendered from a {@link ControlLayout}, which is also what the
 * editor produces.
 */
public class ControlOverlay extends FrameLayout {

    public enum Scheme {
        NONE("Touch only"),
        WASD("Joystick (WASD)"),
        ARROWS("Joystick (arrows)"),
        DPAD("D-pad (arrows)"),
        TOUCHPAD("Mouse touchpad"),
        CUSTOM("Custom layout");

        private final String label;

        Scheme(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    public interface EditListener {
        void onSelected(ControlItem item);

        void onMoved(ControlItem item);
    }

    private final KeyEmitter keys = new KeyEmitter();
    private final Paint selectionPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint gridPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

    private Scheme scheme = Scheme.NONE;
    private ControlLayout layout = new ControlLayout();
    private ControlLayout custom;

    private boolean editing;
    private EditListener editListener;
    private ControlItem selected;
    private float grabX;
    private float grabY;

    public ControlOverlay(Context context) {
        super(context);
        initialize();
    }

    public ControlOverlay(Context context, AttributeSet attrs) {
        super(context, attrs);
        initialize();
    }

    private void initialize() {
        setClipChildren(false);

        selectionPaint.setColor(Color.argb(220, 124, 156, 245));
        selectionPaint.setStyle(Paint.Style.STROKE);
        selectionPaint.setStrokeWidth(4f);

        gridPaint.setColor(Color.argb(40, 255, 255, 255));
        gridPaint.setStrokeWidth(1f);
    }

    public Scheme scheme() {
        return scheme;
    }

    public ControlLayout layout() {
        return layout;
    }

    /** The layout used when the scheme is {@link Scheme#CUSTOM}. Set it before applying that scheme. */
    public void setCustomLayout(ControlLayout value) {
        custom = value;
    }

    public void apply(Scheme value) {
        scheme = value;
        render(value == Scheme.CUSTOM && custom != null ? custom : ControlLayout.forScheme(value));
    }

    public void render(ControlLayout value) {
        keys.releaseAll();
        removeControls();
        layout = value;
        selected = null;

        for (ControlItem item : layout.items()) {
            View view = create(item);
            view.setTag(item);
            addView(view, new LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT));
        }

        requestLayout();
    }

    /** Anything the overlay did not add itself, such as the guest surface it is drawn over, stays put. */
    private void removeControls() {
        for (int i = getChildCount() - 1; i >= 0; i--) {
            if (getChildAt(i).getTag() instanceof ControlItem) {
                removeViewAt(i);
            }
        }
    }

    public void releaseAll() {
        keys.releaseAll();
    }

    public void setEditing(boolean value, EditListener listener) {
        editing = value;
        editListener = listener;
        keys.releaseAll();
        setWillNotDraw(!value);
        invalidate();
    }

    public ControlItem selected() {
        return selected;
    }

    public void select(ControlItem item) {
        selected = item;
        invalidate();

        if (editListener != null) {
            editListener.onSelected(item);
        }
    }

    private View create(ControlItem item) {
        switch (item.kind) {
            case JOYSTICK:
            case DPAD:
                return stick(item);

            case TOUCHPAD:
                return new TouchpadView(getContext());

            case MOUSE: {
                ActionButtonView view = new ActionButtonView(getContext(), item.caption());
                view.setListener(down -> PointerState.press(item.mouseButton, down));
                return view;
            }

            default: {
                ActionButtonView view = new ActionButtonView(getContext(), item.caption());
                view.setListener(down -> {
                    if (down) {
                        keys.press(item, item.key);
                    } else {
                        keys.release(item, item.key);
                    }
                });
                return view;
            }
        }
    }

    private View stick(ControlItem item) {
        JoystickView view = new JoystickView(getContext());
        view.setKeys(item.up, item.down, item.left, item.right);
        view.setCross(item.kind == ControlItem.Kind.DPAD);
        view.setListener(new JoystickView.Listener() {
            @Override
            public void onDirections(Set<VirtualKey> directions) {
                keys.apply(item, directions);
            }
        });
        return view;
    }

    @Override
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        int width = right - left;
        int height = bottom - top;

        for (int i = 0; i < getChildCount(); i++) {
            View child = getChildAt(i);

            if (!(child.getTag() instanceof ControlItem)) {
                child.measure(MeasureSpec.makeMeasureSpec(width, MeasureSpec.EXACTLY),
                        MeasureSpec.makeMeasureSpec(height, MeasureSpec.EXACTLY));
                child.layout(0, 0, width, height);
                continue;
            }

            ControlItem item = (ControlItem) child.getTag();
            int itemWidth = dp(item.size);
            int itemHeight = item.kind == ControlItem.Kind.TOUCHPAD ? Math.round(itemWidth * 0.66f) : itemWidth;
            int centreX = Math.round(item.x * width);
            int centreY = Math.round(item.y * height);

            child.measure(MeasureSpec.makeMeasureSpec(itemWidth, MeasureSpec.EXACTLY),
                    MeasureSpec.makeMeasureSpec(itemHeight, MeasureSpec.EXACTLY));
            child.layout(centreX - itemWidth / 2, centreY - itemHeight / 2,
                    centreX + itemWidth / 2, centreY + itemHeight / 2);
        }
    }

    @Override
    public boolean onInterceptTouchEvent(MotionEvent event) {
        return editing;
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        if (!editing) {
            return super.onTouchEvent(event);
        }

        switch (event.getActionMasked()) {
            case MotionEvent.ACTION_DOWN: {
                View child = childAt(event.getX(), event.getY());
                select(child == null ? null : (ControlItem) child.getTag());

                if (child != null) {
                    grabX = event.getX() - child.getLeft() - child.getWidth() / 2f;
                    grabY = event.getY() - child.getTop() - child.getHeight() / 2f;
                }

                return true;
            }

            case MotionEvent.ACTION_MOVE: {
                if (selected == null) {
                    return true;
                }

                selected.x = clamp((event.getX() - grabX) / getWidth());
                selected.y = clamp((event.getY() - grabY) / getHeight());
                requestLayout();
                return true;
            }

            case MotionEvent.ACTION_UP:
            case MotionEvent.ACTION_CANCEL:
                if (selected != null && editListener != null) {
                    editListener.onMoved(selected);
                }
                return true;

            default:
                return true;
        }
    }

    private View childAt(float x, float y) {
        for (int i = getChildCount() - 1; i >= 0; i--) {
            View child = getChildAt(i);
            if (!(child.getTag() instanceof ControlItem)) {
                continue;
            }

            if (x >= child.getLeft() && x <= child.getRight() && y >= child.getTop() && y <= child.getBottom()) {
                return child;
            }
        }

        return null;
    }

    @Override
    protected void onDraw(Canvas canvas) {
        if (!editing) {
            return;
        }

        for (int i = 1; i < 4; i++) {
            float x = getWidth() * i / 4f;
            float y = getHeight() * i / 4f;
            canvas.drawLine(x, 0f, x, getHeight(), gridPaint);
            canvas.drawLine(0f, y, getWidth(), y, gridPaint);
        }
    }

    @Override
    protected void dispatchDraw(Canvas canvas) {
        super.dispatchDraw(canvas);

        if (!editing || selected == null) {
            return;
        }

        for (int i = 0; i < getChildCount(); i++) {
            View child = getChildAt(i);
            if (child.getTag() != selected) {
                continue;
            }

            canvas.drawRoundRect(child.getLeft() - 6f, child.getTop() - 6f,
                    child.getRight() + 6f, child.getBottom() + 6f, 20f, 20f, selectionPaint);
        }
    }

    private static float clamp(float value) {
        return Math.max(0.02f, Math.min(0.98f, value));
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
