package dev.brovan.input;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Point;
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
        NONE,
        WASD,
        ARROWS,
        DPAD,
        TOUCHPAD,
        CUSTOM
    }

    public interface EditListener {
        void onSelected(ControlItem item);

        void onMoved(ControlItem item);
    }

    private static final VirtualKey[] SLOT_KEYS = {
            VirtualKey.DIGIT_1, VirtualKey.DIGIT_2, VirtualKey.DIGIT_3, VirtualKey.DIGIT_4, VirtualKey.DIGIT_5,
            VirtualKey.DIGIT_6, VirtualKey.DIGIT_7, VirtualKey.DIGIT_8, VirtualKey.DIGIT_9, VirtualKey.DIGIT_0};

    private final KeyEmitter keys = new KeyEmitter();
    private final Paint selectionPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint gridPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

    private int accent;
    private int onAccent;
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

        selectionPaint.setStyle(Paint.Style.STROKE);
        selectionPaint.setStrokeWidth(4f);

        gridPaint.setColor(Color.argb(40, 255, 255, 255));
        gridPaint.setStrokeWidth(1f);
    }

    /** Call before the first render. */
    public void setAccent(int accent, int onAccent) {
        this.accent = accent & 0xFFFFFF;
        this.onAccent = onAccent & 0xFFFFFF;
        selectionPaint.setColor(ControlItem.shade(this.accent, 220, 1f));
    }

    public int accent() {
        return accent;
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
            ControlView view = create(item, new ControlPainter(getContext(), accent, onAccent));
            view.setStyle(item);
            view.setTag(item);
            addView(view, new LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT));
        }

        requestLayout();
    }

    public void restyle() {
        for (int i = 0; i < getChildCount(); i++) {
            View child = getChildAt(i);
            if (child instanceof ControlView && child.getTag() instanceof ControlItem) {
                ((ControlView) child).setStyle((ControlItem) child.getTag());
            }
        }
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

    private ControlView create(ControlItem item, ControlPainter painter) {
        switch (item.kind) {
            case JOYSTICK:
            case DPAD:
                return stick(item, painter);

            case TOUCHPAD:
                return new TouchpadView(getContext(), painter);

            case MOUSE: {
                ActionButtonView view = new ActionButtonView(getContext(), painter, item.caption());
                view.setListener(down -> PointerState.press(item.mouseButton, down));
                return view;
            }

            case SWITCHER:
                return switcher(item, painter);

            default: {
                ActionButtonView view = new ActionButtonView(getContext(), painter, item.caption());
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

    private ControlView stick(ControlItem item, ControlPainter painter) {
        JoystickView view = new JoystickView(getContext(), painter);
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

    private ControlView switcher(ControlItem item, ControlPainter painter) {
        SwitcherView view = new SwitcherView(getContext(), painter);
        view.setSlots(item.slots);
        view.setHorizontal(item.horizontal);
        view.setListener((direction, slot) -> {
            if (slot < 0) {
                PointerState.scroll(direction);
            } else {
                keys.tap(item, SLOT_KEYS[slot % SLOT_KEYS.length]);
            }
        });
        return view;
    }

    @Override
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        int width = right - left;
        int height = bottom - top;
        float density = getResources().getDisplayMetrics().density;
        float widthDp = width / density;
        float heightDp = height / density;

        for (int i = 0; i < getChildCount(); i++) {
            View child = getChildAt(i);

            if (!(child.getTag() instanceof ControlItem)) {
                child.measure(MeasureSpec.makeMeasureSpec(width, MeasureSpec.EXACTLY),
                        MeasureSpec.makeMeasureSpec(height, MeasureSpec.EXACTLY));
                child.layout(0, 0, width, height);
                continue;
            }

            ControlItem item = (ControlItem) child.getTag();
            int span = dp(item.size);
            int itemWidth = span;
            int itemHeight = span;

            if (item.kind == ControlItem.Kind.TOUCHPAD) {
                itemHeight = Math.round(span * 0.66f);
            } else if (item.kind == ControlItem.Kind.SWITCHER) {
                int across = Math.round(span * 0.38f);
                itemWidth = item.horizontal ? span : across;
                itemHeight = item.horizontal ? across : span;
            }

            int centreX = keepInside(Math.round(item.centreX(widthDp) * density), itemWidth, width);
            int centreY = keepInside(Math.round(item.centreY(heightDp) * density), itemHeight, height);

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

                View child = viewOf(selected);
                if (child == null) {
                    return true;
                }

                float density = getResources().getDisplayMetrics().density;
                int centreX = keepInside(Math.round(event.getX() - grabX), child.getWidth(), getWidth());
                int centreY = keepInside(Math.round(event.getY() - grabY), child.getHeight(), getHeight());
                selected.anchorAt(centreX / density, centreY / density, widthDp(), heightDp());
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

    /** Drawn after the children, because a guest SurfaceView child clears whatever is drawn under it. */
    @Override
    protected void dispatchDraw(Canvas canvas) {
        super.dispatchDraw(canvas);

        if (!editing) {
            return;
        }

        // Where ControlItem.anchorAt changes the edge a dragged control is measured from.
        float middle = getWidth() / 2f;
        float third = getHeight() / 3f;
        canvas.drawLine(middle, 0f, middle, getHeight(), gridPaint);
        canvas.drawLine(0f, third, getWidth(), third, gridPaint);

        View child = viewOf(selected);
        if (child != null) {
            canvas.drawRoundRect(child.getLeft() - 6f, child.getTop() - 6f,
                    child.getRight() + 6f, child.getBottom() + 6f, 20f, 20f, selectionPaint);
        }
    }

    private View viewOf(ControlItem item) {
        if (item == null) {
            return null;
        }

        for (int i = 0; i < getChildCount(); i++) {
            View child = getChildAt(i);
            if (child.getTag() == item) {
                return child;
            }
        }

        return null;
    }

    /** Picks the spot that covers the fewest controls, nearest the selected one or else the bottom centre. */
    public void findClearSpot(int width, int height, int margin, int top, Point out) {
        View anchor = viewOf(selected);
        float anchorX = anchor != null ? (anchor.getLeft() + anchor.getRight()) / 2f : getWidth() / 2f;
        float anchorY = anchor != null ? (anchor.getTop() + anchor.getBottom()) / 2f : getHeight();
        int step = dp(8);
        int pad = dp(10);
        int right = getWidth() - margin - width;
        int bottom = getHeight() - margin - height;

        out.set(margin, top);
        long best = Long.MAX_VALUE;

        for (int y = top; y <= bottom; y += step) {
            for (int x = margin; x <= right; x += step) {
                long covered = 0;
                long area = 0;

                for (int i = 0; i < getChildCount(); i++) {
                    View child = getChildAt(i);
                    if (!(child.getTag() instanceof ControlItem)) {
                        continue;
                    }

                    long across = Math.min(x + width, child.getRight() + pad) - Math.max(x, child.getLeft() - pad);
                    long down = Math.min(y + height, child.getBottom() + pad) - Math.max(y, child.getTop() - pad);
                    if (across > 0 && down > 0) {
                        covered++;
                        area += across * down;
                    }
                }

                double distance = Math.hypot(x + width / 2f - anchorX, y + height / 2f - anchorY);
                long score = covered * 1_000_000_000_000L + area * 16 + (long) distance;
                if (score < best) {
                    best = score;
                    out.set(x, y);
                }
            }
        }
    }

    public float widthDp() {
        return getWidth() / getResources().getDisplayMetrics().density;
    }

    public float heightDp() {
        return getHeight() / getResources().getDisplayMetrics().density;
    }

    private static int keepInside(int centre, int span, int limit) {
        if (span >= limit) {
            return limit / 2;
        }

        return Math.max(span / 2, Math.min(limit - span / 2, centre));
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
