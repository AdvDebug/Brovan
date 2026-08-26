package dev.brovan.input;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.view.MotionEvent;
import android.view.View;

import dev.brovan.BrovanNative;

/**
 * Relative pointer control. Games that hide the cursor and read movement deltas cannot use absolute
 * touch positions, so this accumulates a virtual cursor and reports it as ordinary mouse motion.
 */
public class TouchpadView extends View {

    private static final float SPEED = 1.6f;
    private static final int TAP_SLOP = 40;
    private static final int TAP_TIMEOUT_MS = 400;

    private final Paint hintPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

    private int strokeColor = ControlItem.DEFAULT_COLOR;
    private float opacity = 1f;

    private float cursorX;
    private float cursorY;
    private float lastX;
    private float lastY;
    private float travelled;
    private float travelX;
    private float travelY;
    private long downAt;
    private int pointerId = MotionEvent.INVALID_POINTER_ID;

    public TouchpadView(Context context) {
        super(context);
        hintPaint.setStyle(Paint.Style.STROKE);
        hintPaint.setStrokeWidth(2f);
        applyStyle();
    }

    public void setStyle(int stroke, float opacity) {
        strokeColor = stroke;
        this.opacity = opacity;
        applyStyle();
        invalidate();
    }

    private void applyStyle() {
        hintPaint.setColor(ControlItem.shade(strokeColor, 40, opacity));
    }

    @Override
    protected void onSizeChanged(int width, int height, int oldWidth, int oldHeight) {
        super.onSizeChanged(width, height, oldWidth, oldHeight);
        cursorX = surfaceWidth() / 2f;
        cursorY = surfaceHeight() / 2f;
    }

    /// The cursor moves across the whole guest window, not just the pad it is driven from.
    private int surfaceWidth() {
        View parent = (View) getParent();
        return parent == null ? getWidth() : parent.getWidth();
    }

    private int surfaceHeight() {
        View parent = (View) getParent();
        return parent == null ? getHeight() : parent.getHeight();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        canvas.drawRoundRect(4f, 4f, getWidth() - 4f, getHeight() - 4f, 18f, 18f, hintPaint);
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        switch (event.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
            case MotionEvent.ACTION_POINTER_DOWN: {
                if (pointerId != MotionEvent.INVALID_POINTER_ID) {
                    return true;
                }

                int index = event.getActionIndex();
                pointerId = event.getPointerId(index);
                lastX = event.getX(index);
                lastY = event.getY(index);
                travelled = 0f;
                downAt = event.getEventTime();
                return true;
            }

            case MotionEvent.ACTION_MOVE: {
                int index = event.findPointerIndex(pointerId);
                if (index < 0) {
                    return true;
                }

                float speed = SPEED * PointerState.speed();
                float dx = (event.getX(index) - lastX) * speed;
                float dy = (event.getY(index) - lastY) * speed;
                lastX = event.getX(index);
                lastY = event.getY(index);
                travelled += Math.abs(dx) + Math.abs(dy);

                cursorX = clamp(cursorX + dx, surfaceWidth());
                cursorY = clamp(cursorY + dy, surfaceHeight());
                reportTravel(dx, dy);
                PointerState.moved((int) cursorX, (int) cursorY);
                BrovanNative.injectPointer(BrovanNative.POINTER_MOVE, BrovanNative.BUTTON_LEFT,
                        (int) cursorX, (int) cursorY, 0);
                return true;
            }

            case MotionEvent.ACTION_UP:
            case MotionEvent.ACTION_POINTER_UP:
                if (event.getPointerId(event.getActionIndex()) != pointerId) {
                    return true;
                }

                pointerId = MotionEvent.INVALID_POINTER_ID;
                if (travelled < TAP_SLOP && event.getEventTime() - downAt < TAP_TIMEOUT_MS) {
                    click();
                }
                return true;

            case MotionEvent.ACTION_CANCEL:
                pointerId = MotionEvent.INVALID_POINTER_ID;
                return true;

            default:
                return super.onTouchEvent(event);
        }
    }

    private void reportTravel(float dx, float dy) {
        travelX += dx;
        travelY += dy;

        int wholeX = (int) travelX;
        int wholeY = (int) travelY;
        travelX -= wholeX;
        travelY -= wholeY;

        BrovanNative.injectMouseTravel(wholeX, wholeY);
    }

    private void click() {
        PointerState.moved((int) cursorX, (int) cursorY);
        PointerState.click(BrovanNative.BUTTON_LEFT);
    }

    private static float clamp(float value, int limit) {
        return Math.max(0f, Math.min(value, limit));
    }
}
