package dev.brovan.input;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
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
    private static final int TAP_SLOP = 12;
    private static final int TAP_TIMEOUT_MS = 220;

    private final Paint hintPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

    private float cursorX;
    private float cursorY;
    private float lastX;
    private float lastY;
    private float travelled;
    private long downAt;

    public TouchpadView(Context context) {
        super(context);
        hintPaint.setColor(Color.argb(40, 255, 255, 255));
        hintPaint.setStyle(Paint.Style.STROKE);
        hintPaint.setStrokeWidth(2f);
    }

    @Override
    protected void onSizeChanged(int width, int height, int oldWidth, int oldHeight) {
        super.onSizeChanged(width, height, oldWidth, oldHeight);
        cursorX = width / 2f;
        cursorY = height / 2f;
    }

    @Override
    protected void onDraw(Canvas canvas) {
        canvas.drawRoundRect(4f, 4f, getWidth() - 4f, getHeight() - 4f, 18f, 18f, hintPaint);
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        switch (event.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
                lastX = event.getX();
                lastY = event.getY();
                travelled = 0f;
                downAt = event.getEventTime();
                return true;

            case MotionEvent.ACTION_MOVE: {
                float dx = (event.getX() - lastX) * SPEED;
                float dy = (event.getY() - lastY) * SPEED;
                lastX = event.getX();
                lastY = event.getY();
                travelled += Math.abs(dx) + Math.abs(dy);

                cursorX = clamp(cursorX + dx, getWidth());
                cursorY = clamp(cursorY + dy, getHeight());
                BrovanNative.injectPointer(BrovanNative.POINTER_MOVE, BrovanNative.BUTTON_LEFT,
                        (int) cursorX, (int) cursorY, 0);
                return true;
            }

            case MotionEvent.ACTION_UP:
                if (travelled < TAP_SLOP && event.getEventTime() - downAt < TAP_TIMEOUT_MS) {
                    click();
                }
                return true;

            default:
                return super.onTouchEvent(event);
        }
    }

    private void click() {
        int x = (int) cursorX;
        int y = (int) cursorY;
        BrovanNative.injectPointer(BrovanNative.POINTER_DOWN, BrovanNative.BUTTON_LEFT, x, y, BrovanNative.MK_LBUTTON);
        BrovanNative.injectPointer(BrovanNative.POINTER_UP, BrovanNative.BUTTON_LEFT, x, y, 0);
    }

    private static float clamp(float value, int limit) {
        return Math.max(0f, Math.min(value, limit));
    }
}
