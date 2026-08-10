package dev.brovan.input;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.view.MotionEvent;
import android.view.View;

/** Round hold-to-press button. What the press means is the overlay's business, not this view's. */
public class ActionButtonView extends View {

    public interface Listener {
        void onPressed(boolean down);
    }

    private final Paint fillPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint ringPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

    private String label;
    private Listener listener;
    private boolean pressed;
    private int pointerId = MotionEvent.INVALID_POINTER_ID;

    public ActionButtonView(Context context, String label) {
        super(context);
        this.label = label;

        fillPaint.setColor(Color.argb(70, 255, 255, 255));
        ringPaint.setColor(Color.argb(130, 255, 255, 255));
        ringPaint.setStyle(Paint.Style.STROKE);
        ringPaint.setStrokeWidth(3f);
        textPaint.setColor(Color.argb(220, 255, 255, 255));
        textPaint.setTextAlign(Paint.Align.CENTER);
    }

    public void setLabel(String value) {
        label = value;
        invalidate();
    }

    public void setListener(Listener listener) {
        this.listener = listener;
    }

    @Override
    protected void onDraw(Canvas canvas) {
        float centreX = getWidth() / 2f;
        float centreY = getHeight() / 2f;
        float radius = Math.min(centreX, centreY) - 4f;

        fillPaint.setAlpha(pressed ? 140 : 70);
        canvas.drawCircle(centreX, centreY, radius, fillPaint);
        canvas.drawCircle(centreX, centreY, radius, ringPaint);

        textPaint.setTextSize(textSize(radius));
        float baseline = centreY - (textPaint.descent() + textPaint.ascent()) / 2f;
        canvas.drawText(label, centreX, baseline, textPaint);
    }

    /** Long labels such as "Page down" have to shrink or they spill out of the circle. */
    private float textSize(float radius) {
        float size = radius * 0.7f;
        if (label.length() <= 2) {
            return size;
        }

        return Math.max(radius * 0.26f, size * 2f / label.length());
    }

    /** Tracks the finger that pressed it, so another finger elsewhere cannot release the button. */
    @Override
    public boolean onTouchEvent(MotionEvent event) {
        switch (event.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
            case MotionEvent.ACTION_POINTER_DOWN:
                if (pointerId == MotionEvent.INVALID_POINTER_ID) {
                    pointerId = event.getPointerId(event.getActionIndex());
                    updatePressed(true);
                }
                return true;

            case MotionEvent.ACTION_UP:
            case MotionEvent.ACTION_POINTER_UP:
                if (event.getPointerId(event.getActionIndex()) != pointerId) {
                    return true;
                }

                pointerId = MotionEvent.INVALID_POINTER_ID;
                updatePressed(false);
                return true;

            case MotionEvent.ACTION_CANCEL:
                pointerId = MotionEvent.INVALID_POINTER_ID;
                updatePressed(false);
                return true;

            default:
                return super.onTouchEvent(event);
        }
    }

    private void updatePressed(boolean value) {
        if (pressed == value) {
            return;
        }

        pressed = value;
        invalidate();

        if (listener != null) {
            listener.onPressed(value);
        }
    }
}
