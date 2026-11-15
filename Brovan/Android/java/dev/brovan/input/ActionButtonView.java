package dev.brovan.input;

import android.content.Context;
import android.graphics.Canvas;
import android.view.MotionEvent;

/** Round hold-to-press button. What the press means is the overlay's business, not this view's. */
public class ActionButtonView extends ControlView {

    public interface Listener {
        void onPressed(boolean down);
    }

    private String label;
    private Listener listener;
    private boolean pressed;
    private int pointerId = MotionEvent.INVALID_POINTER_ID;

    public ActionButtonView(Context context, ControlPainter painter, String label) {
        super(context, painter);
        this.label = label;
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
        float radius = Math.min(centreX, centreY) - painter.inset();

        painter.begin(canvas, centreX, centreY, pressed);
        painter.body(canvas, painter.circle(centreX, centreY, radius), pressed, false);
        painter.label(canvas, label, centreX, centreY, painter.fit(label, radius * 1.3f, radius * 0.7f), pressed);
        painter.end(canvas);
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
