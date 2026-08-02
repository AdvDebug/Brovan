package dev.brovan.input;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.view.MotionEvent;
import android.view.View;

/** Round hold-to-press button bound to one key. */
public class ActionButtonView extends View {

    public interface Listener {
        void onPressed(VirtualKey key, boolean down);
    }

    private final Paint fillPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint ringPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

    private final VirtualKey key;
    private final String label;

    private Listener listener;
    private boolean pressed;

    public ActionButtonView(Context context, VirtualKey key, String label) {
        super(context);
        this.key = key;
        this.label = label;

        fillPaint.setColor(Color.argb(70, 255, 255, 255));
        ringPaint.setColor(Color.argb(130, 255, 255, 255));
        ringPaint.setStyle(Paint.Style.STROKE);
        ringPaint.setStrokeWidth(3f);
        textPaint.setColor(Color.argb(220, 255, 255, 255));
        textPaint.setTextAlign(Paint.Align.CENTER);
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

        textPaint.setTextSize(radius * 0.7f);
        float baseline = centreY - (textPaint.descent() + textPaint.ascent()) / 2f;
        canvas.drawText(label, centreX, baseline, textPaint);
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        switch (event.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
                updatePressed(true);
                return true;

            case MotionEvent.ACTION_UP:
            case MotionEvent.ACTION_CANCEL:
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
            listener.onPressed(key, value);
        }
    }
}
