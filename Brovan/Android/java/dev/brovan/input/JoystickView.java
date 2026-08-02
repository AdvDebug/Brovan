package dev.brovan.input;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.view.MotionEvent;
import android.view.View;

import java.util.EnumSet;
import java.util.Set;

/**
 * Analog-looking stick that resolves to the eight compass directions, because the guest only has keys to
 * press. The dead zone stops a resting thumb from walking the character.
 */
public class JoystickView extends View {

    public interface Listener {
        void onDirections(Set<VirtualKey> directions);
    }

    private static final float DEAD_ZONE = 0.28f;

    private final Paint basePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint ringPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint knobPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

    private VirtualKey up = VirtualKey.W;
    private VirtualKey down = VirtualKey.S;
    private VirtualKey left = VirtualKey.A;
    private VirtualKey right = VirtualKey.D;

    private Listener listener;
    private float knobX;
    private float knobY;
    private boolean active;

    public JoystickView(Context context) {
        super(context);

        basePaint.setColor(Color.argb(70, 255, 255, 255));
        ringPaint.setColor(Color.argb(120, 255, 255, 255));
        ringPaint.setStyle(Paint.Style.STROKE);
        ringPaint.setStrokeWidth(3f);
        knobPaint.setColor(Color.argb(170, 255, 255, 255));
    }

    public void setListener(Listener listener) {
        this.listener = listener;
    }

    public void setKeys(VirtualKey up, VirtualKey down, VirtualKey left, VirtualKey right) {
        this.up = up;
        this.down = down;
        this.left = left;
        this.right = right;
    }

    @Override
    protected void onDraw(Canvas canvas) {
        float centreX = getWidth() / 2f;
        float centreY = getHeight() / 2f;
        float radius = Math.min(centreX, centreY) - 6f;

        canvas.drawCircle(centreX, centreY, radius, basePaint);
        canvas.drawCircle(centreX, centreY, radius, ringPaint);

        float x = active ? centreX + knobX * radius : centreX;
        float y = active ? centreY + knobY * radius : centreY;
        canvas.drawCircle(x, y, radius * 0.38f, knobPaint);
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        switch (event.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
            case MotionEvent.ACTION_MOVE:
                active = true;
                track(event.getX(), event.getY());
                return true;

            case MotionEvent.ACTION_UP:
            case MotionEvent.ACTION_CANCEL:
                active = false;
                knobX = 0f;
                knobY = 0f;
                emit(EnumSet.noneOf(VirtualKey.class));
                invalidate();
                return true;

            default:
                return super.onTouchEvent(event);
        }
    }

    private void track(float touchX, float touchY) {
        float centreX = getWidth() / 2f;
        float centreY = getHeight() / 2f;
        float radius = Math.min(centreX, centreY);

        float dx = (touchX - centreX) / radius;
        float dy = (touchY - centreY) / radius;

        float length = (float) Math.hypot(dx, dy);
        if (length > 1f) {
            dx /= length;
            dy /= length;
            length = 1f;
        }

        knobX = dx;
        knobY = dy;

        Set<VirtualKey> directions = EnumSet.noneOf(VirtualKey.class);
        if (length >= DEAD_ZONE) {
            if (dy <= -DEAD_ZONE) directions.add(up);
            if (dy >= DEAD_ZONE) directions.add(down);
            if (dx <= -DEAD_ZONE) directions.add(left);
            if (dx >= DEAD_ZONE) directions.add(right);
        }

        emit(directions);
        invalidate();
    }

    private void emit(Set<VirtualKey> directions) {
        if (listener != null) {
            listener.onDirections(directions);
        }
    }
}
