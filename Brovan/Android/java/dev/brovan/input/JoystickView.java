package dev.brovan.input;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
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
    private static final float ARM_HALF_WIDTH = 0.34f;
    private static final float[] ARM_ROTATION = {0f, 180f, 270f, 90f};

    private final Paint basePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint ringPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint knobPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint litPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint arrowPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Path pad = new Path();
    private final Path arrow = new Path();
    private final RectF armBounds = new RectF();

    private VirtualKey up = VirtualKey.W;
    private VirtualKey down = VirtualKey.S;
    private VirtualKey left = VirtualKey.A;
    private VirtualKey right = VirtualKey.D;

    private Listener listener;
    private float knobX;
    private float knobY;
    private boolean active;
    private boolean cross;
    private int pointerId = MotionEvent.INVALID_POINTER_ID;

    public JoystickView(Context context) {
        super(context);

        basePaint.setColor(Color.argb(70, 255, 255, 255));
        ringPaint.setColor(Color.argb(120, 255, 255, 255));
        ringPaint.setStyle(Paint.Style.STROKE);
        ringPaint.setStrokeWidth(3f);
        knobPaint.setColor(Color.argb(170, 255, 255, 255));
        litPaint.setColor(Color.argb(90, 255, 255, 255));
        arrowPaint.setColor(Color.argb(220, 255, 255, 255));
    }

    @Override
    protected void onSizeChanged(int width, int height, int oldWidth, int oldHeight) {
        super.onSizeChanged(width, height, oldWidth, oldHeight);
        buildCross();
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

    /** Draws as a four-way cross instead of a stick; the touch handling is the same either way. */
    public void setCross(boolean value) {
        cross = value;
        invalidate();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        float centreX = getWidth() / 2f;
        float centreY = getHeight() / 2f;
        float radius = Math.min(centreX, centreY) - 6f;

        if (cross) {
            drawCross(canvas, centreX, centreY, radius);
            return;
        }

        canvas.drawCircle(centreX, centreY, radius, basePaint);
        canvas.drawCircle(centreX, centreY, radius, ringPaint);

        float x = active ? centreX + knobX * radius : centreX;
        float y = active ? centreY + knobY * radius : centreY;
        canvas.drawCircle(x, y, radius * 0.38f, knobPaint);
    }

    private void drawCross(Canvas canvas, float centreX, float centreY, float radius) {
        if (pad.isEmpty()) {
            buildCross();
        }

        float half = radius * ARM_HALF_WIDTH;
        float corner = half * 0.6f;

        basePaint.setAlpha(70);
        canvas.drawPath(pad, basePaint);
        canvas.drawPath(pad, ringPaint);

        for (int index = 0; index < 4; index++) {
            boolean horizontal = index >= 2;
            float direction = index % 2 == 0 ? -1f : 1f;
            boolean lit = active && (horizontal
                    ? Math.abs(knobX) >= DEAD_ZONE && Math.signum(knobX) == direction
                    : Math.abs(knobY) >= DEAD_ZONE && Math.signum(knobY) == direction);

            canvas.save();
            canvas.rotate(ARM_ROTATION[index], centreX, centreY);

            if (lit) {
                canvas.save();
                canvas.clipPath(pad);
                armBounds.set(centreX - half, centreY - radius, centreX + half, centreY - half * 0.2f);
                canvas.drawRoundRect(armBounds, corner, corner, litPaint);
                canvas.restore();
            }

            float tip = centreY - radius + half * 0.5f;
            arrow.reset();
            arrow.moveTo(centreX, tip);
            arrow.lineTo(centreX - half * 0.62f, tip + half * 0.9f);
            arrow.lineTo(centreX + half * 0.62f, tip + half * 0.9f);
            arrow.close();

            arrowPaint.setAlpha(lit ? 255 : 190);
            canvas.drawPath(arrow, arrowPaint);
            canvas.restore();
        }
    }

    private void buildCross() {
        pad.reset();

        float centreX = getWidth() / 2f;
        float centreY = getHeight() / 2f;
        float radius = Math.min(centreX, centreY) - 6f;
        if (radius <= 0f) {
            return;
        }

        float half = radius * ARM_HALF_WIDTH;
        float corner = half * 0.6f;

        Path vertical = new Path();
        vertical.addRoundRect(centreX - half, centreY - radius, centreX + half, centreY + radius,
                corner, corner, Path.Direction.CW);

        Path horizontal = new Path();
        horizontal.addRoundRect(centreX - radius, centreY - half, centreX + radius, centreY + half,
                corner, corner, Path.Direction.CW);

        pad.op(vertical, horizontal, Path.Op.UNION);
    }

    /**
     * Follows the one finger that grabbed the stick. Without the pointer id, a second finger anywhere in
     * the same gesture arrives here as well and the knob jumps to whichever pointer moved last.
     */
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
                active = true;
                track(event.getX(index), event.getY(index));
                return true;
            }

            case MotionEvent.ACTION_MOVE: {
                int index = event.findPointerIndex(pointerId);
                if (index < 0) {
                    return true;
                }

                track(event.getX(index), event.getY(index));
                return true;
            }

            case MotionEvent.ACTION_UP:
            case MotionEvent.ACTION_POINTER_UP:
                if (event.getPointerId(event.getActionIndex()) != pointerId) {
                    return true;
                }

                release();
                return true;

            case MotionEvent.ACTION_CANCEL:
                release();
                return true;

            default:
                return super.onTouchEvent(event);
        }
    }

    private void release() {
        pointerId = MotionEvent.INVALID_POINTER_ID;
        active = false;
        knobX = 0f;
        knobY = 0f;
        emit(EnumSet.noneOf(VirtualKey.class));
        invalidate();
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
