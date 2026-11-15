package dev.brovan.input;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Path;
import android.graphics.RectF;
import android.view.MotionEvent;

import java.util.EnumSet;
import java.util.Set;

/**
 * Analog-looking stick that resolves to the eight compass directions, because the guest only has keys to
 * press. The dead zone stops a resting thumb from walking the character.
 */
public class JoystickView extends ControlView {

    public interface Listener {
        void onDirections(Set<VirtualKey> directions);
    }

    private static final float DEAD_ZONE = 0.28f;
    private static final float KNOB = 0.36f;
    private static final float KNOB_OVERHANG = 0.55f;
    private static final float LEGEND_REACH = 0.72f;
    private static final float ARM_HALF_WIDTH = 0.34f;
    private static final float[] ARM_ROTATION = {0f, 180f, 270f, 90f};

    private final Path pad = new Path();
    private final Path arrow = new Path();
    private final RectF armBounds = new RectF();
    private final float[] legendSizes = new float[4];

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

    public JoystickView(Context context, ControlPainter painter) {
        super(context, painter);
    }

    @Override
    protected void onSizeChanged(int width, int height, int oldWidth, int oldHeight) {
        super.onSizeChanged(width, height, oldWidth, oldHeight);
        buildCross();
        fitLegends();
    }

    public void setListener(Listener listener) {
        this.listener = listener;
    }

    public void setKeys(VirtualKey up, VirtualKey down, VirtualKey left, VirtualKey right) {
        this.up = up;
        this.down = down;
        this.left = left;
        this.right = right;
        fitLegends();
    }

    /** Draws as a four-way cross instead of a stick; the touch handling is the same either way. */
    public void setCross(boolean value) {
        cross = value;
        invalidate();
    }

    private float radius() {
        return Math.min(getWidth(), getHeight()) / 2f - painter.inset();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        float centreX = getWidth() / 2f;
        float centreY = getHeight() / 2f;
        float radius = radius();

        if (cross) {
            drawCross(canvas, centreX, centreY, radius);
            return;
        }

        painter.body(canvas, painter.circle(centreX, centreY, radius), false, true);
        painter.deadZone(canvas, centreX, centreY, radius * DEAD_ZONE);
        drawLegends(canvas, centreX, centreY, radius);

        float knob = radius * KNOB;
        float travel = radius - knob * KNOB_OVERHANG;
        float x = active ? centreX + knobX * travel : centreX;
        float y = active ? centreY + knobY * travel : centreY;
        painter.knob(canvas, x, y, knob, active);
    }

    private void drawLegends(Canvas canvas, float centreX, float centreY, float radius) {
        boolean moving = active && Math.hypot(knobX, knobY) >= DEAD_ZONE;
        float reach = radius * LEGEND_REACH;

        painter.legend(canvas, up.shortLabel(), centreX, centreY - reach, legendSizes[0],
                moving && knobY <= -DEAD_ZONE);
        painter.legend(canvas, down.shortLabel(), centreX, centreY + reach, legendSizes[1],
                moving && knobY >= DEAD_ZONE);
        painter.legend(canvas, left.shortLabel(), centreX - reach, centreY, legendSizes[2],
                moving && knobX <= -DEAD_ZONE);
        painter.legend(canvas, right.shortLabel(), centreX + reach, centreY, legendSizes[3],
                moving && knobX >= DEAD_ZONE);
    }

    private void fitLegends() {
        float radius = radius();
        VirtualKey[] keys = {up, down, left, right};
        for (int i = 0; i < keys.length; i++) {
            legendSizes[i] = painter.fit(keys[i].shortLabel(), radius * 0.34f, radius * 0.2f);
        }
    }

    private void drawCross(Canvas canvas, float centreX, float centreY, float radius) {
        if (pad.isEmpty()) {
            buildCross();
        }

        float half = radius * ARM_HALF_WIDTH;
        float corner = half * 0.6f;

        painter.body(canvas, pad, false, false);

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
                canvas.drawRoundRect(armBounds, corner, corner, painter.lit());
                canvas.restore();
            }

            float tip = centreY - radius + half * 0.5f;
            arrow.reset();
            arrow.moveTo(centreX, tip);
            arrow.lineTo(centreX - half * 0.62f, tip + half * 0.9f);
            arrow.lineTo(centreX + half * 0.62f, tip + half * 0.9f);
            arrow.close();

            canvas.drawPath(arrow, painter.ink(lit));
            canvas.restore();
        }
    }

    private void buildCross() {
        float radius = radius();
        if (radius <= 0f) {
            pad.reset();
            return;
        }

        painter.buildCross(pad, getWidth() / 2f, getHeight() / 2f, radius, radius * ARM_HALF_WIDTH);
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
