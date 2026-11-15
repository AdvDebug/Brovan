package dev.brovan.input;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Path;
import android.graphics.RectF;
import android.view.MotionEvent;

/**
 * Steps a selection one notch at a time. Tapping an end steps once and holding it repeats; sweeping a
 * finger along the control runs through several. What a step means is the overlay's business.
 */
public class SwitcherView extends ControlView {

    public interface Listener {
        /** Direction is +1 or -1. Slot is the slot now selected, or -1 when the control keeps no slots. */
        void onStep(int direction, int slot);
    }

    private static final float END_FRACTION = 0.32f;
    private static final float STEP_DP = 26f;
    private static final long REPEAT_FIRST_MS = 360;
    private static final long REPEAT_MS = 140;

    private final Path chevron = new Path();
    private final RectF bounds = new RectF();
    private final RectF endBounds = new RectF();
    private final RectF glyphBounds = new RectF();

    private final float stepDistance;

    private Listener listener;
    private int slots;
    private int index;
    private boolean horizontal;
    private int lit;
    private int repeatDirection;
    private float swept;
    private float lastAlong;
    private int pointerId = MotionEvent.INVALID_POINTER_ID;

    private final Runnable repeat = new Runnable() {
        @Override
        public void run() {
            step(repeatDirection);
            postDelayed(this, REPEAT_MS);
        }
    };

    public SwitcherView(Context context, ControlPainter painter) {
        super(context, painter);
        stepDistance = STEP_DP * getResources().getDisplayMetrics().density;
    }

    /** Zero keeps no selection of its own, which is what a control that only turns a wheel wants. */
    public void setSlots(int count) {
        slots = Math.max(0, count);
        index = 0;
        invalidate();
    }

    public void setHorizontal(boolean value) {
        horizontal = value;
        invalidate();
    }

    public void setListener(Listener listener) {
        this.listener = listener;
    }

    @Override
    protected void onDraw(Canvas canvas) {
        float inset = painter.inset();
        if ((horizontal ? getHeight() : getWidth()) / 2f - inset <= 0f) {
            return;
        }

        bounds.set(inset, inset, getWidth() - inset, getHeight() - inset);
        Path pill = painter.pill(bounds);
        painter.body(canvas, pill, false, false);

        if (lit != 0) {
            canvas.save();
            canvas.clipRect(endBounds());
            canvas.drawPath(pill, painter.lit());
            canvas.restore();
        }

        drawDividers(canvas);

        float across = horizontal ? bounds.height() : bounds.width();
        drawEnds(canvas, across * 0.18f);

        if (slots > 0) {
            painter.label(canvas, Integer.toString(index + 1), bounds.centerX(), bounds.centerY(),
                    across * 0.40f, false);
        } else {
            drawWheel(canvas, bounds.centerX(), bounds.centerY(), across * 0.20f);
        }
    }

    /** Forward is up on a tall control and right on a wide one, which is the way the finger already moves. */
    private void drawEnds(Canvas canvas, float half) {
        float span = horizontal ? bounds.width() : bounds.height();
        float centre = span * END_FRACTION / 2f;

        if (horizontal) {
            drawChevron(canvas, bounds.right - centre, bounds.centerY(), 90f, half, lit > 0);
            drawChevron(canvas, bounds.left + centre, bounds.centerY(), 270f, half, lit < 0);
        } else {
            drawChevron(canvas, bounds.centerX(), bounds.top + centre, 0f, half, lit > 0);
            drawChevron(canvas, bounds.centerX(), bounds.bottom - centre, 180f, half, lit < 0);
        }
    }

    private void drawChevron(Canvas canvas, float centreX, float centreY, float rotation, float half,
                             boolean bright) {
        canvas.save();
        canvas.rotate(rotation, centreX, centreY);
        chevron.reset();
        chevron.moveTo(centreX - half, centreY + half * 0.5f);
        chevron.lineTo(centreX, centreY - half * 0.5f);
        chevron.lineTo(centreX + half, centreY + half * 0.5f);
        canvas.drawPath(chevron, painter.line(bright));
        canvas.restore();
    }

    private RectF endBounds() {
        float span = horizontal ? bounds.width() : bounds.height();
        float end = span * END_FRACTION;
        endBounds.set(bounds);

        if (horizontal) {
            if (lit > 0) {
                endBounds.left = bounds.right - end;
            } else {
                endBounds.right = bounds.left + end;
            }
        } else {
            if (lit > 0) {
                endBounds.bottom = bounds.top + end;
            } else {
                endBounds.top = bounds.bottom - end;
            }
        }

        return endBounds;
    }

    private void drawDividers(Canvas canvas) {
        float span = horizontal ? bounds.width() : bounds.height();
        float end = span * END_FRACTION;

        if (horizontal) {
            float top = bounds.top + bounds.height() * 0.24f;
            float bottom = bounds.bottom - bounds.height() * 0.24f;
            canvas.drawLine(bounds.left + end, top, bounds.left + end, bottom, painter.divider());
            canvas.drawLine(bounds.right - end, top, bounds.right - end, bottom, painter.divider());
        } else {
            float left = bounds.left + bounds.width() * 0.24f;
            float right = bounds.right - bounds.width() * 0.24f;
            canvas.drawLine(left, bounds.top + end, right, bounds.top + end, painter.divider());
            canvas.drawLine(left, bounds.bottom - end, right, bounds.bottom - end, painter.divider());
        }
    }

    /** A control with no slots of its own still has to say what it does, so it draws the wheel it turns. */
    private void drawWheel(Canvas canvas, float centreX, float centreY, float half) {
        glyphBounds.set(centreX - half * 0.70f, centreY - half, centreX + half * 0.70f, centreY + half);
        canvas.drawRoundRect(glyphBounds, half * 0.70f, half * 0.70f, painter.line(false));
        canvas.drawLine(centreX, centreY - half * 0.52f, centreX, centreY - half * 0.10f, painter.line(false));
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        switch (event.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
            case MotionEvent.ACTION_POINTER_DOWN: {
                if (pointerId != MotionEvent.INVALID_POINTER_ID) {
                    return true;
                }

                int pointer = event.getActionIndex();
                pointerId = event.getPointerId(pointer);
                lastAlong = horizontal ? event.getX(pointer) : event.getY(pointer);
                swept = 0f;

                int zone = zoneAt(event.getX(pointer), event.getY(pointer));
                if (zone != 0) {
                    step(zone);
                    repeatDirection = zone;
                    postDelayed(repeat, REPEAT_FIRST_MS);
                }

                return true;
            }

            case MotionEvent.ACTION_MOVE: {
                int pointer = event.findPointerIndex(pointerId);
                if (pointer < 0) {
                    return true;
                }

                float now = horizontal ? event.getX(pointer) : event.getY(pointer);
                swept += horizontal ? now - lastAlong : lastAlong - now;
                lastAlong = now;

                while (Math.abs(swept) >= stepDistance) {
                    int direction = swept > 0f ? 1 : -1;
                    swept -= direction * stepDistance;
                    removeCallbacks(repeat);
                    step(direction);
                }

                return true;
            }

            case MotionEvent.ACTION_UP:
            case MotionEvent.ACTION_POINTER_UP:
                if (event.getPointerId(event.getActionIndex()) != pointerId) {
                    return true;
                }

                finish();
                return true;

            case MotionEvent.ACTION_CANCEL:
                finish();
                return true;

            default:
                return super.onTouchEvent(event);
        }
    }

    private void finish() {
        pointerId = MotionEvent.INVALID_POINTER_ID;
        removeCallbacks(repeat);
        lit = 0;
        invalidate();
    }

    @Override
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        removeCallbacks(repeat);
    }

    /** +1 for the end that steps forward, -1 for the other, 0 for the readout between them. */
    private int zoneAt(float x, float y) {
        float position = horizontal ? x : y;
        float span = horizontal ? getWidth() : getHeight();

        if (position <= span * END_FRACTION) {
            return horizontal ? -1 : 1;
        }

        if (position >= span * (1f - END_FRACTION)) {
            return horizontal ? 1 : -1;
        }

        return 0;
    }

    private void step(int direction) {
        if (slots > 0) {
            index = (index + direction + slots) % slots;
        }

        lit = direction;
        invalidate();

        if (listener != null) {
            listener.onStep(direction, slots > 0 ? index : -1);
        }
    }
}
