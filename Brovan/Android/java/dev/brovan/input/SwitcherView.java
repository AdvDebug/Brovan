package dev.brovan.input;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.Typeface;
import android.view.MotionEvent;
import android.view.View;

/**
 * Steps a selection one notch at a time. Tapping an end steps once and holding it repeats; sweeping a
 * finger along the control runs through several. What a step means is the overlay's business.
 */
public class SwitcherView extends View {

    public interface Listener {
        /** Direction is +1 or -1. Slot is the slot now selected, or -1 when the control keeps no slots. */
        void onStep(int direction, int slot);
    }

    private static final float END_FRACTION = 0.32f;
    private static final float RING_DP = 1.8f;
    private static final float DROP_DP = 3f;
    private static final float CHEVRON_DP = 2.4f;
    private static final float STEP_DP = 26f;
    private static final long REPEAT_FIRST_MS = 360;
    private static final long REPEAT_MS = 140;

    private final Paint fillPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint ringPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint dividerPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint litPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint dropPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint chevronPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint glyphPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Path chevron = new Path();
    private final RectF bounds = new RectF();
    private final RectF endBounds = new RectF();
    private final RectF glyphBounds = new RectF();

    private final float ringWidth;
    private final float drop;
    private final float stepDistance;

    private int fillColor = ControlItem.DEFAULT_COLOR;
    private int strokeColor = ControlItem.DEFAULT_COLOR;
    private int labelColor = ControlItem.DEFAULT_COLOR;
    private float opacity = 1f;

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

    public SwitcherView(Context context) {
        super(context);

        float density = getResources().getDisplayMetrics().density;
        ringWidth = RING_DP * density;
        drop = DROP_DP * density;
        stepDistance = STEP_DP * density;

        ringPaint.setStyle(Paint.Style.STROKE);
        ringPaint.setStrokeWidth(ringWidth);
        dividerPaint.setStyle(Paint.Style.STROKE);
        dividerPaint.setStrokeWidth(density);
        chevronPaint.setStyle(Paint.Style.STROKE);
        chevronPaint.setStrokeWidth(CHEVRON_DP * density);
        chevronPaint.setStrokeCap(Paint.Cap.ROUND);
        chevronPaint.setStrokeJoin(Paint.Join.ROUND);
        glyphPaint.setStyle(Paint.Style.STROKE);
        glyphPaint.setStrokeWidth(CHEVRON_DP * density * 0.8f);
        glyphPaint.setStrokeCap(Paint.Cap.ROUND);
        textPaint.setTextAlign(Paint.Align.CENTER);
        textPaint.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        textPaint.setShadowLayer(2f * density, 0f, density, 0x99000000);
        applyStyle();
    }

    public void setStyle(int fill, int stroke, int text, float opacity) {
        fillColor = fill;
        strokeColor = stroke;
        labelColor = text;
        this.opacity = opacity;
        applyStyle();
        invalidate();
    }

    private void applyStyle() {
        ringPaint.setColor(ControlItem.shade(strokeColor, 150, opacity));
        dividerPaint.setColor(ControlItem.shade(strokeColor, 60, opacity));
        litPaint.setColor(ControlItem.shade(fillColor, 90, opacity));
        dropPaint.setColor(ControlItem.shade(0x000000, 60, opacity));
        textPaint.setColor(ControlItem.shade(labelColor, 235, opacity));
        glyphPaint.setColor(ControlItem.shade(labelColor, 175, opacity));
        buildFill();
    }

    private void buildFill() {
        if (getWidth() <= 0 || getHeight() <= 0) {
            fillPaint.setShader(null);
            fillPaint.setColor(ControlItem.shade(fillColor, 70, opacity));
            return;
        }

        fillPaint.setShader(new LinearGradient(0f, 0f, horizontal ? getWidth() : 0f,
                horizontal ? 0f : getHeight(),
                ControlItem.shade(fillColor, 95, opacity), ControlItem.shade(fillColor, 45, opacity),
                Shader.TileMode.CLAMP));
    }

    @Override
    protected void onSizeChanged(int width, int height, int oldWidth, int oldHeight) {
        super.onSizeChanged(width, height, oldWidth, oldHeight);
        buildFill();
    }

    /** Zero keeps no selection of its own, which is what a control that only turns a wheel wants. */
    public void setSlots(int count) {
        slots = Math.max(0, count);
        index = 0;
        invalidate();
    }

    public void setHorizontal(boolean value) {
        horizontal = value;
        buildFill();
        invalidate();
    }

    public void setListener(Listener listener) {
        this.listener = listener;
    }

    @Override
    protected void onDraw(Canvas canvas) {
        float inset = ringWidth + drop;
        float corner = (horizontal ? getHeight() : getWidth()) / 2f - inset;
        if (corner <= 0f) {
            return;
        }

        bounds.set(inset, inset, getWidth() - inset, getHeight() - inset);

        canvas.save();
        canvas.translate(0f, drop * 0.7f);
        canvas.drawRoundRect(bounds, corner, corner, dropPaint);
        canvas.restore();

        canvas.drawRoundRect(bounds, corner, corner, fillPaint);

        if (lit != 0) {
            canvas.save();
            canvas.clipRect(endBounds());
            canvas.drawRoundRect(bounds, corner, corner, litPaint);
            canvas.restore();
        }

        canvas.drawRoundRect(bounds, corner, corner, ringPaint);
        drawDividers(canvas);

        float across = horizontal ? bounds.height() : bounds.width();
        drawEnds(canvas, across * 0.18f);

        if (slots > 0) {
            textPaint.setTextSize(across * 0.40f);
            float baseline = bounds.centerY() - (textPaint.descent() + textPaint.ascent()) / 2f;
            canvas.drawText(Integer.toString(index + 1), bounds.centerX(), baseline, textPaint);
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
        chevronPaint.setColor(ControlItem.shade(labelColor, bright ? 255 : 170, opacity));

        canvas.save();
        canvas.rotate(rotation, centreX, centreY);
        chevron.reset();
        chevron.moveTo(centreX - half, centreY + half * 0.5f);
        chevron.lineTo(centreX, centreY - half * 0.5f);
        chevron.lineTo(centreX + half, centreY + half * 0.5f);
        canvas.drawPath(chevron, chevronPaint);
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
            canvas.drawLine(bounds.left + end, top, bounds.left + end, bottom, dividerPaint);
            canvas.drawLine(bounds.right - end, top, bounds.right - end, bottom, dividerPaint);
        } else {
            float left = bounds.left + bounds.width() * 0.24f;
            float right = bounds.right - bounds.width() * 0.24f;
            canvas.drawLine(left, bounds.top + end, right, bounds.top + end, dividerPaint);
            canvas.drawLine(left, bounds.bottom - end, right, bounds.bottom - end, dividerPaint);
        }
    }

    /** A control with no slots of its own still has to say what it does, so it draws the wheel it turns. */
    private void drawWheel(Canvas canvas, float centreX, float centreY, float half) {
        glyphBounds.set(centreX - half * 0.70f, centreY - half, centreX + half * 0.70f, centreY + half);
        canvas.drawRoundRect(glyphBounds, half * 0.70f, half * 0.70f, glyphPaint);
        canvas.drawLine(centreX, centreY - half * 0.52f, centreX, centreY - half * 0.10f, glyphPaint);
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
