package dev.brovan.input;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.DashPathEffect;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RadialGradient;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.Typeface;
import android.util.TypedValue;

import androidx.core.graphics.ColorUtils;

public final class ControlPainter {

    public static final int DARK_INK = 0x0B1020;

    private static final int SCRIM = 0x090D14;
    private static final int KNOB_SHADE = 0x6E7891;
    private static final float SCRIM_MIX = 0.82f;

    private static final int REST_ALPHA = 133;
    private static final int QUIET_ALPHA = 87;
    private static final int PRESSED_ALPHA = 240;
    private static final int LIT_ALPHA = 180;
    private static final int RIM_ALPHA = 173;
    private static final int EDGE_ALPHA = 82;
    private static final int LABEL_ALPHA = 247;
    private static final int INK_ALPHA = 217;
    private static final int KNOB_ALPHA = 245;
    private static final int KNOB_SHADOW_ALPHA = 90;
    private static final int DIVIDER_ALPHA = 56;
    private static final int DEAD_ZONE_ALPHA = 107;
    private static final int DOT_ALPHA = 50;

    private static final float RIM_DP = 1.5f;
    private static final float EDGE_DP = 3.4f;
    private static final float LINE_DP = 2.4f;
    private static final float DASH_DP = 1.2f;
    private static final float KNOB_DROP_DP = 2.5f;
    private static final float PAD_CORNER_DP = 16f;
    private static final float DOT_PITCH_DP = 22f;
    private static final float DOT_DP = 1.2f;
    private static final float PRESS_SCALE = 0.94f;
    private static final float MIN_TEXT_SP = 11f;

    /** Above this relative luminance, dark text has more contrast than white. */
    private static final double INK_SWITCH = 0.179;

    private final float density;
    private final float minTextSize;
    private final int accent;
    private final int onAccent;

    private final Paint restPaint = fill();
    private final Paint quietPaint = fill();
    private final Paint pressedPaint = fill();
    private final Paint litPaint = fill();
    private final Paint inkPaint = fill();
    private final Paint brightInkPaint = fill();
    private final Paint dotPaint = fill();
    private final Paint knobPaint = fill();
    private final Paint knobShadowPaint = fill();
    private final Paint textPaint = fill();
    private final Paint edgePaint;
    private final Paint rimPaint;
    private final Paint linePaint;
    private final Paint brightLinePaint;
    private final Paint dividerPaint;
    private final Paint deadZonePaint;
    private final Paint knobEdgePaint;
    private final Path shape = new Path();

    private int labelColor;
    private int pressedLabelColor;
    private int knobTop;
    private int knobBottom;
    private int knobActiveTop;
    private int knobActiveBottom;
    private float knobRadius = -1f;
    private boolean knobActive;

    public ControlPainter(Context context, int accent, int onAccent) {
        density = context.getResources().getDisplayMetrics().density;
        minTextSize = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, MIN_TEXT_SP,
                context.getResources().getDisplayMetrics());
        this.accent = accent & 0xFFFFFF;
        this.onAccent = onAccent & 0xFFFFFF;

        edgePaint = stroke(EDGE_DP * density);
        rimPaint = stroke(RIM_DP * density);
        linePaint = stroke(LINE_DP * density);
        brightLinePaint = stroke(LINE_DP * density);
        dividerPaint = stroke(density);
        deadZonePaint = stroke(DASH_DP * density);
        deadZonePaint.setPathEffect(new DashPathEffect(new float[]{2f * density, 4f * density}, 0f));
        knobEdgePaint = stroke(density);

        textPaint.setTextAlign(Paint.Align.CENTER);
        textPaint.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
    }

    public void setStyle(ControlItem item) {
        int fill = item.fill(accent);
        int body = mix(fill, SCRIM, SCRIM_MIX);
        float opacity = item.opacity;

        restPaint.setColor(ControlItem.shade(body, REST_ALPHA, opacity));
        quietPaint.setColor(ControlItem.shade(body, QUIET_ALPHA, opacity));
        pressedPaint.setColor(ControlItem.shade(fill, PRESSED_ALPHA, opacity));
        litPaint.setColor(ControlItem.shade(fill, LIT_ALPHA, opacity));
        edgePaint.setColor(ControlItem.shade(0x000000, EDGE_ALPHA, opacity));
        rimPaint.setColor(ControlItem.shade(item.strokeColor, RIM_ALPHA, opacity));
        dividerPaint.setColor(ControlItem.shade(item.strokeColor, DIVIDER_ALPHA, opacity));

        int pressedInk;
        if (item.fillColor == ControlItem.ACCENT_FILL) {
            pressedInk = onAccent;
        } else {
            pressedInk = ColorUtils.calculateLuminance(0xFF000000 | fill) > INK_SWITCH ? DARK_INK : item.labelColor;
        }

        labelColor = ControlItem.shade(item.labelColor, LABEL_ALPHA, opacity);
        pressedLabelColor = ControlItem.shade(pressedInk, LABEL_ALPHA, opacity);
        inkPaint.setColor(ControlItem.shade(item.labelColor, INK_ALPHA, opacity));
        brightInkPaint.setColor(ControlItem.shade(item.labelColor, 255, opacity));
        linePaint.setColor(ControlItem.shade(item.labelColor, INK_ALPHA, opacity));
        brightLinePaint.setColor(ControlItem.shade(item.labelColor, 255, opacity));
        deadZonePaint.setColor(ControlItem.shade(item.labelColor, DEAD_ZONE_ALPHA, opacity));
        dotPaint.setColor(ControlItem.shade(item.labelColor, DOT_ALPHA, opacity));

        knobTop = ControlItem.shade(item.labelColor, KNOB_ALPHA, opacity);
        knobBottom = ControlItem.shade(mix(item.labelColor, KNOB_SHADE, 0.25f), KNOB_ALPHA, opacity);
        knobActiveTop = ControlItem.shade(mix(fill, 0xFFFFFF, 0.35f), KNOB_ALPHA, opacity);
        knobActiveBottom = ControlItem.shade(fill, KNOB_ALPHA, opacity);
        knobShadowPaint.setColor(ControlItem.shade(0x000000, KNOB_SHADOW_ALPHA, opacity));
        knobEdgePaint.setColor(ControlItem.shade(0x000000, KNOB_SHADOW_ALPHA, opacity));
        knobRadius = -1f;
    }

    /** How far a body sits inside its view, so the outer edge is not cut by the view bounds. */
    public float inset() {
        return EDGE_DP * density / 2f;
    }

    /** The shape builders share one path; draw it before asking for the next. */
    public Path circle(float centreX, float centreY, float radius) {
        shape.reset();
        shape.addCircle(centreX, centreY, radius, Path.Direction.CW);
        return shape;
    }

    public Path pad(RectF bounds) {
        float corner = PAD_CORNER_DP * density;
        shape.reset();
        shape.addRoundRect(bounds, corner, corner, Path.Direction.CW);
        return shape;
    }

    public Path pill(RectF bounds) {
        float corner = Math.min(bounds.width(), bounds.height()) / 2f;
        shape.reset();
        shape.addRoundRect(bounds, corner, corner, Path.Direction.CW);
        return shape;
    }

    public void buildCross(Path out, float centreX, float centreY, float radius, float half) {
        float corner = half * 0.6f;
        out.reset();

        Path vertical = new Path();
        vertical.addRoundRect(centreX - half, centreY - radius, centreX + half, centreY + radius,
                corner, corner, Path.Direction.CW);

        Path horizontal = new Path();
        horizontal.addRoundRect(centreX - radius, centreY - half, centreX + radius, centreY + half,
                corner, corner, Path.Direction.CW);

        out.op(vertical, horizontal, Path.Op.UNION);
    }

    public void body(Canvas canvas, Path outline, boolean pressed, boolean quiet) {
        canvas.drawPath(outline, pressed ? pressedPaint : quiet ? quietPaint : restPaint);
        canvas.drawPath(outline, edgePaint);
        canvas.drawPath(outline, rimPaint);
    }

    public void begin(Canvas canvas, float centreX, float centreY, boolean pressed) {
        canvas.save();
        if (pressed) {
            canvas.scale(PRESS_SCALE, PRESS_SCALE, centreX, centreY);
        }
    }

    public void end(Canvas canvas) {
        canvas.restore();
    }

    public void label(Canvas canvas, String text, float centreX, float centreY, float size, boolean pressed) {
        drawText(canvas, text, centreX, centreY, size, pressed ? pressedLabelColor : labelColor);
    }

    public float fit(String text, float width, float size) {
        textPaint.setTextSize(size);
        float measured = textPaint.measureText(text);
        float fitted = measured > width ? size * width / measured : size;
        return Math.max(minTextSize, fitted);
    }

    public void legend(Canvas canvas, String text, float centreX, float centreY, float size, boolean held) {
        if (held) {
            canvas.drawCircle(centreX, centreY, size * 0.95f, litPaint);
        }

        drawText(canvas, text, centreX, centreY, size, held ? pressedLabelColor : inkPaint.getColor());
    }

    private void drawText(Canvas canvas, String text, float centreX, float centreY, float size, int color) {
        textPaint.setTextSize(size);
        textPaint.setColor(color);
        float baseline = centreY - (textPaint.descent() + textPaint.ascent()) / 2f;
        canvas.drawText(text, centreX, baseline, textPaint);
    }

    public Paint lit() {
        return litPaint;
    }

    public Paint ink(boolean bright) {
        return bright ? brightInkPaint : inkPaint;
    }

    public Paint line(boolean bright) {
        return bright ? brightLinePaint : linePaint;
    }

    public Paint divider() {
        return dividerPaint;
    }

    public void deadZone(Canvas canvas, float centreX, float centreY, float radius) {
        canvas.drawCircle(centreX, centreY, radius, deadZonePaint);
    }

    public void dots(Canvas canvas, RectF bounds) {
        float pitch = DOT_PITCH_DP * density;
        float radius = DOT_DP * density;

        for (float x = bounds.left + pitch; x < bounds.right - pitch / 2f; x += pitch) {
            for (float y = bounds.top + pitch; y < bounds.bottom - pitch / 2f; y += pitch) {
                canvas.drawCircle(x, y, radius, dotPaint);
            }
        }
    }

    public void knob(Canvas canvas, float x, float y, float radius, boolean active) {
        canvas.drawCircle(x, y + KNOB_DROP_DP * density, radius, knobShadowPaint);

        if (radius != knobRadius || active != knobActive) {
            knobPaint.setShader(new RadialGradient(-0.3f * radius, -0.35f * radius, 1.35f * radius,
                    active ? knobActiveTop : knobTop, active ? knobActiveBottom : knobBottom,
                    Shader.TileMode.CLAMP));
            knobRadius = radius;
            knobActive = active;
        }

        canvas.save();
        canvas.translate(x, y);
        canvas.drawCircle(0f, 0f, radius, knobPaint);
        canvas.drawCircle(0f, 0f, radius, knobEdgePaint);
        canvas.restore();
    }

    private static Paint fill() {
        Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        paint.setStyle(Paint.Style.FILL);
        return paint;
    }

    private static Paint stroke(float width) {
        Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        paint.setStyle(Paint.Style.STROKE);
        paint.setStrokeWidth(width);
        paint.setStrokeJoin(Paint.Join.ROUND);
        paint.setStrokeCap(Paint.Cap.ROUND);
        return paint;
    }

    private static int mix(int from, int to, float amount) {
        return ColorUtils.blendARGB(0xFF000000 | from, 0xFF000000 | to, amount) & 0xFFFFFF;
    }
}
