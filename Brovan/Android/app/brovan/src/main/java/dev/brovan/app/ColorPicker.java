package dev.brovan.app;

import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.view.View;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.google.android.material.slider.Slider;

final class ColorPicker {

    interface Choice {
        void onChosen(int rgb);
    }

    private static final int[] READY = {
            0xFFFFFF, 0xB9C4D0, 0x6E7681, 0x111820,
            0xF2707A, 0xFF8C00, 0xE8C36B, 0x5BD68A,
            0x2DD4BF, 0x56B6C2, 0x6FB6F1, 0x7C9CF5,
            0xC792EA, 0xFF6FB5};

    private ColorPicker() {
    }

    static void show(Context context, int titleId, int current, Palette palette, Choice choice) {
        float[] hsv = new float[3];
        Color.colorToHSV(0xFF000000 | current, hsv);

        LinearLayout root = new LinearLayout(context);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(context, 20), dp(context, 12), dp(context, 20), 0);

        View preview = new View(context);
        root.addView(preview, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(context, 46)));
        swatch(preview, current);

        Slider hue = slider(context, root, palette, R.string.controls_hue, 360f, hsv[0]);
        Slider saturation = slider(context, root, palette, R.string.controls_saturation, 100f, hsv[1] * 100f);
        Slider brightness = slider(context, root, palette, R.string.controls_brightness, 100f, hsv[2] * 100f);

        int[] chosen = {current};
        Slider.OnChangeListener listener = (slider, value, fromUser) -> {
            chosen[0] = Color.HSVToColor(new float[]{
                    hue.getValue(), saturation.getValue() / 100f, brightness.getValue() / 100f}) & 0xFFFFFF;
            swatch(preview, chosen[0]);
        };

        hue.addOnChangeListener(listener);
        saturation.addOnChangeListener(listener);
        brightness.addOnChangeListener(listener);

        root.addView(ready(context, color -> {
            float[] preset = new float[3];
            Color.colorToHSV(0xFF000000 | color, preset);
            hue.setValue(snap(hue, preset[0]));
            saturation.setValue(snap(saturation, preset[1] * 100f));
            brightness.setValue(snap(brightness, preset[2] * 100f));
        }), 1);

        Theming.dialog(context, palette)
                .setTitle(titleId)
                .setView(root)
                .setPositiveButton(android.R.string.ok, (dialog, which) -> choice.onChosen(chosen[0]))
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    static void swatch(View view, int rgb) {
        GradientDrawable shape = new GradientDrawable();
        shape.setShape(GradientDrawable.RECTANGLE);
        shape.setCornerRadius(dp(view.getContext(), 8));
        shape.setColor(0xFF000000 | rgb);
        shape.setStroke(dp(view.getContext(), 1), Color.argb(60, 128, 128, 128));
        view.setBackground(shape);
    }

    private static View ready(Context context, Choice choice) {
        LinearLayout row = new LinearLayout(context);
        row.setOrientation(LinearLayout.HORIZONTAL);

        for (int color : READY) {
            View chip = new View(context);
            swatch(chip, color);
            chip.setOnClickListener(view -> choice.onChosen(color));

            LinearLayout.LayoutParams params =
                    new LinearLayout.LayoutParams(dp(context, 34), dp(context, 34));
            params.setMarginEnd(dp(context, 8));
            row.addView(chip, params);
        }

        HorizontalScrollView scroller = new HorizontalScrollView(context);
        scroller.setHorizontalScrollBarEnabled(false);
        scroller.addView(row);
        return scroller;
    }

    private static Slider slider(Context context, LinearLayout parent, Palette palette, int labelId,
                                 float to, float value) {
        TextView caption = new TextView(context);
        caption.setText(labelId);
        caption.setTextColor(palette.get(Palette.Role.TEXT_SECONDARY));
        caption.setTextSize(13f);
        caption.setGravity(Gravity.START);
        parent.addView(caption);

        Slider slider = new Slider(context);
        slider.setValueFrom(0f);
        slider.setValueTo(to);
        slider.setStepSize(1f);
        slider.setValue(snap(slider, value));
        parent.addView(slider, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        return slider;
    }

    private static float snap(Slider slider, float value) {
        float step = slider.getStepSize();
        float from = slider.getValueFrom();
        float snapped = from + Math.round((value - from) / step) * step;
        return Math.max(from, Math.min(slider.getValueTo(), snapped));
    }

    private static int dp(Context context, int value) {
        return Math.round(value * context.getResources().getDisplayMetrics().density);
    }
}
