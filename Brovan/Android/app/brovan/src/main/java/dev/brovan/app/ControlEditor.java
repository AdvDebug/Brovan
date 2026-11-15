package dev.brovan.app;

import android.graphics.Point;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.slider.Slider;

import java.util.function.ObjIntConsumer;
import java.util.function.ToIntFunction;

import dev.brovan.BrovanNative;
import dev.brovan.input.ControlItem;
import dev.brovan.input.ControlLayout;
import dev.brovan.input.ControlOverlay;
import dev.brovan.input.VirtualKey;

final class ControlEditor implements ControlOverlay.EditListener {

    interface Host {
        void onSave(ControlLayout layout);

        void onCancel();
    }

    private interface KeyChoice {
        void onChosen(VirtualKey key);
    }

    private static final int MARGIN_DP = 12;

    private final AppCompatActivity activity;
    private final ControlOverlay overlay;
    private final Palette palette;
    private final Host host;
    private final View root;
    private final View bar;
    private final View panel;
    private final View editor;
    private final TextView hint;
    private final ViewGroup keyRow;
    private final Slider size;
    private final Slider opacity;
    private final View fillSwatch;
    private final View strokeSwatch;
    private final View labelSwatch;
    private final Point spot = new Point();
    private final OnBackPressedCallback back;

    private ControlLayout layout;
    private boolean placementPending;

    ControlEditor(AppCompatActivity activity, ControlOverlay overlay, View root, Palette palette, Host host) {
        this.activity = activity;
        this.overlay = overlay;
        this.palette = palette;
        this.host = host;
        this.root = root;

        bar = root.findViewById(R.id.controls_bar);
        panel = root.findViewById(R.id.controls_panel);
        editor = root.findViewById(R.id.controls_editor);
        hint = root.findViewById(R.id.controls_hint);
        keyRow = root.findViewById(R.id.controls_keys);
        size = root.findViewById(R.id.controls_size);
        opacity = root.findViewById(R.id.controls_opacity);
        fillSwatch = root.findViewById(R.id.controls_colour_fill);
        strokeSwatch = root.findViewById(R.id.controls_colour_stroke);
        labelSwatch = root.findViewById(R.id.controls_colour_label);

        size.addOnChangeListener((slider, value, fromUser) -> {
            ControlItem selected = overlay.selected();
            if (selected != null && fromUser) {
                selected.size = (int) value;
                overlay.requestLayout();
            }
        });

        opacity.addOnChangeListener((slider, value, fromUser) -> {
            ControlItem selected = overlay.selected();
            if (selected != null && fromUser) {
                selected.opacity = value / 100f;
                overlay.restyle();
            }
        });

        bindSwatch(fillSwatch, R.string.controls_colour_fill, item -> item.fill(overlay.accent()),
                (item, rgb) -> item.fillColor = rgb, true);
        bindSwatch(strokeSwatch, R.string.controls_colour_stroke, item -> item.strokeColor,
                (item, rgb) -> item.strokeColor = rgb, false);
        bindSwatch(labelSwatch, R.string.controls_colour_label, item -> item.labelColor,
                (item, rgb) -> item.labelColor = rgb, false);

        root.findViewById(R.id.controls_style_all).setOnClickListener(button -> applyStyleToAll());
        root.findViewById(R.id.controls_delete).setOnClickListener(button -> deleteSelected());
        root.findViewById(R.id.controls_add).setOnClickListener(button -> showAdd());
        root.findViewById(R.id.controls_preset).setOnClickListener(button -> showPresets());
        root.findViewById(R.id.controls_cancel).setOnClickListener(button -> host.onCancel());
        root.findViewById(R.id.controls_save).setOnClickListener(button -> host.onSave(layout));

        back = new OnBackPressedCallback(false) {
            @Override
            public void handleOnBackPressed() {
                host.onCancel();
            }
        };
        activity.getOnBackPressedDispatcher().addCallback(activity, back);
    }

    boolean editing() {
        return back.isEnabled();
    }

    void start(ControlLayout value) {
        layout = value.copy();
        root.setVisibility(View.VISIBLE);
        panel.setVisibility(View.INVISIBLE);
        overlay.render(layout);
        overlay.setEditing(true, this);
        back.setEnabled(true);
        showSelection();
        showPanel();
    }

    void stop() {
        back.setEnabled(false);
        overlay.setEditing(false, null);
        root.setVisibility(View.GONE);
    }

    /** The panel waits for the finger to lift, so it never jumps around under a drag. */
    @Override
    public void onSelected(ControlItem item) {
        showSelection();

        if (item == null) {
            showPanel();
        } else {
            panel.setVisibility(View.INVISIBLE);
        }
    }

    @Override
    public void onMoved(ControlItem item) {
        showPanel();
    }

    private void showPanel() {
        if (!editing()) {
            return;
        }

        // The search reads where the controls are, so it waits for a pending layout to place them.
        if (overlay.getWidth() == 0 || overlay.isLayoutRequested()) {
            if (!placementPending) {
                placementPending = true;
                overlay.addOnLayoutChangeListener(new View.OnLayoutChangeListener() {
                    @Override
                    public void onLayoutChange(View view, int left, int top, int right, int bottom,
                                               int oldLeft, int oldTop, int oldRight, int oldBottom) {
                        overlay.removeOnLayoutChangeListener(this);
                        placementPending = false;
                        if (editing()) {
                            placePanel();
                        }
                    }
                });
            }
            return;
        }

        placePanel();
    }

    private void placePanel() {
        int margin = dp(MARGIN_DP);
        bar.measure(View.MeasureSpec.makeMeasureSpec(overlay.getWidth(), View.MeasureSpec.EXACTLY),
                View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED));
        panel.measure(View.MeasureSpec.makeMeasureSpec(panel.getLayoutParams().width, View.MeasureSpec.EXACTLY),
                View.MeasureSpec.makeMeasureSpec(overlay.getHeight(), View.MeasureSpec.AT_MOST));
        overlay.findClearSpot(panel.getMeasuredWidth(), panel.getMeasuredHeight(), margin,
                bar.getMeasuredHeight() + margin, spot);
        panel.setTranslationX(spot.x);
        panel.setTranslationY(spot.y);
        panel.setVisibility(View.VISIBLE);
    }

    private void showSelection() {
        ControlItem selected = overlay.selected();
        keyRow.removeAllViews();

        if (selected == null) {
            editor.setVisibility(View.GONE);
            hint.setText(R.string.controls_hint);
            return;
        }

        editor.setVisibility(View.VISIBLE);
        hint.setText(activity.getString(R.string.controls_selected, selected.caption()));
        size.setValue(Math.max(size.getValueFrom(), Math.min(size.getValueTo(), selected.size)));
        opacity.setValue(snap(opacity, selected.opacity * 100f));
        showSwatches(selected);

        switch (selected.kind) {
            case BUTTON:
                addKeyButton(R.string.controls_key, selected.key, key -> {
                    selected.key = key;
                    refresh();
                });
                break;

            case JOYSTICK:
            case DPAD:
                addKeyButton(R.string.controls_up, selected.up, key -> {
                    selected.up = key;
                    refresh();
                });
                addKeyButton(R.string.controls_down, selected.down, key -> {
                    selected.down = key;
                    refresh();
                });
                addKeyButton(R.string.controls_left, selected.left, key -> {
                    selected.left = key;
                    refresh();
                });
                addKeyButton(R.string.controls_right, selected.right, key -> {
                    selected.right = key;
                    refresh();
                });
                break;

            case MOUSE:
                addMouseButton(selected);
                break;

            case SWITCHER:
                addSlotsButton(selected);
                addOrientationButton(selected);
                break;

            default:
                break;
        }
    }

    private void bindSwatch(View swatch, int titleId, ToIntFunction<ControlItem> current,
                            ObjIntConsumer<ControlItem> choose, boolean accentChoice) {
        swatch.setOnClickListener(view -> {
            ControlItem selected = overlay.selected();
            if (selected == null) {
                return;
            }

            ColorPicker.show(activity, titleId, current.applyAsInt(selected), palette, rgb -> {
                choose.accept(selected, rgb);
                applyStyle();
            }, R.string.controls_colour_accent, accentChoice ? () -> {
                choose.accept(selected, ControlItem.ACCENT_FILL);
                applyStyle();
            } : null);
        });
    }

    private void showSwatches(ControlItem selected) {
        ColorPicker.swatch(fillSwatch, selected.fill(overlay.accent()));
        ColorPicker.swatch(strokeSwatch, selected.strokeColor);
        ColorPicker.swatch(labelSwatch, selected.labelColor);
    }

    private void applyStyle() {
        overlay.restyle();
        ControlItem selected = overlay.selected();
        if (selected != null) {
            showSwatches(selected);
        }
    }

    private void applyStyleToAll() {
        ControlItem selected = overlay.selected();
        if (selected == null) {
            return;
        }

        for (ControlItem item : layout.items()) {
            selected.copyStyleTo(item);
        }

        overlay.restyle();
        Toast.makeText(activity, R.string.controls_style_all_done, Toast.LENGTH_SHORT).show();
    }

    private static float snap(Slider slider, float value) {
        float step = slider.getStepSize();
        float from = slider.getValueFrom();
        float snapped = from + Math.round((value - from) / step) * step;
        return Math.max(from, Math.min(slider.getValueTo(), snapped));
    }

    private void addChoice(CharSequence text, View.OnClickListener click) {
        MaterialButton button = new MaterialButton(activity, null,
                com.google.android.material.R.attr.materialButtonOutlinedStyle);
        button.setText(text);
        button.setOnClickListener(click);
        keyRow.addView(button, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
    }

    private void addKeyButton(int labelId, VirtualKey current, KeyChoice choice) {
        addChoice(activity.getString(labelId, current.label()), view -> pickKey(choice));
    }

    private void addMouseButton(ControlItem selected) {
        boolean right = selected.mouseButton == BrovanNative.BUTTON_RIGHT;

        addChoice(activity.getString(right ? R.string.controls_mouse_right : R.string.controls_mouse_left), view -> {
            selected.mouseButton = right ? BrovanNative.BUTTON_LEFT : BrovanNative.BUTTON_RIGHT;
            selected.label = right ? "L" : "R";
            refresh();
        });
    }

    private void addSlotsButton(ControlItem selected) {
        String slots = selected.slots > 0
                ? Integer.toString(selected.slots)
                : activity.getString(R.string.controls_slots_wheel);

        addChoice(activity.getString(R.string.controls_slots, slots), view -> pickSlots(selected));
    }

    private void addOrientationButton(ControlItem selected) {
        addChoice(activity.getString(selected.horizontal ? R.string.controls_horizontal : R.string.controls_vertical),
                view -> {
                    selected.horizontal = !selected.horizontal;
                    refresh();
                });
    }

    private void pickSlots(ControlItem selected) {
        CharSequence[] labels = new CharSequence[ControlItem.MAX_SLOTS];
        labels[0] = activity.getString(R.string.controls_slots_wheel);
        for (int i = 1; i < labels.length; i++) {
            labels[i] = Integer.toString(i + 1);
        }

        Theming.dialog(activity)
                .setTitle(R.string.controls_slots_title)
                .setItems(labels, (dialog, index) -> {
                    selected.slots = index == 0 ? 0 : index + 1;
                    refresh();
                })
                .show();
    }

    private void pickKey(KeyChoice choice) {
        VirtualKey[] all = VirtualKey.values();
        CharSequence[] labels = new CharSequence[all.length];
        for (int i = 0; i < all.length; i++) {
            labels[i] = all[i].label();
        }

        Theming.dialog(activity)
                .setTitle(R.string.controls_pick_key)
                .setItems(labels, (dialog, index) -> choice.onChosen(all[index]))
                .show();
    }

    private void showAdd() {
        CharSequence[] options = {
                activity.getString(R.string.controls_add_button),
                activity.getString(R.string.controls_add_joystick),
                activity.getString(R.string.controls_add_dpad),
                activity.getString(R.string.controls_add_touchpad),
                activity.getString(R.string.controls_add_mouse),
                activity.getString(R.string.controls_add_switcher),
                activity.getString(R.string.controls_add_wheel)};

        Theming.dialog(activity)
                .setTitle(R.string.controls_add)
                .setItems(options, (dialog, index) -> add(index))
                .show();
    }

    private void add(int index) {
        ControlItem item;

        switch (index) {
            case 1:
                item = ControlItem.stick(ControlItem.Kind.JOYSTICK,
                        VirtualKey.W, VirtualKey.S, VirtualKey.A, VirtualKey.D, 180);
                break;

            case 2:
                item = ControlItem.stick(ControlItem.Kind.DPAD,
                        VirtualKey.UP, VirtualKey.DOWN, VirtualKey.LEFT, VirtualKey.RIGHT, 190);
                break;

            case 3:
                item = ControlItem.touchpad(260);
                break;

            case 4:
                item = ControlItem.mouse(BrovanNative.BUTTON_LEFT, "L", 66);
                break;

            case 5:
                item = ControlItem.switcher(4, false, 190);
                break;

            case 6:
                item = ControlItem.switcher(0, false, 150);
                break;

            default:
                item = ControlItem.button(VirtualKey.SPACE, 70);
                break;
        }

        item.anchorAt(overlay.widthDp() / 2f, overlay.heightDp() / 2f, overlay.widthDp(), overlay.heightDp());

        layout.add(item);
        overlay.render(layout);
        select(item);
    }

    private void deleteSelected() {
        ControlItem selected = overlay.selected();
        if (selected == null) {
            return;
        }

        layout.remove(selected);
        overlay.render(layout);
        select(null);
    }

    private void showPresets() {
        ControlOverlay.Scheme[] schemes = {ControlOverlay.Scheme.WASD, ControlOverlay.Scheme.ARROWS,
                ControlOverlay.Scheme.DPAD, ControlOverlay.Scheme.TOUCHPAD};
        String[] names = activity.getResources().getStringArray(R.array.control_schemes);
        CharSequence[] labels = new CharSequence[schemes.length];
        for (int i = 0; i < schemes.length; i++) {
            labels[i] = names[schemes[i].ordinal()];
        }

        Theming.dialog(activity)
                .setTitle(R.string.controls_preset_title)
                .setItems(labels, (dialog, index) -> {
                    layout = ControlLayout.forScheme(schemes[index]);
                    overlay.render(layout);
                    select(null);
                })
                .show();
    }

    private void refresh() {
        ControlItem selected = overlay.selected();
        overlay.render(layout);
        select(selected);
    }

    /** A selection made here, not by a finger, has no lift to wait for. */
    private void select(ControlItem item) {
        overlay.select(item);
        showPanel();
    }

    private int dp(int value) {
        return Math.round(value * activity.getResources().getDisplayMetrics().density);
    }
}
