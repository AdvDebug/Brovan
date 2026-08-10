package dev.brovan.app;

import android.os.Bundle;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.slider.Slider;

import dev.brovan.BrovanNative;
import dev.brovan.input.ControlItem;
import dev.brovan.input.ControlLayout;
import dev.brovan.input.ControlOverlay;
import dev.brovan.input.VirtualKey;

/** Lays out the touch controls: drag to place, tap to select, and every control binds to a key of its own. */
public class ControlsActivity extends AppCompatActivity implements ControlOverlay.EditListener {

    private Settings settings;
    private ControlOverlay overlay;
    private ControlLayout layout;
    private View editor;
    private TextView hint;
    private LinearLayout keyRow;
    private Slider size;
    private ControlItem selected;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_controls);

        settings = new Settings(this);

        overlay = findViewById(R.id.controls);
        editor = findViewById(R.id.controls_editor);
        hint = findViewById(R.id.controls_hint);
        keyRow = findViewById(R.id.controls_keys);
        size = findViewById(R.id.controls_size);

        layout = ControlLayout.fromJson(settings.controlLayout());
        if (layout.items().isEmpty()) {
            layout = ControlLayout.forScheme(ControlOverlay.Scheme.WASD);
        }

        overlay.render(layout);
        overlay.setEditing(true, this);

        size.addOnChangeListener((slider, value, fromUser) -> {
            if (selected != null && fromUser) {
                selected.size = (int) value;
                overlay.requestLayout();
            }
        });

        findViewById(R.id.controls_delete).setOnClickListener(button -> deleteSelected());
        findViewById(R.id.controls_add).setOnClickListener(button -> showAdd());
        findViewById(R.id.controls_preset).setOnClickListener(button -> showPresets());
        findViewById(R.id.controls_save).setOnClickListener(button -> save());
    }

    @Override
    public void onSelected(ControlItem item) {
        selected = item;
        showSelection();
    }

    @Override
    public void onMoved(ControlItem item) {
        // Positions are written straight into the layout while dragging; nothing left to do here.
    }

    private void showSelection() {
        keyRow.removeAllViews();

        if (selected == null) {
            editor.setVisibility(View.GONE);
            hint.setText(R.string.controls_hint);
            return;
        }

        editor.setVisibility(View.VISIBLE);
        hint.setText(getString(R.string.controls_selected, selected.caption()));
        size.setValue(Math.max(size.getValueFrom(), Math.min(size.getValueTo(), selected.size)));

        switch (selected.kind) {
            case BUTTON:
                addKeyButton(R.string.controls_key, selected.key, key -> {
                    selected.key = key;
                    selected.label = key.label();
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
                addMouseButton();
                break;

            default:
                break;
        }
    }

    private interface KeyChoice {
        void onChosen(VirtualKey key);
    }

    private void addKeyButton(int labelId, VirtualKey current, KeyChoice choice) {
        MaterialButton button = new MaterialButton(this, null,
                com.google.android.material.R.attr.materialButtonOutlinedStyle);
        button.setText(getString(labelId, current.label()));
        button.setOnClickListener(view -> pickKey(choice));

        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        params.setMarginEnd(dp(8));
        keyRow.addView(button, params);
    }

    private void addMouseButton() {
        MaterialButton button = new MaterialButton(this, null,
                com.google.android.material.R.attr.materialButtonOutlinedStyle);
        boolean right = selected.mouseButton == BrovanNative.BUTTON_RIGHT;
        button.setText(getString(right ? R.string.controls_mouse_right : R.string.controls_mouse_left));
        button.setOnClickListener(view -> {
            selected.mouseButton = right ? BrovanNative.BUTTON_LEFT : BrovanNative.BUTTON_RIGHT;
            selected.label = right ? "L" : "R";
            refresh();
        });

        keyRow.addView(button);
    }

    private void pickKey(KeyChoice choice) {
        VirtualKey[] all = VirtualKey.values();
        CharSequence[] labels = new CharSequence[all.length];
        for (int i = 0; i < all.length; i++) {
            labels[i] = all[i].label();
        }

        new AlertDialog.Builder(this)
                .setTitle(R.string.controls_pick_key)
                .setItems(labels, (dialog, index) -> choice.onChosen(all[index]))
                .show();
    }

    private void showAdd() {
        CharSequence[] options = {
                getString(R.string.controls_add_button),
                getString(R.string.controls_add_joystick),
                getString(R.string.controls_add_dpad),
                getString(R.string.controls_add_touchpad),
                getString(R.string.controls_add_mouse)};

        new AlertDialog.Builder(this)
                .setTitle(R.string.controls_add)
                .setItems(options, (dialog, index) -> add(index))
                .show();
    }

    private void add(int index) {
        ControlItem item;

        switch (index) {
            case 1:
                item = ControlItem.stick(ControlItem.Kind.JOYSTICK,
                        VirtualKey.W, VirtualKey.S, VirtualKey.A, VirtualKey.D, 0.5f, 0.5f, 180);
                break;

            case 2:
                item = ControlItem.stick(ControlItem.Kind.DPAD,
                        VirtualKey.UP, VirtualKey.DOWN, VirtualKey.LEFT, VirtualKey.RIGHT, 0.5f, 0.5f, 190);
                break;

            case 3:
                item = ControlItem.touchpad(0.5f, 0.5f, 260);
                break;

            case 4:
                item = ControlItem.mouse(BrovanNative.BUTTON_LEFT, "L", 0.5f, 0.5f, 66);
                break;

            default:
                item = ControlItem.button(VirtualKey.SPACE, VirtualKey.SPACE.label(), 0.5f, 0.5f, 70);
                break;
        }

        layout.add(item);
        overlay.render(layout);
        overlay.select(item);
    }

    private void deleteSelected() {
        if (selected == null) {
            return;
        }

        layout.remove(selected);
        selected = null;
        overlay.render(layout);
        showSelection();
    }

    private void showPresets() {
        ControlOverlay.Scheme[] schemes = {ControlOverlay.Scheme.WASD, ControlOverlay.Scheme.ARROWS,
                ControlOverlay.Scheme.DPAD, ControlOverlay.Scheme.TOUCHPAD};
        CharSequence[] labels = new CharSequence[schemes.length];
        for (int i = 0; i < schemes.length; i++) {
            labels[i] = schemes[i].label();
        }

        new AlertDialog.Builder(this)
                .setTitle(R.string.controls_preset_title)
                .setItems(labels, (dialog, index) -> {
                    layout = ControlLayout.forScheme(schemes[index]);
                    selected = null;
                    overlay.render(layout);
                    showSelection();
                })
                .show();
    }

    private void refresh() {
        overlay.render(layout);
        overlay.select(selected);
    }

    private void save() {
        settings.setControlLayout(layout.toJson());
        settings.setControlScheme(ControlOverlay.Scheme.CUSTOM.ordinal());
        finish();
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
