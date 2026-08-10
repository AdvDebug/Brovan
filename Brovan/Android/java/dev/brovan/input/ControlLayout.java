package dev.brovan.input;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

import dev.brovan.BrovanNative;

/** An arrangement of controls: what the built-in schemes produce, and what the editor saves. */
public final class ControlLayout {

    private final List<ControlItem> items = new ArrayList<>();

    public List<ControlItem> items() {
        return items;
    }

    public void add(ControlItem item) {
        items.add(item);
    }

    public void remove(ControlItem item) {
        items.remove(item);
    }

    public ControlLayout copy() {
        ControlLayout layout = new ControlLayout();
        for (ControlItem item : items) {
            layout.add(item.copy());
        }
        return layout;
    }

    public static ControlLayout forScheme(ControlOverlay.Scheme scheme) {
        ControlLayout layout = new ControlLayout();

        switch (scheme) {
            case WASD:
                layout.add(ControlItem.stick(ControlItem.Kind.JOYSTICK,
                        VirtualKey.W, VirtualKey.S, VirtualKey.A, VirtualKey.D, 0.13f, 0.68f, 180));
                addActions(layout);
                break;

            case ARROWS:
                layout.add(ControlItem.stick(ControlItem.Kind.JOYSTICK,
                        VirtualKey.UP, VirtualKey.DOWN, VirtualKey.LEFT, VirtualKey.RIGHT, 0.13f, 0.68f, 180));
                addActions(layout);
                break;

            case DPAD:
                layout.add(ControlItem.stick(ControlItem.Kind.DPAD,
                        VirtualKey.UP, VirtualKey.DOWN, VirtualKey.LEFT, VirtualKey.RIGHT, 0.13f, 0.68f, 190));
                addActions(layout);
                break;

            case TOUCHPAD:
                layout.add(ControlItem.touchpad(0.82f, 0.70f, 260));
                layout.add(ControlItem.mouse(BrovanNative.BUTTON_LEFT, "L", 0.62f, 0.84f, 66));
                layout.add(ControlItem.mouse(BrovanNative.BUTTON_RIGHT, "R", 0.62f, 0.60f, 66));
                break;

            case NONE:
            default:
                break;
        }

        return layout;
    }

    private static void addActions(ControlLayout layout) {
        layout.add(ControlItem.button(VirtualKey.SPACE, "A", 0.88f, 0.86f, 70));
        layout.add(ControlItem.button(VirtualKey.ENTER, "B", 0.94f, 0.66f, 70));
        layout.add(ControlItem.button(VirtualKey.SHIFT, "X", 0.82f, 0.66f, 70));
        layout.add(ControlItem.button(VirtualKey.ESCAPE, "Esc", 0.88f, 0.46f, 70));
    }

    public String toJson() {
        JSONArray array = new JSONArray();

        for (ControlItem item : items) {
            try {
                array.put(item.toJson());
            } catch (JSONException broken) {
                // A control that cannot be written is dropped rather than losing the whole layout.
            }
        }

        return array.toString();
    }

    public static ControlLayout fromJson(String json) {
        ControlLayout layout = new ControlLayout();
        if (json == null || json.isEmpty()) {
            return layout;
        }

        try {
            JSONArray array = new JSONArray(json);

            for (int i = 0; i < array.length(); i++) {
                JSONObject entry = array.optJSONObject(i);
                if (entry == null) {
                    continue;
                }

                ControlItem item = ControlItem.fromJson(entry);
                if (item != null) {
                    layout.add(item);
                }
            }
        } catch (JSONException broken) {
            return new ControlLayout();
        }

        return layout;
    }
}
