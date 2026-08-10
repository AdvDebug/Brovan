package dev.brovan.input;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * One control on the overlay. Positions are fractions of the overlay so a layout survives a different
 * screen or orientation; sizes stay in dp so a control keeps its physical size.
 */
public final class ControlItem {

    public enum Kind {
        BUTTON,
        JOYSTICK,
        DPAD,
        TOUCHPAD,
        MOUSE
    }

    public Kind kind;
    public float x;
    public float y;
    public int size;
    public VirtualKey key;
    public VirtualKey up;
    public VirtualKey down;
    public VirtualKey left;
    public VirtualKey right;
    public int mouseButton;
    public String label;

    public static ControlItem button(VirtualKey key, String label, float x, float y, int size) {
        ControlItem item = new ControlItem();
        item.kind = Kind.BUTTON;
        item.key = key;
        item.label = label;
        item.x = x;
        item.y = y;
        item.size = size;
        return item;
    }

    public static ControlItem stick(Kind kind, VirtualKey up, VirtualKey down, VirtualKey left, VirtualKey right,
                                    float x, float y, int size) {
        ControlItem item = new ControlItem();
        item.kind = kind;
        item.up = up;
        item.down = down;
        item.left = left;
        item.right = right;
        item.x = x;
        item.y = y;
        item.size = size;
        return item;
    }

    public static ControlItem touchpad(float x, float y, int size) {
        ControlItem item = new ControlItem();
        item.kind = Kind.TOUCHPAD;
        item.x = x;
        item.y = y;
        item.size = size;
        return item;
    }

    public static ControlItem mouse(int button, String label, float x, float y, int size) {
        ControlItem item = new ControlItem();
        item.kind = Kind.MOUSE;
        item.mouseButton = button;
        item.label = label;
        item.x = x;
        item.y = y;
        item.size = size;
        return item;
    }

    public ControlItem copy() {
        ControlItem item = new ControlItem();
        item.kind = kind;
        item.x = x;
        item.y = y;
        item.size = size;
        item.key = key;
        item.up = up;
        item.down = down;
        item.left = left;
        item.right = right;
        item.mouseButton = mouseButton;
        item.label = label;
        return item;
    }

    /** What the control shows on screen, and what the editor lists it as. */
    public String caption() {
        switch (kind) {
            case BUTTON:
                return label != null ? label : key.label();
            case MOUSE:
                return label != null ? label : "Click";
            case TOUCHPAD:
                return "Touchpad";
            default:
                return up.label() + left.label() + down.label() + right.label();
        }
    }

    JSONObject toJson() throws JSONException {
        JSONObject json = new JSONObject();
        json.put("kind", kind.name());
        json.put("x", x);
        json.put("y", y);
        json.put("size", size);
        json.put("mouseButton", mouseButton);

        if (key != null) {
            json.put("key", key.name());
        }

        if (up != null) {
            json.put("up", up.name());
            json.put("down", down.name());
            json.put("left", left.name());
            json.put("right", right.name());
        }

        if (label != null) {
            json.put("label", label);
        }

        return json;
    }

    static ControlItem fromJson(JSONObject json) {
        ControlItem item = new ControlItem();

        try {
            item.kind = Kind.valueOf(json.getString("kind"));
        } catch (Exception unknown) {
            return null;
        }

        item.x = (float) json.optDouble("x", 0.5);
        item.y = (float) json.optDouble("y", 0.5);
        item.size = json.optInt("size", 70);
        item.mouseButton = json.optInt("mouseButton", 0);
        item.key = VirtualKey.byName(json.optString("key", null), VirtualKey.SPACE);
        item.up = VirtualKey.byName(json.optString("up", null), VirtualKey.W);
        item.down = VirtualKey.byName(json.optString("down", null), VirtualKey.S);
        item.left = VirtualKey.byName(json.optString("left", null), VirtualKey.A);
        item.right = VirtualKey.byName(json.optString("right", null), VirtualKey.D);
        item.label = json.optString("label", null);

        return item;
    }
}
