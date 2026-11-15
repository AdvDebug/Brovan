package dev.brovan.input;

import org.json.JSONException;
import org.json.JSONObject;

public final class ControlItem {

    /** The screen the defaults are laid out on and that stored fractions refer to, in dp. */
    private static final float REFERENCE_WIDTH_DP = 915f;
    private static final float REFERENCE_HEIGHT_DP = 412f;

    public static final int DEFAULT_COLOR = 0xFFFFFF;

    /** No fill was chosen, so the control draws in the app accent and follows the theme. */
    public static final int ACCENT_FILL = -1;

    /** A switcher steps along the digit row, so ten is as many slots as one can bind. */
    public static final int MAX_SLOTS = 10;

    public enum Kind {
        BUTTON,
        JOYSTICK,
        DPAD,
        TOUCHPAD,
        MOUSE,
        SWITCHER
    }

    public Kind kind;
    public boolean fromEnd;
    public float offsetX;
    public boolean fromBottom;
    public float offsetY;
    public int size;
    public VirtualKey key;
    public VirtualKey up;
    public VirtualKey down;
    public VirtualKey left;
    public VirtualKey right;
    public int mouseButton;
    public int slots;
    public boolean horizontal;
    public String label;
    public int fillColor = ACCENT_FILL;
    public int strokeColor = DEFAULT_COLOR;
    public int labelColor = DEFAULT_COLOR;
    public float opacity = 1f;

    public int fill(int accent) {
        return fillColor == ACCENT_FILL ? accent & 0xFFFFFF : fillColor;
    }

    public static int shade(int rgb, int alpha, float opacity) {
        return (Math.round(alpha * opacity) << 24) | (rgb & 0xFFFFFF);
    }

    public ControlItem at(boolean fromEnd, float offsetX, boolean fromBottom, float offsetY) {
        this.fromEnd = fromEnd;
        this.offsetX = offsetX;
        this.fromBottom = fromBottom;
        this.offsetY = offsetY;
        return this;
    }

    /** Measures from the nearer side, and from the bottom below the top third, so a thumb cluster keeps its spacing. */
    public ControlItem anchorAt(float centreX, float centreY, float widthDp, float heightDp) {
        boolean end = centreX > widthDp / 2f;
        boolean bottom = centreY > heightDp / 3f;
        return at(end, end ? widthDp - centreX : centreX, bottom, bottom ? heightDp - centreY : centreY);
    }

    public float centreX(float widthDp) {
        return fromEnd ? widthDp - offsetX : offsetX;
    }

    public float centreY(float heightDp) {
        return fromBottom ? heightDp - offsetY : offsetY;
    }

    public static ControlItem button(VirtualKey key, int size) {
        ControlItem item = new ControlItem();
        item.kind = Kind.BUTTON;
        item.key = key;
        item.size = size;
        return item;
    }

    public static ControlItem stick(Kind kind, VirtualKey up, VirtualKey down, VirtualKey left, VirtualKey right,
                                    int size) {
        ControlItem item = new ControlItem();
        item.kind = kind;
        item.up = up;
        item.down = down;
        item.left = left;
        item.right = right;
        item.size = size;
        return item;
    }

    public static ControlItem touchpad(int size) {
        ControlItem item = new ControlItem();
        item.kind = Kind.TOUCHPAD;
        item.size = size;
        return item;
    }

    public static ControlItem mouse(int button, String label, int size) {
        ControlItem item = new ControlItem();
        item.kind = Kind.MOUSE;
        item.mouseButton = button;
        item.label = label;
        item.size = size;
        return item;
    }

    /** No slots leaves the control with nothing of its own to select, which is what turns the wheel instead. */
    public static ControlItem switcher(int slots, boolean horizontal, int size) {
        ControlItem item = new ControlItem();
        item.kind = Kind.SWITCHER;
        item.slots = slots;
        item.horizontal = horizontal;
        item.size = size;
        return item;
    }

    public ControlItem copy() {
        ControlItem item = new ControlItem();
        item.kind = kind;
        item.at(fromEnd, offsetX, fromBottom, offsetY);
        item.size = size;
        item.key = key;
        item.up = up;
        item.down = down;
        item.left = left;
        item.right = right;
        item.mouseButton = mouseButton;
        item.slots = slots;
        item.horizontal = horizontal;
        item.label = label;
        item.fillColor = fillColor;
        item.strokeColor = strokeColor;
        item.labelColor = labelColor;
        item.opacity = opacity;
        return item;
    }

    public void copyStyleTo(ControlItem other) {
        other.fillColor = fillColor;
        other.strokeColor = strokeColor;
        other.labelColor = labelColor;
        other.opacity = opacity;
    }

    /** What the control shows on screen, and what the editor lists it as. */
    public String caption() {
        switch (kind) {
            case BUTTON:
                return label != null ? label : key.shortLabel();
            case MOUSE:
                return label != null ? label : "Click";
            case TOUCHPAD:
                return "Touchpad";
            case SWITCHER:
                return slots > 0 ? "Switcher" : "Wheel";
            default:
                return up.shortLabel() + left.shortLabel() + down.shortLabel() + right.shortLabel();
        }
    }

    JSONObject toJson() throws JSONException {
        JSONObject json = new JSONObject();
        json.put("kind", kind.name());
        json.put("end", fromEnd);
        json.put("dx", offsetX);
        json.put("bottom", fromBottom);
        json.put("dy", offsetY);
        // Older builds read only these fractions and place them unclamped.
        json.put("x", fraction(centreX(REFERENCE_WIDTH_DP) / REFERENCE_WIDTH_DP));
        json.put("y", fraction(centreY(REFERENCE_HEIGHT_DP) / REFERENCE_HEIGHT_DP));
        json.put("size", size);
        json.put("mouseButton", mouseButton);
        json.put("slots", slots);
        json.put("horizontal", horizontal);
        if (fillColor != ACCENT_FILL) {
            json.put("colour", fillColor);
            json.put("fill", fillColor);
        }
        json.put("stroke", strokeColor);
        json.put("text", labelColor);
        json.put("opacity", opacity);

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

        if (json.has("dx") && json.has("dy")) {
            item.at(json.optBoolean("end", false), (float) json.optDouble("dx", 0.0),
                    json.optBoolean("bottom", false), (float) json.optDouble("dy", 0.0));
        } else {
            // "x" and "y" alone are fractions of the screen; they are read on the reference screen.
            item.anchorAt((float) json.optDouble("x", 0.5) * REFERENCE_WIDTH_DP,
                    (float) json.optDouble("y", 0.5) * REFERENCE_HEIGHT_DP, REFERENCE_WIDTH_DP, REFERENCE_HEIGHT_DP);
        }
        item.size = json.optInt("size", 70);
        item.mouseButton = json.optInt("mouseButton", 0);
        item.slots = Math.max(0, Math.min(MAX_SLOTS, json.optInt("slots", 0)));
        item.horizontal = json.optBoolean("horizontal", false);
        item.key = VirtualKey.byName(json.optString("key", null), VirtualKey.SPACE);
        item.up = VirtualKey.byName(json.optString("up", null), VirtualKey.W);
        item.down = VirtualKey.byName(json.optString("down", null), VirtualKey.S);
        item.left = VirtualKey.byName(json.optString("left", null), VirtualKey.A);
        item.right = VirtualKey.byName(json.optString("right", null), VirtualKey.D);
        // A button shows the key it sends. A label stored for a button is an older default.
        item.label = item.kind == Kind.BUTTON ? null : json.optString("label", null);
        if (json.has("colour")) {
            item.fillColor = json.optInt("colour", ACCENT_FILL);
        } else {
            // A layout with only "fill" stores a fill nobody chose as white.
            int fill = json.optInt("fill", ACCENT_FILL);
            item.fillColor = fill == DEFAULT_COLOR ? ACCENT_FILL : fill;
        }
        item.strokeColor = json.optInt("stroke", DEFAULT_COLOR);
        item.labelColor = json.optInt("text", DEFAULT_COLOR);
        item.opacity = clampOpacity((float) json.optDouble("opacity", 1.0));

        return item;
    }

    private static float fraction(float value) {
        return Math.max(0.02f, Math.min(0.98f, value));
    }

    private static float clampOpacity(float value) {
        return Math.max(0.2f, Math.min(1f, value));
    }
}
