package dev.brovan.app;

import android.content.SharedPreferences;
import android.graphics.Color;

final class Palette {

    enum Role {
        BACKGROUND(R.string.theme_background, 0xFF0D1117),
        SURFACE(R.string.theme_surface, 0xFF161C24),
        SURFACE_VARIANT(R.string.theme_surface_variant, 0xFF1E2733),
        OUTLINE(R.string.theme_outline, 0xFF2A3542),
        ACCENT(R.string.theme_accent, 0xFF7C9CF5),
        ON_ACCENT(R.string.theme_on_accent, 0xFF0B1020),
        TEXT_PRIMARY(R.string.theme_text_primary, 0xFFE6EDF3),
        TEXT_SECONDARY(R.string.theme_text_secondary, 0xFF95A1B2);

        final int labelId;
        final int fallback;

        Role(int labelId, int fallback) {
            this.labelId = labelId;
            this.fallback = fallback;
        }
    }

    enum Preset {
        MIDNIGHT(R.string.theme_preset_midnight,
                0x0D1117, 0x161C24, 0x1E2733, 0x2A3542, 0x7C9CF5, 0x0B1020, 0xE6EDF3, 0x95A1B2),
        SLATE(R.string.theme_preset_slate,
                0x0E1012, 0x16191C, 0x1F2327, 0x2D3238, 0xAEB9C7, 0x0E1012, 0xE9ECF0, 0x939BA6),
        EMBER(R.string.theme_preset_ember,
                0x141010, 0x1E1817, 0x2A2220, 0x3A2F2B, 0xFF8A4C, 0x1A0E06, 0xF5EAE3, 0xB49C90),
        FOREST(R.string.theme_preset_forest,
                0x0B120E, 0x141C17, 0x1D2721, 0x2A362E, 0x5BD68A, 0x06180D, 0xE4EFE8, 0x92A89A),
        ORCHID(R.string.theme_preset_orchid,
                0x120E16, 0x1B1621, 0x25202C, 0x342C3D, 0xC792EA, 0x150A1C, 0xEFE7F5, 0xA899B4),
        DAYLIGHT(R.string.theme_preset_daylight,
                0xF6F8FB, 0xFFFFFF, 0xEDF1F6, 0xD9E0E8, 0x3B6FE0, 0xFFFFFF, 0x121820, 0x5C6673);

        final int labelId;
        private final int[] colors;

        Preset(int labelId, int... colors) {
            this.labelId = labelId;
            this.colors = colors;
        }

        Palette palette() {
            Palette palette = new Palette();

            for (int i = 0; i < colors.length; i++) {
                palette.colors[i] = 0xFF000000 | colors[i];
            }

            return palette;
        }
    }

    private static final String KEY = "theme_";

    private final int[] colors = new int[Role.values().length];

    private Palette() {
    }

    static Palette defaults() {
        Palette palette = new Palette();
        Role[] roles = Role.values();

        for (int i = 0; i < roles.length; i++) {
            palette.colors[i] = roles[i].fallback;
        }

        return palette;
    }

    static Palette load(SharedPreferences preferences) {
        Palette palette = new Palette();
        Role[] roles = Role.values();

        for (int i = 0; i < roles.length; i++) {
            palette.colors[i] = preferences.getInt(KEY + roles[i].name(), roles[i].fallback);
        }

        return palette;
    }

    void save(SharedPreferences preferences) {
        SharedPreferences.Editor editor = preferences.edit();
        Role[] roles = Role.values();

        for (int i = 0; i < roles.length; i++) {
            editor.putInt(KEY + roles[i].name(), colors[i]);
        }

        editor.apply();
    }

    static void clear(SharedPreferences preferences) {
        SharedPreferences.Editor editor = preferences.edit();

        for (Role role : Role.values()) {
            editor.remove(KEY + role.name());
        }

        editor.apply();
    }

    Palette copy() {
        Palette palette = new Palette();
        System.arraycopy(colors, 0, palette.colors, 0, colors.length);
        return palette;
    }

    int get(Role role) {
        return colors[role.ordinal()];
    }

    void set(Role role, int color) {
        colors[role.ordinal()] = 0xFF000000 | color;
    }

    boolean sameAs(Palette other) {
        for (int i = 0; i < colors.length; i++) {
            if (colors[i] != other.colors[i]) {
                return false;
            }
        }

        return true;
    }

    int remap(int color, Palette into) {
        int rgb = color & 0xFFFFFF;

        for (int i = 0; i < colors.length; i++) {
            if ((colors[i] & 0xFFFFFF) == rgb) {
                return (color & 0xFF000000) | (into.colors[i] & 0xFFFFFF);
            }
        }

        return color;
    }

    boolean isLight() {
        int background = get(Role.BACKGROUND);
        double luminance = 0.2126 * Color.red(background)
                + 0.7152 * Color.green(background)
                + 0.0722 * Color.blue(background);

        return luminance > 140;
    }
}
