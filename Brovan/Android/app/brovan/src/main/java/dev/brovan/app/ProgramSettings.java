package dev.brovan.app;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.Collections;
import java.util.Locale;
import java.util.Properties;

import dev.brovan.BrovanSurfaceView;
import dev.brovan.input.ControlOverlay;

final class ProgramSettings {

    static final String EXTRA_PROFILE_ID = "program_id";

    static final String[] OVERRIDE_KEYS = {
            "controls", "pointer", "pointer_speed", "layout", "network", "jit_cache",
            "relax_vulkan", "low_memory", "render_scale", "sustained", "developer"
    };

    private final Library library;
    private final String id;
    private final Properties values;
    private final Settings defaults;

    ProgramSettings(Library library, Program program, Settings defaults) {
        this.library = library;
        this.id = program.id();
        this.values = program.values();
        this.defaults = defaults;
    }

    int controlScheme() {
        return integer("controls", defaults.controlScheme(), ControlOverlay.Scheme.values().length);
    }

    void setControlScheme(int value) throws IOException {
        write("controls", Integer.toString(value));
    }

    int pointerMode() {
        return integer("pointer", defaults.pointerMode(), BrovanSurfaceView.PointerMode.values().length);
    }

    void setPointerMode(int value) throws IOException {
        write("pointer", Integer.toString(value));
    }

    // Widget.Brovan.SpeedSlider holds the same range.
    private static final float SPEED_MIN = 0.4f;
    private static final float SPEED_MAX = 3f;

    private static float clampSpeed(float value) {
        return Math.max(SPEED_MIN, Math.min(value, SPEED_MAX));
    }

    // The Material slider throws when its value is not on one of its steps.
    static float snapSpeed(float value) {
        return Math.round(clampSpeed(value) * 10f) / 10f;
    }

    static String formatSpeed(float value) {
        return String.format(Locale.US, "%.1fx", value);
    }

    float pointerSpeed() {
        float storedDefault = defaults.pointerSpeed();
        float fallback = Float.isFinite(storedDefault) ? clampSpeed(storedDefault) : 1f;
        try {
            float value = Float.parseFloat(values.getProperty("pointer_speed", Float.toString(fallback)));
            return Float.isFinite(value) ? clampSpeed(value) : fallback;
        } catch (NumberFormatException malformed) {
            return fallback;
        }
    }

    void setPointerSpeed(float value) throws IOException {
        write("pointer_speed", Float.toString(value));
    }

    String controlLayout() { return values.getProperty("layout", defaults.controlLayout()); }
    int network() { return integer("network", defaults.network(), Settings.NETWORK_MODE_COUNT); }
    int renderScale() { return integer("render_scale", defaults.renderScale(), Settings.RENDER_SCALES.length); }
    int lowMemory() { return integer("low_memory", defaults.lowMemory(), Settings.LOW_MEMORY_LEVELS.length); }
    boolean jitCache() { return bool("jit_cache", defaults.jitCache()); }
    boolean relaxVulkan() { return bool("relax_vulkan", defaults.relaxVulkan()); }
    boolean sustainedPerformance() { return bool("sustained", defaults.sustainedPerformance()); }
    boolean developerMode() { return bool("developer", defaults.developerMode()); }

    String emulatorSettings() {
        JSONObject result = new JSONObject();
        try {
            result.put("net.mode", new String[]{"none", "loopback", "full"}[network()]);
            result.put("jit.cache", jitCache());
            result.put("graphics.relax-vulkan", relaxVulkan());
            result.put("graphics.render-scale", Math.round(Settings.RENDER_SCALES[renderScale()] * 100f) / 100.0);
            result.put("platform.low-memory", Settings.LOW_MEMORY_LEVELS[lowMemory()]);
            result.put("log.silent", !developerMode());
        } catch (JSONException failure) {
            throw new IllegalStateException("Could not build launch settings.", failure);
        }
        return result.toString();
    }

    private boolean bool(String key, boolean fallback) {
        String value = values.getProperty(key);
        return "true".equals(value) ? true : "false".equals(value) ? false : fallback;
    }

    private int integer(String key, int fallback, int count) {
        int value = fallback;
        try {
            value = Integer.parseInt(values.getProperty(key, Integer.toString(fallback)));
        } catch (NumberFormatException malformed) {
            value = fallback;
        }
        if (value < 0 || value >= count) {
            value = fallback;
        }
        return value < 0 || value >= count ? 0 : value;
    }

    private void write(String key, String value) throws IOException {
        library.update(id, Collections.singletonMap(key, value));
        values.setProperty(key, value);
    }
}
