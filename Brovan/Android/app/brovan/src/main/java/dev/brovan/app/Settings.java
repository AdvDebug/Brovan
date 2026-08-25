package dev.brovan.app;

import android.content.Context;
import android.content.SharedPreferences;

/** User-visible run options. */
final class Settings {

    static final String[] NETWORK_MODES = {"None", "Loopback", "Full"};

    private static final String FILE = "brovan";
    private static final String KEY_NETWORK = "network";
    private static final String KEY_DEVELOPER = "developer";
    private static final String KEY_FIT_WINDOW = "fit_window";
    private static final String KEY_CONTROLS = "controls";
    private static final String KEY_JIT_CACHE = "jit_cache";
    private static final String KEY_SUSTAINED = "sustained";
    private static final String KEY_SETUP_DISMISSED = "setup_dismissed";
    private static final String KEY_CONTROL_LAYOUT = "control_layout";
    private static final String KEY_POINTER = "pointer";
    private static final String KEY_DXVK_VERSION = "dxvk_version";
    private static final String KEY_POINTER_SPEED = "pointer_speed";

    private final SharedPreferences preferences;

    Settings(Context context) {
        preferences = context.getSharedPreferences(FILE, Context.MODE_PRIVATE);
    }

    int network() {
        return preferences.getInt(KEY_NETWORK, 1);
    }

    void setNetwork(int value) {
        preferences.edit().putInt(KEY_NETWORK, value).apply();
    }

    boolean developerMode() {
        return preferences.getBoolean(KEY_DEVELOPER, false);
    }

    void setDeveloperMode(boolean value) {
        preferences.edit().putBoolean(KEY_DEVELOPER, value).apply();
    }

    int controlScheme() {
        return preferences.getInt(KEY_CONTROLS, 0);
    }

    void setControlScheme(int value) {
        preferences.edit().putInt(KEY_CONTROLS, value).apply();
    }

    boolean fitWindow() {
        return preferences.getBoolean(KEY_FIT_WINDOW, true);
    }

    void setFitWindow(boolean value) {
        preferences.edit().putBoolean(KEY_FIT_WINDOW, value).apply();
    }

    boolean jitCache() {
        return preferences.getBoolean(KEY_JIT_CACHE, true);
    }

    void setJitCache(boolean value) {
        preferences.edit().putBoolean(KEY_JIT_CACHE, value).apply();
    }

    /** Trades peak clocks for a rate the device can hold once it is warm. */
    boolean sustainedPerformance() {
        return preferences.getBoolean(KEY_SUSTAINED, false);
    }

    void setSustainedPerformance(boolean value) {
        preferences.edit().putBoolean(KEY_SUSTAINED, value).apply();
    }

    /** The custom control arrangement, as written by the editor. Empty until the user saves one. */
    String controlLayout() {
        return preferences.getString(KEY_CONTROL_LAYOUT, "");
    }

    void setControlLayout(String json) {
        preferences.edit().putString(KEY_CONTROL_LAYOUT, json).apply();
    }

    int pointerMode() {
        return preferences.getInt(KEY_POINTER, 0);
    }

    void setPointerMode(int value) {
        preferences.edit().putInt(KEY_POINTER, value).apply();
    }

    /** Scales how far the pointer travels for a finger movement, across every touch mode. */
    float pointerSpeed() {
        return preferences.getFloat(KEY_POINTER_SPEED, 1f);
    }

    void setPointerSpeed(float value) {
        preferences.edit().putFloat(KEY_POINTER_SPEED, value).apply();
    }

    /** The DXVK release tag to download, or {@link Dxvk#LATEST} for whichever is newest at that moment. */
    String dxvkVersion() {
        return preferences.getString(KEY_DXVK_VERSION, Dxvk.LATEST);
    }

    void setDxvkVersion(String value) {
        preferences.edit().putString(KEY_DXVK_VERSION, value).apply();
    }

    /** Keeps the get-started screen from taking over the launcher once the user has chosen to leave it. */
    boolean setupDismissed() {
        return preferences.getBoolean(KEY_SETUP_DISMISSED, false);
    }

    void setSetupDismissed(boolean value) {
        preferences.edit().putBoolean(KEY_SETUP_DISMISSED, value).apply();
    }
}
