package dev.brovan.app;

import android.content.Context;
import android.content.SharedPreferences;

/** User-visible run options. */
final class Settings {

    static final String[] BACKENDS = {"Unicorn", "KVM", "WHP"};
    static final String[] NETWORK_MODES = {"None", "Loopback", "Full"};

    private static final String FILE = "brovan";
    private static final String KEY_BACKEND = "backend";
    private static final String KEY_NETWORK = "network";
    private static final String KEY_DEVELOPER = "developer";
    private static final String KEY_FIT_WINDOW = "fit_window";
    private static final String KEY_CONTROLS = "controls";

    private final SharedPreferences preferences;

    Settings(Context context) {
        preferences = context.getSharedPreferences(FILE, Context.MODE_PRIVATE);
    }

    int backend() {
        return preferences.getInt(KEY_BACKEND, 0);
    }

    void setBackend(int value) {
        preferences.edit().putInt(KEY_BACKEND, value).apply();
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
}
