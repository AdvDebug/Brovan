package dev.brovan.app;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Properties;

final class ProgramSettings {

    private static final String MANIFEST = "program.properties";
    private static final String KEY_CONTROLS = "controls";
    private static final String KEY_POINTER = "pointer";
    private static final String KEY_POINTER_SPEED = "pointer_speed";

    private final File manifest;
    private final Properties properties = new Properties();
    private final Settings defaults;

    ProgramSettings(File directory, Settings defaults) {
        this.manifest = new File(directory, MANIFEST);
        this.defaults = defaults;

        try (InputStream stream = new FileInputStream(manifest)) {
            properties.load(stream);
        } catch (IOException failure) {
            // A program with no manifest yet answers with the global settings.
        }
    }

    int controlScheme() {
        return integer(KEY_CONTROLS, defaults.controlScheme());
    }

    void setControlScheme(int value) {
        write(KEY_CONTROLS, Integer.toString(value));
    }

    int pointerMode() {
        return integer(KEY_POINTER, defaults.pointerMode());
    }

    void setPointerMode(int value) {
        write(KEY_POINTER, Integer.toString(value));
    }

    float pointerSpeed() {
        String value = properties.getProperty(KEY_POINTER_SPEED);
        if (value == null) {
            return defaults.pointerSpeed();
        }

        try {
            return Float.parseFloat(value);
        } catch (NumberFormatException malformed) {
            return defaults.pointerSpeed();
        }
    }

    void setPointerSpeed(float value) {
        write(KEY_POINTER_SPEED, Float.toString(value));
    }

    private int integer(String key, int fallback) {
        String value = properties.getProperty(key);
        if (value == null) {
            return fallback;
        }

        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException malformed) {
            return fallback;
        }
    }

    private void write(String key, String value) {
        properties.setProperty(key, value);

        try (OutputStream stream = new FileOutputStream(manifest)) {
            properties.store(stream, null);
        } catch (IOException failure) {
            // The program still runs with the setting applied; only remembering it failed.
        }
    }
}
