package dev.brovan;

import android.view.Surface;

import java.util.ArrayList;
import java.util.List;

/**
 * Thin binding over the emulator's exported C ABI. Every method is safe to call from any thread except
 * where noted; the emulator runs the guest on its own threads and never borrows the caller's.
 */
public final class BrovanNative {

    public static final int STATUS_OK = 0;
    public static final int STATUS_NOT_INITIALIZED = -1;
    public static final int STATUS_ALREADY_RUNNING = -2;
    public static final int STATUS_INVALID_ARGUMENT = -3;
    public static final int STATUS_MISSING_WINDOWS_LIBS = -4;
    public static final int STATUS_MISSING_REGISTRY = -5;
    public static final int STATUS_APISETMAP_FAILED = -6;
    public static final int STATUS_BINARY_NOT_FOUND = -7;
    public static final int STATUS_FAILED = -8;

    public static final int BACKEND_UNICORN = 0;
    public static final int BACKEND_KVM = 1;
    public static final int BACKEND_WHP = 2;

    public static final int NETWORK_NONE = 0;
    public static final int NETWORK_LOOPBACK = 1;
    public static final int NETWORK_FULL = 2;

    public static final int POINTER_MOVE = 0;
    public static final int POINTER_DOWN = 1;
    public static final int POINTER_UP = 2;

    public static final int BUTTON_LEFT = 0;
    public static final int BUTTON_MIDDLE = 1;
    public static final int BUTTON_RIGHT = 2;

    public static final int MK_LBUTTON = 0x0001;
    public static final int MK_RBUTTON = 0x0002;
    public static final int MK_SHIFT = 0x0004;
    public static final int MK_CONTROL = 0x0008;
    public static final int MK_MBUTTON = 0x0010;

    public interface Listener {
        void onLog(String line);

        void onExit(int reason);
    }

    private static volatile Listener listener;

    static {
        // .NET's crypto shim dlopens libssl.so, and Android provides none. Loading our bundled pair up front
        // registers them under their sonames so the runtime's own dlopen resolves to these.
        try {
            System.loadLibrary("crypto");
            System.loadLibrary("ssl");
        } catch (UnsatisfiedLinkError ignored) {
            // Left to the runtime to report if it actually needs them.
        }

        System.loadLibrary("Brovan");
        System.loadLibrary("brovan_jni");
    }

    private BrovanNative() {
    }

    public static void setListener(Listener value) {
        listener = value;
    }

    /**
     * Must be the first call into the emulator. baseDirectory becomes the root the emulator resolves
     * WindowsLibs, WinReg, apisetmap.bin, VirtualFS, sessions and logs against, so it has to be a writable
     * app-private directory (getFilesDir()).
     */
    public static int init(String baseDirectory) {
        return nativeInit(baseDirectory);
    }

    /** Call from surfaceCreated / surfaceChanged. */
    public static void setSurface(Surface surface, int densityDpi) {
        nativeSetSurface(surface, densityDpi);
    }

    /** Call from surfaceDestroyed. */
    public static void clearSurface() {
        nativeClearSurface();
    }

    public static int start(String binaryPath, String guestCommandLine, String workingDirectory,
                            String debuggerCommands, int backend, int networkMode) {
        return nativeStart(binaryPath, guestCommandLine, workingDirectory, debuggerCommands, backend, networkMode);
    }

    /** Enables the emulator's own trace into logcat. Must be called before {@link #start}. */
    public static void setVerbose(boolean enabled) {
        nativeSetVerbose(enabled ? 1 : 0);
    }

    /** Feeds one line to the emulator's debugger prompt. Verbose mode only. */
    public static void sendCommand(String command) {
        nativeSendCommand(command);
    }

    public static boolean isRunning() {
        return nativeIsRunning() != 0;
    }

    /** Posts WM_CLOSE to the guest. Calling it a second time terminates the process. */
    public static void requestClose() {
        nativeRequestClose();
    }

    public static void injectPointer(int action, int button, int x, int y, int buttons) {
        nativeInjectPointer(action, button, x, y, buttons);
    }

    public static void injectScroll(int delta, int x, int y, int buttons) {
        nativeInjectScroll(delta, x, y, buttons);
    }

    public static void injectKey(boolean down, int virtualKey, int scanCode) {
        nativeInjectKey(down ? 1 : 0, virtualKey, scanCode);
    }

    public static void injectFocus(boolean focused) {
        nativeInjectFocus(focused ? 1 : 0);
    }

    /** Marks the guest window dirty so it repaints. */
    public static void requestRepaint() {
        nativeRequestRepaint();
    }

    /** One top-level guest window per element. */
    public static List<GuestWindow> listWindows() {
        List<GuestWindow> windows = new ArrayList<>();
        String raw = nativeListWindows();
        if (raw == null || raw.isEmpty()) {
            return windows;
        }

        for (String line : raw.split("\n")) {
            if (line.isEmpty()) {
                continue;
            }

            String[] parts = line.split("\\|", 5);
            if (parts.length < 5) {
                continue;
            }

            try {
                windows.add(new GuestWindow(
                        Long.parseUnsignedLong(parts[0]),
                        Integer.parseInt(parts[1]),
                        Integer.parseInt(parts[2]),
                        "1".equals(parts[3]),
                        parts[4]));
            } catch (NumberFormatException ignored) {
                // A torn snapshot is not worth failing the whole list for.
            }
        }

        return windows;
    }

    /** Chooses which guest window is presented on the Surface. */
    public static void selectWindow(long hwnd) {
        nativeSelectWindow(hwnd);
    }

    public static String getWindowTitle() {
        return nativeGetWindowTitle();
    }

    @SuppressWarnings("unused")
    private static void onNativeLog(String line) {
        Listener current = listener;
        if (current != null) {
            current.onLog(line);
        }
    }

    @SuppressWarnings("unused")
    private static void onNativeExit(int reason) {
        Listener current = listener;
        if (current != null) {
            current.onExit(reason);
        }
    }

    private static native int nativeInit(String baseDirectory);

    private static native void nativeSetSurface(Surface surface, int densityDpi);

    private static native void nativeClearSurface();

    private static native int nativeStart(String binaryPath, String guestCommandLine, String workingDirectory,
                                          String debuggerCommands, int backend, int networkMode);

    private static native void nativeSetVerbose(int enabled);

    private static native void nativeSendCommand(String command);

    private static native int nativeIsRunning();

    private static native void nativeRequestClose();

    private static native void nativeInjectPointer(int action, int button, int x, int y, int buttons);

    private static native void nativeInjectScroll(int delta, int x, int y, int buttons);

    private static native void nativeInjectKey(int down, int virtualKey, int scanCode);

    private static native void nativeInjectFocus(int focused);

    private static native void nativeRequestRepaint();

    private static native String nativeListWindows();

    private static native void nativeSelectWindow(long hwnd);

    private static native String nativeGetWindowTitle();
}
