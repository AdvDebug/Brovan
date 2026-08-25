package dev.brovan;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Typeface;
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

    /** Progress of {@link #installWindows}. Reported from a worker thread, not the main thread. */
    public interface InstallListener {
        void onInstallProgress(long filesDone, long filesTotal, long bytesDone, long bytesTotal);
    }

    private static final String[] NO_RECORDS = new String[0];

    /** The cell of the default GDI font, which is what the emulator falls back to when text cannot be measured. */
    private static final float TEXT_SIZE_PIXELS = 16f;

    /** Slack around a run so antialiased edges and overhang are not clipped. */
    private static final int TEXT_PADDING = 2;

    private static final int TEXT_MAXIMUM_WIDTH = 4096;
    private static final int TEXT_FIELD_COUNT = 8;

    private static final Object TEXT_LOCK = new Object();
    private static Paint textPaint;
    private static Bitmap textBitmap;
    private static Canvas textCanvas;

    private static volatile Listener listener;
    private static volatile InstallListener installListener;

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

    public static void setInstallListener(InstallListener value) {
        installListener = value;
    }

    /**
     * Must be the first call into the emulator. baseDirectory becomes the root the emulator resolves
     * WindowsLibs, WinReg, apisetmap.bin, VirtualFS, sessions and logs against, so it has to be a writable
     * app-private directory (getFilesDir()).
     */
    public static int init(String baseDirectory) {
        return nativeInit(baseDirectory);
    }

    public static int installWindows(String media, int mediaDescriptor, boolean acceptLicense, int imageIndex) {
        return nativeInstallWindows(media, mediaDescriptor, acceptLicense ? 1 : 0, imageIndex);
    }

    /** Downloads only the Visual C++ runtimes, which {@link #installWindows} also does. */
    public static int installRuntimes(boolean acceptLicense) {
        return nativeInstallRuntimes(acceptLicense ? 1 : 0);
    }

    /**
     * Downloads a DXVK release from GitHub and installs its libraries into the emulated System32 and
     * SysWOW64, where they take the place of Direct3D. An empty version takes the newest release.
     */
    public static int installDxvk(String version) {
        return nativeInstallDxvk(version == null ? "" : version);
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
                            String debuggerCommands, int networkMode) {
        return nativeStart(binaryPath, guestCommandLine, workingDirectory, debuggerCommands, networkMode);
    }

    /** Enables the emulator's own trace into logcat. Must be called before {@link #start}. */
    public static void setVerbose(boolean enabled) {
        nativeSetVerbose(enabled ? 1 : 0);
    }

    /** Reuses translated guest code between runs. Must be called before {@link #start}. */
    public static void setJitCache(boolean enabled) {
        nativeSetJitCache(enabled ? 1 : 0);
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

    /**
     * Terminates every guest thread and unwinds the emulator through its normal shutdown, which saves the
     * JIT cache. For a guest that ignored {@link #requestClose}; {@link Listener#onExit} reports completion.
     */
    public static void stop() {
        nativeStop();
    }

    public static void injectPointer(int action, int button, int x, int y, int buttons) {
        nativeInjectPointer(action, button, x, y, buttons);
    }

    /** Reports how far the pointing device moved, which a guest reading raw input uses instead of the cursor. */
    public static void injectMouseTravel(int deltaX, int deltaY) {
        if (deltaX != 0 || deltaY != 0) {
            nativeInjectMouseTravel(deltaX, deltaY);
        }
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

    public static void debugPause() {
        nativeDebugPause();
    }

    public static String[] debugQuery(String request) {
        String raw = nativeDebugQuery(request);
        if (raw == null || raw.isEmpty()) {
            return NO_RECORDS;
        }

        return raw.split("\n");
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

    @SuppressWarnings("unused")
    private static void onNativeInstallProgress(long filesDone, long filesTotal, long bytesDone, long bytesTotal) {
        InstallListener current = installListener;
        if (current != null) {
            current.onInstallProgress(filesDone, filesTotal, bytesDone, bytesTotal);
        }
    }

    /**
     * Font metrics and the size of the bitmap {@link #onNativeRasterizeText} would produce, as
     * width, height, ascent, descent, leading, average width, maximum width, padding. A null text asks for
     * the font metrics alone. Called from emulator threads.
     */
    @SuppressWarnings("unused")
    private static int[] onNativeTextMetrics(String text) {
        int[] fields = new int[TEXT_FIELD_COUNT];

        synchronized (TEXT_LOCK) {
            Paint paint = textPaint();
            Paint.FontMetricsInt metrics = paint.getFontMetricsInt();
            int ascent = -metrics.ascent;

            if (text != null && !text.isEmpty()) {
                fields[0] = advanceOf(paint, text) + (TEXT_PADDING * 2);
                fields[1] = ascent + metrics.descent + (TEXT_PADDING * 2);
            }

            fields[2] = ascent;
            fields[3] = metrics.descent;
            fields[4] = metrics.leading;
            fields[5] = Math.max(1, Math.round(paint.measureText("x")));
            fields[6] = Math.max(1, Math.round(paint.measureText("W")));
            fields[7] = TEXT_PADDING;
        }

        return fields;
    }

    /**
     * Draws the run into a reused ALPHA_8 bitmap, its left edge and baseline placed the way
     * {@link #onNativeTextMetrics} describes.
     */
    @SuppressWarnings("unused")
    private static Bitmap onNativeRasterizeText(String text) {
        if (text == null || text.isEmpty()) {
            return null;
        }

        synchronized (TEXT_LOCK) {
            Paint paint = textPaint();
            Paint.FontMetricsInt metrics = paint.getFontMetricsInt();
            int ascent = -metrics.ascent;
            int width = advanceOf(paint, text) + (TEXT_PADDING * 2);
            int height = ascent + metrics.descent + (TEXT_PADDING * 2);

            if (width <= 0 || height <= 0) {
                return null;
            }

            if (textBitmap == null || textBitmap.getWidth() < width || textBitmap.getHeight() < height) {
                textBitmap = Bitmap.createBitmap(Math.max(width, textBitmap == null ? 0 : textBitmap.getWidth()),
                                                 Math.max(height, textBitmap == null ? 0 : textBitmap.getHeight()),
                                                 Bitmap.Config.ALPHA_8);
                textCanvas = new Canvas(textBitmap);
            }

            textBitmap.eraseColor(Color.TRANSPARENT);
            textCanvas.drawText(text, TEXT_PADDING, TEXT_PADDING + ascent, paint);
            return textBitmap;
        }
    }

    private static int advanceOf(Paint paint, String text) {
        return Math.min((int) Math.ceil(paint.measureText(text)), TEXT_MAXIMUM_WIDTH);
    }

    private static Paint textPaint() {
        if (textPaint == null) {
            textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
            textPaint.setTypeface(Typeface.DEFAULT);
            textPaint.setTextSize(TEXT_SIZE_PIXELS);
            textPaint.setColor(Color.BLACK);
        }

        return textPaint;
    }

    private static native int nativeInit(String baseDirectory);

    private static native int nativeInstallWindows(String media, int mediaDescriptor, int acceptLicense,
                                                   int imageIndex);

    private static native int nativeInstallRuntimes(int acceptLicense);

    private static native int nativeInstallDxvk(String version);

    private static native void nativeSetSurface(Surface surface, int densityDpi);

    private static native void nativeClearSurface();

    private static native int nativeStart(String binaryPath, String guestCommandLine, String workingDirectory,
                                          String debuggerCommands, int networkMode);

    private static native void nativeSetVerbose(int enabled);

    private static native void nativeSetJitCache(int enabled);

    private static native void nativeSendCommand(String command);

    private static native int nativeIsRunning();

    private static native void nativeRequestClose();

    private static native void nativeStop();

    private static native void nativeInjectPointer(int action, int button, int x, int y, int buttons);

    private static native void nativeInjectMouseTravel(int deltaX, int deltaY);

    private static native void nativeInjectScroll(int delta, int x, int y, int buttons);

    private static native void nativeInjectKey(int down, int virtualKey, int scanCode);

    private static native void nativeInjectFocus(int focused);

    private static native void nativeRequestRepaint();

    private static native String nativeListWindows();

    private static native void nativeSelectWindow(long hwnd);

    private static native String nativeGetWindowTitle();

    private static native void nativeDebugPause();

    private static native String nativeDebugQuery(String request);
}
