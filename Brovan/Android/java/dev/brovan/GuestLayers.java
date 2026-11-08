package dev.brovan;

import android.annotation.TargetApi;
import android.graphics.PixelFormat;
import android.graphics.Rect;
import android.os.Build;
import android.util.SparseArray;
import android.view.Surface;
import android.view.SurfaceControl;

/** The emulator's GUI thread creates, places and releases layers, and the UI thread changes their parent. */
@TargetApi(29)
final class GuestLayers {
    private static final Object LOCK = new Object();
    private static final SparseArray<Layer> LAYERS = new SparseArray<>();
    private static SurfaceControl parent;

    private static final class Layer {
        final SurfaceControl control;
        final Surface surface;

        Layer(SurfaceControl control, Surface surface) {
            this.control = control;
            this.surface = surface;
        }
    }

    private GuestLayers() {
    }

    static boolean available() {
        return Build.VERSION.SDK_INT >= 29;
    }

    /** A layer keeps its Surface while it has no parent, so a guest swapchain on it survives. */
    static void setParent(SurfaceControl next) {
        synchronized (LOCK) {
            parent = next;
            if (LAYERS.size() == 0) {
                return;
            }

            SurfaceControl.Transaction transaction = new SurfaceControl.Transaction();
            for (int i = 0; i < LAYERS.size(); i++) {
                transaction.reparent(LAYERS.valueAt(i).control, next);
            }
            transaction.apply();
        }
    }

    static Surface create(int id) {
        synchronized (LOCK) {
            SurfaceControl control = new SurfaceControl.Builder()
                    .setName("brovan-window-" + id)
                    .setBufferSize(1, 1)
                    .setFormat(PixelFormat.RGBA_8888)
                    .setOpaque(false)
                    .setParent(parent)
                    .build();
            Surface surface = new Surface(control);
            LAYERS.put(id, new Layer(control, surface));
            return surface;
        }
    }

    @SuppressWarnings("deprecation")
    static void apply(int id, int x, int y, int width, int height, int z, boolean shown, float alpha) {
        synchronized (LOCK) {
            Layer layer = LAYERS.get(id);
            if (layer == null) {
                return;
            }

            int w = Math.max(width, 1);
            int h = Math.max(height, 1);
            new SurfaceControl.Transaction()
                    .setBufferSize(layer.control, w, h)
                    .setGeometry(layer.control, null, new Rect(x, y, x + w, y + h), Surface.ROTATION_0)
                    .setLayer(layer.control, z)
                    .setVisibility(layer.control, shown)
                    .setAlpha(layer.control, alpha)
                    .apply();
        }
    }

    static void release(int id) {
        synchronized (LOCK) {
            Layer layer = LAYERS.get(id);
            if (layer == null) {
                return;
            }

            LAYERS.remove(id);
            new SurfaceControl.Transaction().reparent(layer.control, null).apply();
            layer.surface.release();
            layer.control.release();
        }
    }
}
