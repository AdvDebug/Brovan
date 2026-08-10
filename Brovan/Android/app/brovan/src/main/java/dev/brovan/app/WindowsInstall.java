package dev.brovan.app;

import android.app.Activity;
import android.content.Context;
import android.net.Uri;
import android.os.ParcelFileDescriptor;

import java.io.File;
import java.util.concurrent.Executor;

import dev.brovan.BrovanNative;

/** The Microsoft downloads, shared by the setup wizard and the Windows files screen. */
final class WindowsInstall {

    interface Listener {
        void onProgress(long filesDone, long filesTotal, long bytesDone, long bytesTotal);

        void onFinished(int status);
    }

    private interface Step {
        int run();
    }

    private WindowsInstall() {
    }

    static boolean filesPresent(Context context) {
        return new File(context.getFilesDir(), "WindowsLibs").isDirectory();
    }

    static boolean runtimesPresent(Context context) {
        return new File(context.getFilesDir(), "WindowsLibs/msvcp140.dll").exists();
    }

    static void windows(Activity activity, Executor worker, String url, Uri iso, Listener listener) {
        run(activity, worker, listener, () -> {
            ParcelFileDescriptor descriptor = null;

            try {
                int handle = -1;

                if (iso != null) {
                    descriptor = activity.getContentResolver().openFileDescriptor(iso, "r");
                    handle = descriptor == null ? -1 : descriptor.getFd();
                }

                return BrovanNative.installWindows(handle >= 0 ? null : url, handle, true, 1);
            } catch (Exception failure) {
                return BrovanNative.STATUS_FAILED;
            } finally {
                close(descriptor);
            }
        });
    }

    static void runtimes(Activity activity, Executor worker, Listener listener) {
        run(activity, worker, listener, () -> BrovanNative.installRuntimes(true));
    }

    private static void run(Activity activity, Executor worker, Listener listener, Step step) {
        BrovanNative.setInstallListener((filesDone, filesTotal, bytesDone, bytesTotal) ->
                activity.runOnUiThread(() -> listener.onProgress(filesDone, filesTotal, bytesDone, bytesTotal)));

        worker.execute(() -> {
            int status = BrovanNative.init(activity.getFilesDir().getAbsolutePath());

            if (status == BrovanNative.STATUS_OK || status == BrovanNative.STATUS_MISSING_WINDOWS_LIBS
                    || status == BrovanNative.STATUS_MISSING_REGISTRY) {
                status = step.run();
            }

            int outcome = status;
            activity.runOnUiThread(() -> {
                BrovanNative.setInstallListener(null);
                listener.onFinished(outcome);
            });
        });
    }

    private static void close(ParcelFileDescriptor descriptor) {
        if (descriptor == null) {
            return;
        }

        try {
            descriptor.close();
        } catch (java.io.IOException ignored) {
        }
    }
}
