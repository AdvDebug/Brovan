package dev.brovan.app;

import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Copies the guest-side files bundled in the APK into the emulated Windows filesystem.
 *
 * <p>The Vulkan shim is a Windows PE, so it cannot live in jniLibs like the host libraries. It is
 * generated from vk.xml together with the managed marshalling layer, which means it only matches
 * the build it shipped with and has to be refreshed whenever the app is updated.
 */
final class GuestAssets {

    private static final String TAG = "Brovan";
    private static final String SOURCE = "virtualfs";
    private static final String STAMP = "virtualfs-assets.stamp";

    private GuestAssets() {
    }

    static void deploy(Context context) {
        File files = context.getFilesDir();
        File stamp = new File(files, STAMP);
        long updated = updateTime(context);

        if (stamp.exists() && stamp.lastModified() >= updated) {
            return;
        }

        File system32 = new File(files, "VirtualFS/C/Windows/System32");
        File sysWow64 = new File(files, "VirtualFS/C/Windows/SysWOW64");

        try {
            copyDirectory(context, SOURCE + "/System32", system32);
            copyDirectory(context, SOURCE + "/SysWOW64", sysWow64);

            if (!stamp.exists() && !stamp.createNewFile()) {
                return;
            }
            stamp.setLastModified(updated);
        } catch (IOException error) {
            Log.e(TAG, "Could not deploy the bundled guest files: " + error.getMessage());
        }
    }

    private static long updateTime(Context context) {
        try {
            return context.getPackageManager()
                    .getPackageInfo(context.getPackageName(), 0)
                    .lastUpdateTime;
        } catch (PackageManager.NameNotFoundException error) {
            return System.currentTimeMillis();
        }
    }

    private static void copyDirectory(Context context, String source, File target) throws IOException {
        String[] names = context.getAssets().list(source);
        if (names == null || names.length == 0) {
            return;
        }

        if (!target.isDirectory() && !target.mkdirs()) {
            throw new IOException("cannot create " + target);
        }

        for (String name : names) {
            String child = source + "/" + name;
            String[] nested = context.getAssets().list(child);

            if (nested != null && nested.length != 0) {
                copyDirectory(context, child, new File(target, name));
                continue;
            }

            try (InputStream in = context.getAssets().open(child);
                 OutputStream out = new FileOutputStream(new File(target, name))) {
                byte[] buffer = new byte[64 * 1024];
                int read;
                while ((read = in.read(buffer)) > 0) {
                    out.write(buffer, 0, read);
                }
            }
        }
    }
}
