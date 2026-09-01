package dev.brovan.app;

import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import java.io.File;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * One emulator per process, and Android fixes the processes at build time, so the pool is a fixed set of
 * activities with one process each.
 */
final class GuestSpawner {

    /** Must match the activities and their android:process in the manifest. */
    private static final Class<?>[] POOL = {
            GuestActivity1.class,
            GuestActivity2.class,
            GuestActivity3.class,
            GuestActivity4.class,
    };

    private static final String TAG = "Brovan";

    private GuestSpawner() {
    }

    static boolean spawn(Context context, String image, String arguments, String guestDirectory,
                         String sessionId, int spawnToken, int depth) {
        if (context == null || image == null || image.isEmpty()) {
            return false;
        }

        Class<?> target = freeActivity(context);
        if (target == null) {
            Log.e(TAG, "[spawn] every guest process of the pool is in use");
            return false;
        }

        File program = new File(image).getParentFile();
        if (program == null) {
            return false;
        }

        Intent intent = PlayerActivity.spawnIntent(context, target, new Settings(context), program,
                new File(image), arguments, guestDirectory, sessionId, spawnToken, depth);

        // The caller is an emulator thread with its own timeout, so the start can wait for the main thread.
        new Handler(Looper.getMainLooper()).post(() -> {
            try {
                context.startActivity(intent);
            } catch (RuntimeException failure) {
                Log.e(TAG, "[spawn] could not start " + target.getSimpleName(), failure);
            }
        });

        return true;
    }

    /** The emulator refuses a second guest in a process, and the reuse fails only once the activity is in front. */
    private static Class<?> freeActivity(Context context) {
        Set<String> busy = busyProcesses(context);
        String prefix = context.getPackageName() + ":guest";

        for (int index = 0; index < POOL.length; index++) {
            if (!busy.contains(prefix + (index + 1))) {
                return POOL[index];
            }
        }

        return null;
    }

    private static Set<String> busyProcesses(Context context) {
        Set<String> names = new HashSet<>();
        ActivityManager manager = context.getSystemService(ActivityManager.class);

        if (manager == null) {
            return names;
        }

        List<ActivityManager.RunningAppProcessInfo> running = manager.getRunningAppProcesses();
        if (running == null) {
            return names;
        }

        for (ActivityManager.RunningAppProcessInfo process : running) {
            if (process.processName != null) {
                names.add(process.processName);
            }
        }

        return names;
    }
}
