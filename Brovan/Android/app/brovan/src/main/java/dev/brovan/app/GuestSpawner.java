package dev.brovan.app;

import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.util.Log;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

    static final class Guest {
        final int slot;
        final int pid;
        final CharSequence label;
        final ActivityManager.AppTask task;

        Guest(int slot, int pid, CharSequence label, ActivityManager.AppTask task) {
            this.slot = slot;
            this.pid = pid;
            this.label = label;
            this.task = task;
        }
    }

    private GuestSpawner() {
    }

    static boolean spawn(Context context, Intent parent, String image, String arguments, String guestDirectory,
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

        Intent intent = PlayerActivity.spawnIntent(context, target, parent, program,
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

    // Android returns app tasks in most recently used order.
    static List<Guest> running(Context context) {
        List<Guest> guests = new ArrayList<>();
        ActivityManager manager = context.getSystemService(ActivityManager.class);
        if (manager == null) {
            return guests;
        }

        Map<String, Integer> processes = runningProcesses(context);
        boolean[] listed = new boolean[POOL.length + 1];

        for (ActivityManager.AppTask task : manager.getAppTasks()) {
            ActivityManager.RecentTaskInfo info;
            try {
                info = task.getTaskInfo();
            } catch (IllegalArgumentException gone) {
                continue;
            }

            int slot = info.topActivity == null ? -1 : slotOf(info.topActivity.getClassName());
            if (slot < 0 || listed[slot]) {
                continue;
            }

            Integer pid = processes.get(processName(context, slot));
            if (pid == null) {
                continue;
            }

            listed[slot] = true;
            guests.add(new Guest(slot, pid, info.taskDescription == null ? null : info.taskDescription.getLabel(),
                    task));
        }

        return guests;
    }

    // Moving a dead guest's task to the front would restart it.
    static boolean show(Context context, Guest guest) {
        for (Guest live : running(context)) {
            if (live.slot == guest.slot && live.pid == guest.pid) {
                return moveToFront(live.task);
            }
        }

        return false;
    }

    static void showNext(Context context) {
        int self = Process.myPid();
        for (Guest guest : running(context)) {
            if (guest.pid != self && moveToFront(guest.task)) {
                return;
            }
        }
    }

    private static boolean moveToFront(ActivityManager.AppTask task) {
        try {
            task.moveToFront();
            return true;
        } catch (IllegalArgumentException gone) {
            return false;
        }
    }

    /** The emulator refuses a second guest in a process, and the reuse fails only once the activity is in front. */
    private static Class<?> freeActivity(Context context) {
        Map<String, Integer> busy = runningProcesses(context);

        for (int index = 0; index < POOL.length; index++) {
            if (!busy.containsKey(processName(context, index + 1))) {
                return POOL[index];
            }
        }

        return null;
    }

    private static int slotOf(String activity) {
        if (PlayerActivity.class.getName().equals(activity)) {
            return 0;
        }

        for (int index = 0; index < POOL.length; index++) {
            if (POOL[index].getName().equals(activity)) {
                return index + 1;
            }
        }

        return -1;
    }

    private static String processName(Context context, int slot) {
        String root = context.getPackageName() + ":guest";
        return slot == 0 ? root : root + slot;
    }

    static Map<String, Integer> runningProcesses(Context context) {
        Map<String, Integer> processes = new HashMap<>();
        ActivityManager manager = context.getSystemService(ActivityManager.class);

        if (manager == null) {
            return processes;
        }

        List<ActivityManager.RunningAppProcessInfo> running = manager.getRunningAppProcesses();
        if (running == null) {
            return processes;
        }

        for (ActivityManager.RunningAppProcessInfo process : running) {
            if (process.processName != null) {
                processes.put(process.processName, process.pid);
            }
        }

        return processes;
    }
}
