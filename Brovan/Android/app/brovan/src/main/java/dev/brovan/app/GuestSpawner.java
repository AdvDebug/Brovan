package dev.brovan.app;

import android.app.ActivityManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.Process;
import android.util.Log;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * One emulator per process, and Android fixes the processes at build time, so the pool is a fixed set of
 * slots with one process each. Slot 0 is the program started from the library.
 */
final class GuestSpawner {

    /** Each must match the android:process of its activity and service in the manifest. */
    private static final Slot[] SLOTS = {
            new Slot(PlayerActivity.class, null),
            new Slot(GuestActivity1.class, GuestService1.class),
            new Slot(GuestActivity2.class, GuestService2.class),
            new Slot(GuestActivity3.class, GuestService3.class),
            new Slot(GuestActivity4.class, GuestService4.class),
    };

    private static final String TAG = "Brovan";

    private static final class Slot {
        final Class<?> activity;
        final Class<?> service;

        Slot(Class<?> activity, Class<?> service) {
            this.activity = activity;
            this.service = service;
        }
    }

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

        int slot = freeSlot(context);
        if (slot < 0) {
            Log.e(TAG, "[spawn] every guest process of the pool is in use");
            return false;
        }

        File program = new File(image).getParentFile();
        if (program == null) {
            return false;
        }

        Intent intent = PlayerActivity.spawnIntent(context, SLOTS[slot].service, parent, program,
                new File(image), arguments, guestDirectory, sessionId, spawnToken, depth);

        try {
            return context.startService(intent) != null;
        } catch (RuntimeException refused) {
            Log.e(TAG, "[spawn] could not start " + SLOTS[slot].service.getSimpleName(), refused);
            return false;
        }
    }

    static Class<?> activityOf(int slot) {
        return SLOTS[slot].activity;
    }

    static int slotOfService(Class<?> service) {
        for (int index = 1; index < SLOTS.length; index++) {
            if (SLOTS[index].service == service) {
                return index;
            }
        }

        return -1;
    }

    // Android returns app tasks in most recently used order.
    static List<Guest> running(Context context) {
        return running(context, runningProcesses(context));
    }

    private static List<Guest> running(Context context, Map<String, Integer> processes) {
        List<Guest> guests = new ArrayList<>();
        ActivityManager manager = context.getSystemService(ActivityManager.class);
        if (manager == null) {
            return guests;
        }

        boolean[] listed = new boolean[SLOTS.length];

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

    /** The emulator refuses a second guest in a process, and a hidden guest has a process but no task. */
    private static int freeSlot(Context context) {
        Map<String, Integer> busy = runningProcesses(context);

        for (int index = 1; index < SLOTS.length; index++) {
            if (!busy.containsKey(processName(context, index))) {
                return index;
            }
        }

        return -1;
    }

    private static int slotOf(String activity) {
        for (int index = 0; index < SLOTS.length; index++) {
            if (SLOTS[index].activity.getName().equals(activity)) {
                return index;
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

    static final class Wake {
        private final Context context;
        private final ServiceConnection[] connections = new ServiceConnection[SLOTS.length];

        Wake(Context context) {
            this.context = context.getApplicationContext();
        }

        void start() {
            Map<String, Integer> processes = runningProcesses(context);
            boolean[] shown = new boolean[SLOTS.length];
            for (Guest guest : running(context, processes)) {
                shown[guest.slot] = true;
            }

            for (int index = 1; index < SLOTS.length; index++) {
                if (!shown[index] && processes.containsKey(processName(context, index))) {
                    wake(index);
                }

                bind(index);
            }
        }

        void stop() {
            for (int index = 1; index < SLOTS.length; index++) {
                unbind(index);
            }
        }

        // Android stops a started service about a minute after the app leaves the screen, so it is started again.
        private void wake(int slot) {
            try {
                context.startService(new Intent(context, SLOTS[slot].service).setAction(GuestService.ACTION_WAKE));
            } catch (RuntimeException refused) {
                Log.e(TAG, "[wake] could not wake " + SLOTS[slot].service.getSimpleName(), refused);
            }
        }

        // The binding keeps a hidden guest from being frozen. Flags 0, so it never starts one.
        private void bind(int slot) {
            if (connections[slot] != null) {
                return;
            }

            ServiceConnection connection = new ServiceConnection() {
                @Override
                public void onServiceConnected(ComponentName name, IBinder service) {
                }

                @Override
                public void onServiceDisconnected(ComponentName name) {
                }

                // A slot used again by a later guest needs a new binding.
                @Override
                public void onBindingDied(ComponentName name) {
                    unbind(slot);
                    bind(slot);
                }
            };

            if (context.bindService(new Intent(context, SLOTS[slot].service), connection, 0)) {
                connections[slot] = connection;
            }
        }

        private void unbind(int slot) {
            ServiceConnection connection = connections[slot];
            if (connection != null) {
                connections[slot] = null;
                context.unbindService(connection);
            }
        }
    }
}
