package dev.brovan.app;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Process;
import android.util.AttributeSet;
import android.util.LruCache;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.HorizontalScrollView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.core.content.ContextCompat;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class TaskbarView extends HorizontalScrollView {

    private static final String ACTION_CHANGED = "dev.brovan.app.action.GUESTS_CHANGED";
    private static final String ICON_DIRECTORY = "taskbar";
    private static final int ICON_EDGE = 96;
    private static final float CORNER_DP = 8f;

    private final LinearLayout entries;
    private final int currentColor;
    private final LruCache<String, Bitmap> icons = new LruCache<>(8);
    private final BroadcastReceiver changed = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            refresh();
        }
    };

    public TaskbarView(Context context, AttributeSet attrs) {
        super(context, attrs);
        setFillViewport(true);
        setHorizontalScrollBarEnabled(false);
        currentColor = Theming.color(context, Palette.Role.SURFACE_VARIANT);

        entries = new LinearLayout(context);
        entries.setGravity(Gravity.CENTER);
        addView(entries, new LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT));
    }

    static void publish(Activity activity, String name, String executable) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            activity.setTaskDescription(new ActivityManager.TaskDescription.Builder().setLabel(name).build());
        } else {
            activity.setTaskDescription(new ActivityManager.TaskDescription(name));
        }

        if (executable == null) {
            return;
        }

        Context application = activity.getApplicationContext();
        new Thread(() -> {
            if (writeIcon(application, new File(executable))) {
                announce(application);
            }
        }, "taskbar-icon").start();
    }

    static void withdraw(Context context) {
        iconFile(context, Process.myPid()).delete();
        announce(context);
    }

    void startWatching() {
        ContextCompat.registerReceiver(getContext(), changed, new IntentFilter(ACTION_CHANGED),
                ContextCompat.RECEIVER_NOT_EXPORTED);
        refresh();
    }

    void stopWatching() {
        getContext().unregisterReceiver(changed);
    }

    private void refresh() {
        List<GuestSpawner.Guest> guests = GuestSpawner.running(getContext());
        entries.removeAllViews();

        if (guests.size() < 2) {
            setVisibility(GONE);
            return;
        }

        guests.sort(Comparator.comparingInt(guest -> guest.slot));
        LayoutInflater inflater = LayoutInflater.from(getContext());

        for (GuestSpawner.Guest guest : guests) {
            View entry = inflater.inflate(R.layout.item_taskbar, entries, false);
            bind(entry, guest);
            entries.addView(entry);
        }

        setVisibility(VISIBLE);
    }

    private void bind(View entry, GuestSpawner.Guest guest) {
        String name = guest.label == null ? getContext().getString(R.string.taskbar_starting) : guest.label.toString();
        ((TextView) entry.findViewById(R.id.name)).setText(name);
        entry.setContentDescription(name);

        File file = iconFile(getContext(), guest.pid);
        String key = file.getName() + "-" + file.lastModified();
        Bitmap icon = icons.get(key);
        if (icon == null && file.isFile()) {
            icon = BitmapFactory.decodeFile(file.getPath());
            if (icon != null) {
                icons.put(key, icon);
            }
        }

        ImageView image = entry.findViewById(R.id.icon);
        if (icon != null) {
            image.setImageBitmap(icon);
        } else {
            image.setImageDrawable(new ProgramAdapter.Monogram(name));
        }

        if (guest.pid == Process.myPid()) {
            GradientDrawable current = new GradientDrawable();
            current.setColor(currentColor);
            current.setCornerRadius(CORNER_DP * getResources().getDisplayMetrics().density);
            entry.setBackground(current);
            entry.findViewById(R.id.indicator).setVisibility(VISIBLE);
            return;
        }

        entry.setOnClickListener(view -> {
            if (!GuestSpawner.show(getContext(), guest)) {
                refresh();
            }
        });
    }

    private static void announce(Context context) {
        context.sendBroadcast(new Intent(ACTION_CHANGED).setPackage(context.getPackageName()));
    }

    private static File iconFile(Context context, int pid) {
        return new File(new File(context.getCacheDir(), ICON_DIRECTORY), pid + ".png");
    }

    // Rename only after writing so other processes cannot read a partial icon.
    private static boolean writeIcon(Context context, File executable) {
        Bitmap extracted = ExeIcon.extract(executable);
        if (extracted == null) {
            return false;
        }

        File target = iconFile(context, Process.myPid());
        File directory = target.getParentFile();
        directory.mkdirs();
        if (!directory.isDirectory()) {
            return false;
        }

        removeStale(context, directory);

        Bitmap icon = Bitmap.createScaledBitmap(extracted, ICON_EDGE, ICON_EDGE, true);
        File partial = new File(directory, target.getName() + ".part");

        try (OutputStream stream = new FileOutputStream(partial)) {
            icon.compress(Bitmap.CompressFormat.PNG, 100, stream);
        } catch (IOException unwritable) {
            partial.delete();
            return false;
        }

        return partial.renameTo(target);
    }

    // Android can reuse a dead guest's PID.
    private static void removeStale(Context context, File directory) {
        File[] files = directory.listFiles();
        if (files == null || files.length == 0) {
            return;
        }

        Set<String> live = new HashSet<>();
        for (int pid : GuestSpawner.runningProcesses(context).values()) {
            live.add(Integer.toString(pid));
        }

        for (File file : files) {
            String name = file.getName();
            int dot = name.indexOf('.');
            if (!live.contains(dot < 0 ? name : name.substring(0, dot))) {
                file.delete();
            }
        }
    }
}
