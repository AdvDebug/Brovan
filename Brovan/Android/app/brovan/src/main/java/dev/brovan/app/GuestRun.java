package dev.brovan.app;

import android.content.Context;
import android.content.Intent;
import android.hardware.display.DisplayManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.Display;

import dev.brovan.BrovanNative;
import dev.brovan.BrovanSurfaceView;

final class GuestRun implements BrovanNative.Listener, BrovanNative.PlayerListener, BrovanNative.MessageListener {

    private static final String TAG = "Brovan";
    private static final long VIEW_WAIT_MS = 3_000;

    // The guest of this process, which outlives the activities that show it. Main thread only.
    private static GuestRun current;

    private final Context context;
    private final Intent settings;
    private final int slot;
    private final Handler ui = new Handler(Looper.getMainLooper());

    private GuestService service;
    private int serviceStartId;
    private boolean started;
    private boolean shown;
    private boolean attached;
    private volatile boolean exited;
    private volatile int exitReason;
    private int startStatus = BrovanNative.STATUS_OK;

    // The spawn handler runs on an emulator thread, so it reads a copy the main thread replaces.
    private volatile Bundle spawnSettings;

    private GuestRun(Context context, Intent settings, int slot) {
        this.context = context;
        this.settings = settings;
        this.slot = slot;
        publishSettings();
    }

    static GuestRun current() {
        return current;
    }

    static GuestRun create(Context context, Intent settings, int slot) {
        current = new GuestRun(context.getApplicationContext(), settings, slot);
        return current;
    }

    /** A spawned guest starts from these, so the view changes them through {@code put}. */
    Intent settings() {
        return settings;
    }

    void put(String key, int value) {
        settings.putExtra(key, value);
        publishSettings();
    }

    void put(String key, float value) {
        settings.putExtra(key, value);
        publishSettings();
    }

    void put(String key, String value) {
        settings.putExtra(key, value);
        publishSettings();
    }

    private void publishSettings() {
        Bundle extras = settings.getExtras();
        spawnSettings = extras != null ? extras : new Bundle();
    }

    boolean started() {
        return started;
    }

    int startStatus() {
        return startStatus;
    }

    /** An exit that reached the run before the view took over its events. */
    boolean exited() {
        return exited;
    }

    int exitReason() {
        return exitReason;
    }

    int init() {
        return BrovanNative.init(context.getFilesDir().getAbsolutePath());
    }

    /** The listeners must be set first, so nothing the guest does at startup is missed. */
    int start() {
        started = true;
        BrovanNative.setLogSink(settings.getBooleanExtra(PlayerActivity.EXTRA_DEVELOPER, false));

        String session = settings.getStringExtra(PlayerActivity.EXTRA_SESSION);
        if (session != null && !session.isEmpty()) {
            BrovanNative.joinSession(session, settings.getIntExtra(PlayerActivity.EXTRA_TOKEN, 0),
                    settings.getIntExtra(PlayerActivity.EXTRA_DEPTH, 1));
        }

        BrovanNative.setSpawnHandler((image, arguments, workingDirectory, sessionId, spawnToken, depth) ->
                GuestSpawner.spawn(context, new Intent().putExtras(spawnSettings), image, arguments, workingDirectory,
                        sessionId, spawnToken, depth));

        // A spawned program gets a guest path, not the host directory of the program.
        String guestDirectory = settings.getStringExtra(PlayerActivity.EXTRA_GUEST_DIRECTORY);
        String directory = guestDirectory == null || guestDirectory.isEmpty()
                ? settings.getStringExtra(PlayerActivity.EXTRA_DIRECTORY)
                : guestDirectory;

        startStatus = BrovanNative.start(
                settings.getStringExtra(PlayerActivity.EXTRA_EXECUTABLE),
                settings.getStringExtra(PlayerActivity.EXTRA_ARGUMENTS),
                directory,
                null,
                settings.getStringExtra(PlayerActivity.EXTRA_SETTINGS));
        return startStatus;
    }

    void startHidden(GuestService owner, int startId) {
        keep(owner, startId);

        // The debugger prompt needs the screen, and without a host window per guest window Brovan cannot tell a
        // hidden window from a shown one.
        if (init() != BrovanNative.STATUS_OK
                || settings.getBooleanExtra(PlayerActivity.EXTRA_DEVELOPER, false)
                || !BrovanNative.topLevelsEnabled()) {
            show();
            return;
        }

        publishDisplay();
        BrovanNative.setListener(this);
        BrovanNative.setPlayerListener(this);
        BrovanNative.setMessageListener(this);

        if (start() != BrovanNative.STATUS_OK) {
            show();
        }
    }

    void keep(GuestService owner, int startId) {
        if (attached) {
            owner.stopSelf(startId);
            return;
        }

        service = owner;
        serviceStartId = startId;

        // Android drops an activity start without an error while no Brovan screen is visible, so each wake tries again.
        if (shown) {
            show();
        }
    }

    void attach() {
        attached = true;
        if (service != null) {
            service.stopSelf(serviceStartId);
            service = null;
        }
    }

    private void show() {
        shown = true;
        try {
            context.startActivity(new Intent(context, GuestSpawner.activityOf(slot))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        } catch (RuntimeException refused) {
            Log.e(TAG, "[spawn] could not show slot " + slot, refused);
        }
    }

    private void reveal() {
        if (!shown && !attached) {
            show();
        }
    }

    // The player is landscape, so the guest gets the long side as its width.
    private void publishDisplay() {
        DisplayManager displays = context.getSystemService(DisplayManager.class);
        Display display = displays == null ? null : displays.getDisplay(Display.DEFAULT_DISPLAY);
        if (display == null) {
            return;
        }

        DisplayMetrics metrics = new DisplayMetrics();
        display.getRealMetrics(metrics);
        int width = Math.max(metrics.widthPixels, metrics.heightPixels);
        int height = Math.min(metrics.widthPixels, metrics.heightPixels);

        int scale = settings.getIntExtra(PlayerActivity.EXTRA_DISPLAY_SCALE, 0);
        int dpi = Settings.DISPLAY_DPIS[scale];
        if (dpi == BrovanSurfaceView.AUTO_DPI) {
            dpi = BrovanSurfaceView.autoDpi(width, height, metrics.densityDpi);
        }

        BrovanNative.setDisplayMetrics(width, height, dpi);
    }

    @Override
    public void onLog(String line) {
    }

    // The process ends with the guest. A view already asked for gets time to attach and end it, because a view that
    // starts after the kill comes up in a new process with no guest.
    @Override
    public void onExit(int reason) {
        exitReason = reason;
        exited = true;
        ui.post(() -> ui.postDelayed(this::endUnattached, shown ? VIEW_WAIT_MS : 0));
    }

    private void endUnattached() {
        if (attached) {
            return;
        }

        BrovanNative.abandonMessage();
        TaskbarView.withdraw(context);
        android.os.Process.killProcess(android.os.Process.myPid());
    }

    @Override
    public void onConsoleAttached() {
    }

    @Override
    public void onScreenChanged() {
    }

    @Override
    public void onWindowShown() {
        ui.post(this::reveal);
    }

    @Override
    public void onConsoleWritten() {
        ui.post(this::reveal);
    }

    @Override
    public void onMessage(BrovanNative.MessageRequest request) {
        ui.post(this::reveal);
    }
}
