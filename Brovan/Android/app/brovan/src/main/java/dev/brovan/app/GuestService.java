package dev.brovan.app;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;

public class GuestService extends Service {

    static final String ACTION_WAKE = "dev.brovan.app.action.WAKE_GUEST";

    private static final String TAG = "Brovan";

    private final Handler ui = new Handler(Looper.getMainLooper());

    // Android redelivers a start whose process died inside this call, and that guest's spawn token is spent.
    // The work is posted, so the call returns before native code runs.
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null || (flags & START_FLAG_RETRY) != 0) {
            Log.e(TAG, "[spawn] " + getClass().getSimpleName() + " was restarted after its guest ended");
            end(startId);
            return START_NOT_STICKY;
        }

        // Posted behind the spawn's start, so the run exists when a wake follows it closely.
        if (ACTION_WAKE.equals(intent.getAction())) {
            ui.post(() -> {
                GuestRun run = GuestRun.current();
                if (run != null) {
                    run.keep(this, startId);
                } else {
                    end(startId);
                }
            });
            return START_NOT_STICKY;
        }

        int slot = GuestSpawner.slotOfService(getClass());
        ui.post(() -> {
            if (GuestRun.current() != null) {
                Log.e(TAG, "[spawn] slot " + slot + " already runs a guest");
                return;
            }

            GuestRun.create(this, intent, slot).startHidden(this, startId);
        });
        return START_NOT_STICKY;
    }

    private void end(int startId) {
        stopSelf(startId);
        android.os.Process.killProcess(android.os.Process.myPid());
    }

    @Override
    public IBinder onBind(Intent intent) {
        return new Binder();
    }
}
