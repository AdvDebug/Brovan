package dev.brovan.app;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;
import android.view.View;
import android.view.WindowManager;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import com.google.android.material.floatingactionbutton.FloatingActionButton;

import java.io.File;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

import dev.brovan.BrovanNative;
import dev.brovan.BrovanSurfaceView;

import dev.brovan.GuestWindow;
import dev.brovan.input.ControlLayout;
import dev.brovan.input.ControlOverlay;

/**
 * Runs one program full screen. It lives in its own process, so quitting reclaims everything the emulator
 * allocated and the next launch starts from a clean state.
 */
public class PlayerActivity extends AppCompatActivity implements BrovanNative.Listener, DebuggerView.Listener {

    private static final String EXTRA_DIRECTORY = "directory";
    private static final String EXTRA_EXECUTABLE = "executable";
    private static final String EXTRA_NAME = "name";
    private static final String EXTRA_NETWORK = "network";
    private static final String EXTRA_DEVELOPER = "developer";
    private static final String EXTRA_CONTROLS = "controls";
    private static final String EXTRA_JIT_CACHE = "jit_cache";
    private static final String EXTRA_SUSTAINED = "sustained";
    private static final String EXTRA_LAYOUT = "layout";
    private static final String EXTRA_POINTER = "pointer";

    private static final int MAX_LINES = 1200;
    private static final int TRIM_CHUNK = 200;
    private static final long FLUSH_DELAY_MS = 80;

    private final ArrayDeque<CharSequence> lines = new ArrayDeque<>();
    private final ArrayDeque<CharSequence> pending = new ArrayDeque<>();
    private final Handler ui = new Handler(Looper.getMainLooper());

    private BrovanSurfaceView surface;
    private ControlOverlay controls;
    private Settings settings;
    private DebuggerView debugger;
    private TextView status;
    private TextView log;
    private ScrollView logScroll;
    private boolean developerMode;
    private boolean flushScheduled;
    private boolean logStale;
    private int logColorError;
    private int logColorOk;
    private int logColorWarn;
    private int logColorTrace;
    private int logColorInfo;
    private int logColorSpecial;
    private int logColorCommand;
    private int logColorText;

    static Intent intentFor(Context context, Program program, Settings settings) {
        return new Intent(context, PlayerActivity.class)
                .putExtra(EXTRA_DIRECTORY, program.directory().getAbsolutePath())
                .putExtra(EXTRA_EXECUTABLE, program.executable().getAbsolutePath())
                .putExtra(EXTRA_NAME, program.name())
                .putExtra(EXTRA_NETWORK, settings.network())
                .putExtra(EXTRA_DEVELOPER, settings.developerMode())
                .putExtra(EXTRA_CONTROLS, settings.controlScheme())
                .putExtra(EXTRA_JIT_CACHE, settings.jitCache())
                .putExtra(EXTRA_SUSTAINED, settings.sustainedPerformance())
                .putExtra(EXTRA_LAYOUT, settings.controlLayout())
                .putExtra(EXTRA_POINTER, settings.pointerMode());
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        applySustainedPerformance();
        setContentView(R.layout.activity_player);

        settings = new Settings(this);
        surface = findViewById(R.id.surface);
        controls = findViewById(R.id.controls);
        debugger = findViewById(R.id.debugger);
        debugger.setListener(this);

        controls.setCustomLayout(ControlLayout.fromJson(getIntent().getStringExtra(EXTRA_LAYOUT)));
        int scheme = getIntent().getIntExtra(EXTRA_CONTROLS, 0);
        controls.apply(ControlOverlay.Scheme.values()[scheme]);

        surface.setPointerMode(BrovanSurfaceView.PointerMode.values()[
                getIntent().getIntExtra(EXTRA_POINTER, 0)]);
        status = findViewById(R.id.status);
        log = findViewById(R.id.log);
        logScroll = findViewById(R.id.log_scroll);

        logColorError = ContextCompat.getColor(this, R.color.log_error);
        logColorOk = ContextCompat.getColor(this, R.color.log_ok);
        logColorWarn = ContextCompat.getColor(this, R.color.log_warn);
        logColorTrace = ContextCompat.getColor(this, R.color.log_trace);
        logColorInfo = ContextCompat.getColor(this, R.color.log_info);
        logColorSpecial = ContextCompat.getColor(this, R.color.log_special);
        logColorCommand = ContextCompat.getColor(this, R.color.log_command);
        logColorText = ContextCompat.getColor(this, R.color.text_primary);

        developerMode = getIntent().getBooleanExtra(EXTRA_DEVELOPER, false);
        debugger.setDeveloperMode(developerMode);

        FloatingActionButton menu = findViewById(R.id.menu);
        menu.setOnClickListener(view -> showMenu());

        EditText command = findViewById(R.id.command);
        findViewById(R.id.send).setOnClickListener(view -> {
            String text = command.getText().toString().trim();
            if (!text.isEmpty()) {
                append("[/] > " + text);
                command.setText("");
                debugger.send(text);
            }
        });

        BrovanNative.setListener(this);
        start();
    }

    private void start() {
        int status = BrovanNative.init(getFilesDir().getAbsolutePath());
        if (status != BrovanNative.STATUS_OK) {
            fail("Could not start the emulator (" + status + ").");
            return;
        }

        BrovanNative.setVerbose(developerMode);
        BrovanNative.setJitCache(getIntent().getBooleanExtra(EXTRA_JIT_CACHE, true));
        setStatus(getIntent().getStringExtra(EXTRA_NAME));

        // Developer mode leaves the guest at the debugger prompt instead of running it, so the debugger has
        // to be up for the "start" that gets it going to be reachable.
        if (developerMode) {
            debugger.setVisibility(View.VISIBLE);
            append(getString(R.string.player_developer_hint));
        }

        int result = BrovanNative.start(
                getIntent().getStringExtra(EXTRA_EXECUTABLE),
                null,
                getIntent().getStringExtra(EXTRA_DIRECTORY),
                null,
                getIntent().getIntExtra(EXTRA_NETWORK, 1));

        if (result != BrovanNative.STATUS_OK) {
            fail(describe(result));
        }
    }

    private void applySustainedPerformance() {
        if (!getIntent().getBooleanExtra(EXTRA_SUSTAINED, false)) {
            return;
        }

        PowerManager power = getSystemService(PowerManager.class);
        if (power != null && power.isSustainedPerformanceModeSupported()) {
            getWindow().setSustainedPerformanceMode(true);
        }
    }

    private void showMenu() {
        List<String> labels = new ArrayList<>();
        List<Runnable> actions = new ArrayList<>();

        labels.add(getString(R.string.player_controls));
        actions.add(this::showControlSchemes);

        labels.add(getString(R.string.player_pointer));
        actions.add(this::showPointerModes);

        labels.add(getString(R.string.player_windows));
        actions.add(this::showWindows);

        labels.add(getString(R.string.player_redraw));
        actions.add(BrovanNative::requestRepaint);

        if (developerMode) {
            labels.add(getString(R.string.player_debugger));
            actions.add(this::toggleDebugger);
        }

        labels.add(getString(R.string.player_quit));
        actions.add(this::quit);

        new AlertDialog.Builder(this)
                .setItems(labels.toArray(new CharSequence[0]),
                        (dialog, index) -> actions.get(index).run())
                .show();
    }

    private void showControlSchemes() {
        ControlOverlay.Scheme[] schemes = ControlOverlay.Scheme.values();
        CharSequence[] labels = new CharSequence[schemes.length];
        for (int i = 0; i < schemes.length; i++) {
            labels[i] = schemes[i].label();
        }

        new AlertDialog.Builder(this)
                .setTitle(R.string.player_controls)
                .setSingleChoiceItems(labels, controls.scheme().ordinal(), (dialog, index) -> {
                    controls.apply(schemes[index]);
                    settings.setControlScheme(index);
                    dialog.dismiss();
                })
                .show();
    }

    private void showPointerModes() {
        BrovanSurfaceView.PointerMode[] modes = BrovanSurfaceView.PointerMode.values();
        CharSequence[] labels = new CharSequence[modes.length];
        for (int i = 0; i < modes.length; i++) {
            labels[i] = modes[i].label();
        }

        int current = getIntent().getIntExtra(EXTRA_POINTER, 0);
        new AlertDialog.Builder(this)
                .setTitle(R.string.player_pointer)
                .setSingleChoiceItems(labels, current, (dialog, index) -> {
                    surface.setPointerMode(modes[index]);
                    getIntent().putExtra(EXTRA_POINTER, index);
                    dialog.dismiss();
                })
                .show();
    }

    private void showWindows() {
        List<GuestWindow> windows = BrovanNative.listWindows();
        if (windows.isEmpty()) {
            append("[*] The program has not created a window yet.");
            return;
        }

        CharSequence[] labels = new CharSequence[windows.size()];
        for (int i = 0; i < windows.size(); i++) {
            labels[i] = windows.get(i).toString();
        }

        new AlertDialog.Builder(this)
                .setTitle(R.string.player_windows)
                .setItems(labels, (dialog, index) -> {
                    BrovanNative.selectWindow(windows.get(index).hwnd());
                    debugger.setVisibility(View.GONE);
                    surface.requestFocus();
                })
                .show();
    }

    private void toggleDebugger() {
        boolean visible = debugger.getVisibility() == View.VISIBLE;
        debugger.setVisibility(visible ? View.GONE : View.VISIBLE);
        if (visible) {
            surface.requestFocus();
            BrovanNative.requestRepaint();
            return;
        }

        if (logStale) {
            rebuildLog();
            logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        controls.releaseAll();
    }

    private void quit() {
        BrovanNative.requestClose();
        finish();
    }

    private void fail(String message) {
        append("[-] " + message);
        debugger.setVisibility(View.VISIBLE);
        setStatus(message);
    }

    private void setStatus(String value) {
        runOnUiThread(() -> status.setText(value));
    }

    /**
     * A trace line arrives on an emulator thread, so the text is styled there and only the batch is handed
     * to the UI thread. One append and one scroll per window keeps a chatty guest from turning every line
     * into a layout pass, which is what made the whole app crawl in developer mode.
     */
    private void append(String line) {
        CharSequence styled = style(line);

        synchronized (pending) {
            pending.addLast(styled);
            while (pending.size() > MAX_LINES) {
                pending.removeFirst();
            }

            if (flushScheduled) {
                return;
            }

            flushScheduled = true;
        }

        ui.postDelayed(this::flushLog, FLUSH_DELAY_MS);
    }

    private void flushLog() {
        SpannableStringBuilder batch = new SpannableStringBuilder();

        synchronized (pending) {
            flushScheduled = false;

            for (CharSequence entry : pending) {
                lines.addLast(entry);
                batch.append(entry).append('\n');
            }

            pending.clear();
        }

        if (batch.length() == 0) {
            return;
        }

        // Nothing is on screen while another debugger tab is up, so the history is kept and the text view
        // is rebuilt from it the next time the log is opened.
        if (!debugger.isLogVisible()) {
            trim();
            logStale = true;
            return;
        }

        if (lines.size() > MAX_LINES || logStale) {
            trim();
            rebuildLog();
        } else {
            log.append(batch);
        }

        logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
    }

    private void trim() {
        while (lines.size() > MAX_LINES) {
            for (int i = 0; i < TRIM_CHUNK && !lines.isEmpty(); i++) {
                lines.removeFirst();
            }
        }
    }

    private void rebuildLog() {
        SpannableStringBuilder builder = new SpannableStringBuilder();
        for (CharSequence entry : lines) {
            builder.append(entry).append('\n');
        }

        log.setText(builder);
        logStale = false;
    }

    private CharSequence style(String line) {
        SpannableString styled = new SpannableString(line);
        styled.setSpan(new ForegroundColorSpan(colorFor(line)), 0, line.length(),
                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
        return styled;
    }

    /** Mirrors the markers the emulator colours its own console output with. */
    private int colorFor(String line) {
        if (line.startsWith("[!!]") || line.startsWith("[-]")) return logColorError;
        if (line.startsWith("[!]")) return logColorWarn;
        if (line.startsWith("[+]")) return logColorOk;
        if (line.startsWith("[*]")) return logColorTrace;
        if (line.startsWith("[#]")) return logColorInfo;
        if (line.startsWith("[$]")) return logColorSpecial;
        if (line.startsWith("[/]")) return logColorCommand;
        return logColorText;
    }

    @Override
    public void onLog(String line) {
        if (developerMode) {
            append(line);
        }
    }

    @Override
    public void onDebuggerMessage(String line) {
        append(line);
    }

    @Override
    public void onExit(int reason) {
        append(reason == 0 ? "[*] The program closed." : "[-] The program stopped unexpectedly.");
        setStatus(reason == 0 ? "Finished" : "Stopped");
        runOnUiThread(() -> {
            if (!developerMode) {
                finish();
            }
        });
    }

    @Override
    public void onBackPressed() {
        if (debugger.getVisibility() == View.VISIBLE) {
            toggleDebugger();
            return;
        }

        quit();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        ui.removeCallbacksAndMessages(null);

        // The emulator refuses a second guest in the same process, so the process goes with the activity.
        if (isFinishing()) {
            android.os.Process.killProcess(android.os.Process.myPid());
        }
    }

    private static String describe(int status) {
        switch (status) {
            case BrovanNative.STATUS_MISSING_WINDOWS_LIBS: return "Windows system files are missing.";
            case BrovanNative.STATUS_MISSING_REGISTRY: return "The registry files are missing.";
            case BrovanNative.STATUS_BINARY_NOT_FOUND: return "The program file is gone.";
            case BrovanNative.STATUS_ALREADY_RUNNING: return "Another program is already running.";
            default: return "The program could not be started (" + status + ").";
        }
    }
}
