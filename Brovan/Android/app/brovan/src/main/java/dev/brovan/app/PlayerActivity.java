package dev.brovan.app;

import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.util.DisplayMetrics;
import android.view.Gravity;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;

import com.google.android.material.sidesheet.SideSheetDialog;
import com.google.android.material.slider.Slider;
import com.google.android.material.textfield.MaterialAutoCompleteTextView;

import java.io.File;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Locale;

import dev.brovan.BrovanNative;
import dev.brovan.BrovanSurfaceView;

import dev.brovan.GuestWindow;
import dev.brovan.input.ControlLayout;
import dev.brovan.input.ControlOverlay;
import dev.brovan.input.PointerState;

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
    private static final String EXTRA_ARGUMENTS = "arguments";
    private static final String EXTRA_GUEST_DIRECTORY = "guest_directory";
    private static final String EXTRA_SESSION = "session";
    private static final String EXTRA_TOKEN = "token";
    private static final String EXTRA_DEPTH = "depth";

    private static final int MAX_LINES = 1200;
    private static final int TRIM_CHUNK = 200;
    private static final long FLUSH_DELAY_MS = 80;
    private static final long CLOSE_GRACE_MS = 5_000;
    private static final long STOP_TIMEOUT_MS = 10_000;

    private static final int VK_ESCAPE = 0x1B;
    private static final int ESCAPE_SCAN_CODE = 1;
    private static final long KEY_HOLD_MS = 70;
    private static final float SPEED_MIN = 0.4f;
    private static final float SPEED_MAX = 3f;
    private static final float MENU_FRACTION = 0.45f;
    private static final float MENU_LIMIT = 0.92f;
    private static final int MENU_MIN_DP = 320;
    private static final int MENU_MAX_DP = 520;

    private final ArrayDeque<CharSequence> lines = new ArrayDeque<>();
    private final ArrayDeque<CharSequence> pending = new ArrayDeque<>();
    private final Handler ui = new Handler(Looper.getMainLooper());

    private BrovanSurfaceView surface;
    private SideSheetDialog menu;
    private ControlOverlay controls;
    private Settings settings;
    private ProgramSettings program;
    private DebuggerView debugger;
    private TextView status;
    private TextView log;
    private ScrollView logScroll;
    private boolean developerMode;
    private boolean quitting;
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
        ProgramSettings own = new ProgramSettings(program.directory(), settings);
        return new Intent(context, PlayerActivity.class)
                .putExtra(EXTRA_DIRECTORY, program.directory().getAbsolutePath())
                .putExtra(EXTRA_EXECUTABLE, program.executable().getAbsolutePath())
                .putExtra(EXTRA_NAME, program.name())
                .putExtra(EXTRA_NETWORK, settings.network())
                .putExtra(EXTRA_DEVELOPER, settings.developerMode())
                .putExtra(EXTRA_CONTROLS, own.controlScheme())
                .putExtra(EXTRA_JIT_CACHE, settings.jitCache())
                .putExtra(EXTRA_SUSTAINED, settings.sustainedPerformance())
                .putExtra(EXTRA_LAYOUT, settings.controlLayout())
                .putExtra(EXTRA_POINTER, own.pointerMode());
    }

    /** The session and token are what let the two emulator processes find each other. */
    static Intent spawnIntent(Context context, Class<?> target, Settings settings, File directory, File image,
                              String arguments, String guestDirectory, String sessionId, int spawnToken,
                              int depth) {
        ProgramSettings own = new ProgramSettings(directory, settings);
        return new Intent(context, target)
                .putExtra(EXTRA_DIRECTORY, directory.getAbsolutePath())
                .putExtra(EXTRA_EXECUTABLE, image.getAbsolutePath())
                .putExtra(EXTRA_NAME, image.getName())
                .putExtra(EXTRA_ARGUMENTS, arguments)
                .putExtra(EXTRA_GUEST_DIRECTORY, guestDirectory)
                .putExtra(EXTRA_SESSION, sessionId)
                .putExtra(EXTRA_TOKEN, spawnToken)
                .putExtra(EXTRA_DEPTH, depth)
                .putExtra(EXTRA_NETWORK, settings.network())
                .putExtra(EXTRA_DEVELOPER, settings.developerMode())
                .putExtra(EXTRA_CONTROLS, own.controlScheme())
                .putExtra(EXTRA_JIT_CACHE, settings.jitCache())
                .putExtra(EXTRA_SUSTAINED, settings.sustainedPerformance())
                .putExtra(EXTRA_LAYOUT, settings.controlLayout())
                .putExtra(EXTRA_POINTER, own.pointerMode());
    }

    private void goFullscreen() {
        Window window = getWindow();
        window.setStatusBarColor(Color.BLACK);
        window.setNavigationBarColor(Color.BLACK);

        WindowInsetsControllerCompat bars = WindowCompat.getInsetsController(window, window.getDecorView());
        bars.hide(WindowInsetsCompat.Type.systemBars());
        bars.setSystemBarsBehavior(WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE);
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);

        if (hasFocus) {
            goFullscreen();
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Palette palette = new Settings(this).palette();
        Theming.install(this, palette);

        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        applySustainedPerformance();

        setContentView(R.layout.activity_player);

        Theming.apply(this, Palette.defaults(), palette);
        goFullscreen();

        settings = new Settings(this);
        program = new ProgramSettings(new File(getIntent().getStringExtra(EXTRA_DIRECTORY)), settings);
        surface = findViewById(R.id.surface);
        controls = findViewById(R.id.controls);
        debugger = findViewById(R.id.debugger);
        debugger.setListener(this);

        controls.setCustomLayout(ControlLayout.fromJson(getIntent().getStringExtra(EXTRA_LAYOUT)));
        int scheme = getIntent().getIntExtra(EXTRA_CONTROLS, 0);
        controls.apply(ControlOverlay.Scheme.values()[scheme]);

        surface.setPointerMode(BrovanSurfaceView.PointerMode.values()[
                getIntent().getIntExtra(EXTRA_POINTER, 0)]);
        PointerState.setSpeed(snapSpeed(program.pointerSpeed()));
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
        logColorText = Theming.color(this, Palette.Role.TEXT_PRIMARY);

        developerMode = getIntent().getBooleanExtra(EXTRA_DEVELOPER, false);
        debugger.setDeveloperMode(developerMode);

        EditText command = findViewById(R.id.command);
        findViewById(R.id.send).setOnClickListener(view -> {
            String text = command.getText().toString().trim();
            if (!text.isEmpty()) {
                append("[/] > " + text);
                command.setText("");
                debugger.send(text);
            }
        });

        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                if (debugger.getVisibility() == View.VISIBLE) {
                    toggleDebugger();
                    return;
                }

                showMenu();
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

        String session = getIntent().getStringExtra(EXTRA_SESSION);
        if (session != null && !session.isEmpty()) {
            BrovanNative.joinSession(session, getIntent().getIntExtra(EXTRA_TOKEN, 0),
                    getIntent().getIntExtra(EXTRA_DEPTH, 1));
        }

        BrovanNative.setSpawnHandler((image, arguments, workingDirectory, sessionId, spawnToken, depth) ->
                GuestSpawner.spawn(this, image, arguments, workingDirectory, sessionId, spawnToken, depth));

        // Developer mode leaves the guest at the debugger prompt instead of running it, so the debugger has
        // to be up for the "start" that gets it going to be reachable.
        if (developerMode) {
            debugger.setVisibility(View.VISIBLE);
            append(getString(R.string.player_developer_hint));
        }

        // A spawned program gets a guest path, not the host directory of the program.
        String guestDirectory = getIntent().getStringExtra(EXTRA_GUEST_DIRECTORY);
        String directory = guestDirectory == null || guestDirectory.isEmpty()
                ? getIntent().getStringExtra(EXTRA_DIRECTORY)
                : guestDirectory;

        int result = BrovanNative.start(
                getIntent().getStringExtra(EXTRA_EXECUTABLE),
                getIntent().getStringExtra(EXTRA_ARGUMENTS),
                directory,
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
        if (menu != null) {
            return;
        }

        View view = getLayoutInflater().inflate(R.layout.sheet_player_menu, null);
        bindMenu(view);

        menu = new SideSheetDialog(this);
        Theming.paintOnShow(menu, new Settings(this).palette());
        menu.setContentView(view);

        // The sheet view only exists once there is content in it, and both the edge and the width belong
        // to that view rather than to the dialog.
        menu.setSheetEdge(Gravity.LEFT);
        resize((View) view.getParent());
        menu.setOnDismissListener(dialog -> {
            menu = null;
            surface.requestFocus();
        });

        menu.show();
    }

    private void bindMenu(View view) {
        ((TextView) view.findViewById(R.id.title)).setText(getIntent().getStringExtra(EXTRA_NAME));

        BrovanSurfaceView.PointerMode[] modes = BrovanSurfaceView.PointerMode.values();
        String[] modeLabels = new String[modes.length];
        for (int i = 0; i < modes.length; i++) {
            modeLabels[i] = modes[i].label();
        }

        MaterialAutoCompleteTextView pointer = view.findViewById(R.id.pointer);
        pointer.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, modeLabels));
        pointer.setText(modeLabels[getIntent().getIntExtra(EXTRA_POINTER, 0)], false);
        pointer.setOnItemClickListener((parent, item, position, id) -> {
            surface.setPointerMode(modes[position]);
            program.setPointerMode(position);
            getIntent().putExtra(EXTRA_POINTER, position);
        });

        ControlOverlay.Scheme[] schemes = ControlOverlay.Scheme.values();
        String[] schemeLabels = new String[schemes.length];
        for (int i = 0; i < schemes.length; i++) {
            schemeLabels[i] = schemes[i].label();
        }

        MaterialAutoCompleteTextView scheme = view.findViewById(R.id.controls);
        scheme.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, schemeLabels));
        scheme.setText(schemeLabels[controls.scheme().ordinal()], false);
        scheme.setOnItemClickListener((parent, item, position, id) -> {
            controls.apply(schemes[position]);
            program.setControlScheme(position);
        });

        TextView speedValue = view.findViewById(R.id.sensitivity_value);
        Slider speed = view.findViewById(R.id.sensitivity);
        speed.setValue(snapSpeed(program.pointerSpeed()));
        speedValue.setText(formatSpeed(speed.getValue()));
        speed.addOnChangeListener((slider, value, fromUser) -> {
            PointerState.setSpeed(value);
            speedValue.setText(formatSpeed(value));
        });

        // Dragging the slider reports every step it passes through, and each one would rewrite the manifest.
        speed.addOnSliderTouchListener(new Slider.OnSliderTouchListener() {
            @Override
            public void onStartTrackingTouch(Slider slider) {
            }

            @Override
            public void onStopTrackingTouch(Slider slider) {
                program.setPointerSpeed(slider.getValue());
            }
        });

        view.findViewById(R.id.windows).setOnClickListener(button -> {
            dismissMenu();
            showWindows();
        });

        view.findViewById(R.id.escape).setOnClickListener(button -> {
            dismissMenu();
            sendEscape();
        });

        view.findViewById(R.id.redraw).setOnClickListener(button -> {
            dismissMenu();
            BrovanNative.requestRepaint();
        });

        View debuggerButton = view.findViewById(R.id.debugger);
        debuggerButton.setVisibility(developerMode ? View.VISIBLE : View.GONE);
        debuggerButton.setOnClickListener(button -> {
            dismissMenu();
            toggleDebugger();
        });

        view.findViewById(R.id.quit).setOnClickListener(button -> {
            dismissMenu();
            quit();
        });
    }

    private void resize(View sheet) {
        DisplayMetrics metrics = getResources().getDisplayMetrics();
        float bounded = Math.max(MENU_MIN_DP * metrics.density,
                Math.min(metrics.widthPixels * MENU_FRACTION, MENU_MAX_DP * metrics.density));

        ViewGroup.LayoutParams params = sheet.getLayoutParams();
        params.width = Math.round(Math.min(bounded, metrics.widthPixels * MENU_LIMIT));
        sheet.setLayoutParams(params);
    }

    private void dismissMenu() {
        if (menu != null) {
            menu.dismiss();
        }
    }

    // Back opens the panel, so the key it used to send has to be reachable from inside it. A guest that polls
    // the keyboard instead of reading messages misses a press with no duration.
    private void sendEscape() {
        BrovanNative.injectKey(true, VK_ESCAPE, ESCAPE_SCAN_CODE);
        ui.postDelayed(() -> BrovanNative.injectKey(false, VK_ESCAPE, ESCAPE_SCAN_CODE), KEY_HOLD_MS);
    }

    /** The slider only accepts a value that lands on one of its steps. */
    private static float snapSpeed(float value) {
        float bounded = Math.max(SPEED_MIN, Math.min(value, SPEED_MAX));
        return Math.round(bounded * 10f) / 10f;
    }

    private static String formatSpeed(float value) {
        return String.format(Locale.US, "%.1fx", value);
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

        Theming.dialog(this)
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

    /**
     * The emulator only saves the JIT cache on a clean shutdown, so quitting asks the guest to close and
     * waits for {@link #onExit} instead of tearing the process down at once. A guest that ignores WM_CLOSE
     * is stopped by the emulator itself, which still unwinds through the saving path; killing the process
     * is the last resort. A second press skips straight to it.
     */
    private void quit() {
        if (quitting || !BrovanNative.isRunning()) {
            finish();
            return;
        }

        quitting = true;
        setStatus("Stopping...");
        BrovanNative.requestClose();

        // The developer-mode command loop never reports an exit; "exit" is only consumed once the guest
        // has stopped and the cache is saved, and it takes the process with it.
        if (developerMode) {
            BrovanNative.sendCommand("exit");
        }

        ui.postDelayed(this::forceStop, CLOSE_GRACE_MS);
    }

    private void forceStop() {
        if (isFinishing() || !BrovanNative.isRunning()) {
            return;
        }

        BrovanNative.stop();
        ui.postDelayed(this::finish, STOP_TIMEOUT_MS);
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
            if (!developerMode || quitting) {
                finish();
            }
        });
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
