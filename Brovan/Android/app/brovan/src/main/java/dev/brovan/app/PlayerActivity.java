package dev.brovan.app;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
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
import dev.brovan.input.ControlOverlay;

/**
 * Runs one program full screen. It lives in its own process, so quitting reclaims everything the emulator
 * allocated and the next launch starts from a clean state.
 */
public class PlayerActivity extends AppCompatActivity implements BrovanNative.Listener {

    private static final String EXTRA_DIRECTORY = "directory";
    private static final String EXTRA_EXECUTABLE = "executable";
    private static final String EXTRA_NAME = "name";
    private static final String EXTRA_NETWORK = "network";
    private static final String EXTRA_DEVELOPER = "developer";
    private static final String EXTRA_CONTROLS = "controls";
    private static final String EXTRA_JIT_CACHE = "jit_cache";

    private static final int MAX_LINES = 1200;
    private static final int TRIM_CHUNK = 200;

    private final ArrayDeque<CharSequence> lines = new ArrayDeque<>();

    private BrovanSurfaceView surface;
    private ControlOverlay controls;
    private Settings settings;
    private View console;
    private TextView status;
    private TextView log;
    private ScrollView logScroll;
    private boolean developerMode;

    static Intent intentFor(Context context, Program program, Settings settings) {
        return new Intent(context, PlayerActivity.class)
                .putExtra(EXTRA_DIRECTORY, program.directory().getAbsolutePath())
                .putExtra(EXTRA_EXECUTABLE, program.executable().getAbsolutePath())
                .putExtra(EXTRA_NAME, program.name())
                .putExtra(EXTRA_NETWORK, settings.network())
                .putExtra(EXTRA_DEVELOPER, settings.developerMode())
                .putExtra(EXTRA_CONTROLS, settings.controlScheme())
                .putExtra(EXTRA_JIT_CACHE, settings.jitCache());
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        setContentView(R.layout.activity_player);

        settings = new Settings(this);
        surface = findViewById(R.id.surface);
        controls = findViewById(R.id.controls);
        console = findViewById(R.id.console);

        int scheme = getIntent().getIntExtra(EXTRA_CONTROLS, 0);
        controls.apply(ControlOverlay.Scheme.values()[scheme]);
        status = findViewById(R.id.status);
        log = findViewById(R.id.log);
        logScroll = findViewById(R.id.log_scroll);

        developerMode = getIntent().getBooleanExtra(EXTRA_DEVELOPER, false);

        FloatingActionButton menu = findViewById(R.id.menu);
        menu.setOnClickListener(view -> showMenu());

        EditText command = findViewById(R.id.command);
        findViewById(R.id.send).setOnClickListener(view -> {
            String text = command.getText().toString().trim();
            if (!text.isEmpty()) {
                append("[/] > " + text);
                command.setText("");
                BrovanNative.sendCommand(text);
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

        // Developer mode leaves the guest at the debugger prompt instead of running it, so the console has to
        // be up for the "start" that gets it going to be reachable.
        if (developerMode) {
            console.setVisibility(View.VISIBLE);
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

    private void showMenu() {
        List<String> labels = new ArrayList<>();
        List<Runnable> actions = new ArrayList<>();

        labels.add(getString(R.string.player_controls));
        actions.add(this::showControlSchemes);

        labels.add(getString(R.string.player_windows));
        actions.add(this::showWindows);

        labels.add(getString(R.string.player_redraw));
        actions.add(BrovanNative::requestRepaint);

        if (developerMode) {
            labels.add(getString(R.string.player_console));
            actions.add(this::toggleConsole);
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
                    console.setVisibility(View.GONE);
                    surface.requestFocus();
                })
                .show();
    }

    private void toggleConsole() {
        boolean visible = console.getVisibility() == View.VISIBLE;
        console.setVisibility(visible ? View.GONE : View.VISIBLE);
        if (visible) {
            surface.requestFocus();
            BrovanNative.requestRepaint();
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
        console.setVisibility(View.VISIBLE);
        setStatus(message);
    }

    private void setStatus(String value) {
        runOnUiThread(() -> status.setText(value));
    }

    private void append(String line) {
        SpannableString styled = new SpannableString(line);
        styled.setSpan(new ForegroundColorSpan(colorFor(line)), 0, line.length(),
                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);

        runOnUiThread(() -> {
            lines.addLast(styled);
            if (lines.size() > MAX_LINES) {
                for (int i = 0; i < TRIM_CHUNK && !lines.isEmpty(); i++) {
                    lines.removeFirst();
                }

                SpannableStringBuilder builder = new SpannableStringBuilder();
                for (CharSequence entry : lines) {
                    builder.append(entry).append("\n");
                }
                log.setText(builder);
            } else {
                log.append(styled);
                log.append("\n");
            }

            logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
        });
    }

    private int colorFor(String line) {
        if (line.startsWith("[-]") || line.startsWith("[!!]")) return ContextCompat.getColor(this, R.color.log_error);
        if (line.startsWith("[+]")) return ContextCompat.getColor(this, R.color.log_ok);
        if (line.startsWith("[!]")) return ContextCompat.getColor(this, R.color.log_warn);
        if (line.startsWith("[#]")) return ContextCompat.getColor(this, R.color.log_info);
        return ContextCompat.getColor(this, R.color.text_primary);
    }

    @Override
    public void onLog(String line) {
        if (developerMode) {
            append(line);
        }
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
        if (console.getVisibility() == View.VISIBLE) {
            toggleConsole();
            return;
        }

        quit();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();

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
