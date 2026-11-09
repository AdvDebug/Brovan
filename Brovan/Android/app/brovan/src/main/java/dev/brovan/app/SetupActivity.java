package dev.brovan.app;

import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.drawable.Animatable;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.ColorUtils;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.progressindicator.LinearProgressIndicator;
import com.google.android.material.snackbar.Snackbar;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import dev.brovan.BrovanNative;

/** The first-run wizard: one thing to do per page, in the order the emulator needs them. */
public class SetupActivity extends AppCompatActivity {

    private static final int REQUEST_ISO = 1;
    private static final int REQUEST_FOLDER = 2;
    private static final int REQUEST_FILE = 3;

    private static final int[] PAGES = {
            R.layout.setup_page_welcome,
            R.layout.setup_page_windows,
            R.layout.setup_page_runtimes,
            R.layout.setup_page_program,
            R.layout.setup_page_ready};

    private static final String STATE_INDEX = "index";

    /** Roughly what the extracted Windows files occupy; the download needs headroom on top. */
    private static final long WINDOWS_BYTES = 8L << 30;

    private static final int[][] ENABLED_STATES = {{-android.R.attr.state_enabled}, {}};
    // Material 3 disabled opacities, 12% for the container and 38% for the label.
    private static final int DISABLED_FILL_ALPHA = 31;
    private static final int DISABLED_TEXT_ALPHA = 97;

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final List<View> steps = new ArrayList<>();

    private Library library;
    private Settings settings;
    private Palette palette;
    private ViewGroup host;
    private View back;
    private MaterialButton next;
    private MaterialButton skip;
    private View page;
    private int index;
    private boolean busy;
    private ButtonColors filled;
    private ButtonColors tonal;

    private MaterialButton stepAction;
    private TextView programState;
    private LinearProgressIndicator programProgress;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        settings = new Settings(this);
        palette = settings.palette();
        Theming.install(this, palette);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_setup);

        Theming.apply(this, Palette.defaults(), palette);

        library = new Library(this);

        int accent = palette.get(Palette.Role.ACCENT);
        int text = palette.get(Palette.Role.TEXT_PRIMARY);
        filled = new ButtonColors(accent, palette.get(Palette.Role.ON_ACCENT), text);
        tonal = new ButtonColors(ColorUtils.setAlphaComponent(accent, Color.alpha(color(R.color.accent_wash))), text,
                text);

        host = findViewById(R.id.setup_page);
        back = findViewById(R.id.setup_back);
        next = findViewById(R.id.setup_next);
        skip = findViewById(R.id.setup_skip);

        back.setOnClickListener(button -> go(index - 1, false));
        next.setOnClickListener(button -> {
            if (index == PAGES.length - 1) {
                done();
            } else {
                go(index + 1, true);
            }
        });
        skip.setOnClickListener(button -> done());

        buildSteps();
        go(savedInstanceState == null ? 0 : savedInstanceState.getInt(STATE_INDEX), true);
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putInt(STATE_INDEX, index);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        BrovanNative.setInstallListener(null);
        worker.shutdownNow();
    }

    @Override
    public void onBackPressed() {
        if (busy) {
            return;
        }

        if (index > 0) {
            go(index - 1, false);
            return;
        }

        super.onBackPressed();
    }

    private void done() {
        settings.setSetupDismissed(true);
        finish();
    }

    private void go(int target, boolean forward) {
        if (busy || target < 0 || target >= PAGES.length) {
            return;
        }

        index = target;
        stepAction = null;
        programState = null;
        programProgress = null;

        View incoming = LayoutInflater.from(this).inflate(PAGES[index], host, false);
        boolean done = bind(incoming);
        swap(incoming, forward);
        startArt(incoming);
        updateChrome(done);
    }

    private void startArt(View target) {
        ImageView art = target.findViewById(R.id.page_art);
        if (art == null) {
            return;
        }

        Drawable drawable = art.getDrawable();
        if (drawable instanceof Animatable) {
            art.postDelayed(((Animatable) drawable)::start, 400);
        }
    }

    private boolean bind(View target) {
        switch (index) {
            case 0:
                return true;
            case 1:
                return bindWindows(target);
            case 2:
                return bindRuntimes(target);
            case 3:
                return bindProgram(target);
            default:
                bindReady(target);
                return true;
        }
    }

    private boolean bindWindows(View target) {
        stepAction = target.findViewById(R.id.windows_iso_pick);
        stepAction.setOnClickListener(button -> {
            if (!busy) {
                pick(new Intent(Intent.ACTION_OPEN_DOCUMENT)
                        .addCategory(Intent.CATEGORY_OPENABLE)
                        .setType("*/*"), REQUEST_ISO);
            }
        });

        target.findViewById(R.id.windows_get_iso).setOnClickListener(button -> {
            try {
                startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(getString(R.string.windows_download_url))));
            } catch (ActivityNotFoundException missing) {
                snack(getString(R.string.no_browser));
            }
        });

        return showWindowsState(target.findViewById(R.id.windows_state));
    }

    private void installWindows(Uri isoFile) {
        View target = page;
        TextView state = target.findViewById(R.id.windows_state);
        MaterialButton pick = target.findViewById(R.id.windows_iso_pick);
        LinearProgressIndicator bar = target.findViewById(R.id.windows_progress);
        TextView detail = target.findViewById(R.id.windows_progress_text);

        startWork(pick, bar, detail, R.string.windows_working);
        WindowsInstall.windows(this, worker, isoFile, new WindowsInstall.Listener() {
            @Override
            public void onProgress(long filesDone, long filesTotal, long bytesDone, long bytesTotal) {
                if (filesTotal <= 0) {
                    return;
                }

                advance(bar, filesDone, filesTotal);
                detail.setText(getString(R.string.setup_progress_files,
                        filesDone, filesTotal, bytesDone >> 20, bytesTotal >> 20));
            }

            @Override
            public void onFinished(int status) {
                finishWork(pick, bar, detail, status, R.string.windows_done);
                refreshEmphasis(showWindowsState(state));
                pulse(state);
            }
        });
    }

    private boolean bindRuntimes(View target) {
        TextView state = target.findViewById(R.id.runtimes_state);
        MaterialButton install = target.findViewById(R.id.runtimes_install);
        LinearProgressIndicator bar = target.findViewById(R.id.runtimes_progress);
        TextView detail = target.findViewById(R.id.runtimes_progress_text);
        stepAction = install;

        install.setOnClickListener(button -> {
            startWork(install, bar, detail, R.string.windows_runtimes_working);
            WindowsInstall.runtimes(this, worker, new WindowsInstall.Listener() {
                @Override
                public void onProgress(long filesDone, long filesTotal, long bytesDone, long bytesTotal) {
                    // The package sizes only arrive with the Visual Studio manifest, so the bar stays
                    // indeterminate until the native side reports a byte total.
                    if (bytesTotal <= 0) {
                        detail.setText(getString(R.string.setup_progress_downloaded, bytesDone >> 20));
                        return;
                    }

                    advance(bar, bytesDone, bytesTotal);
                    detail.setText(getString(R.string.setup_progress_bytes, bytesDone >> 20, bytesTotal >> 20));
                }

                @Override
                public void onFinished(int status) {
                    finishWork(install, bar, detail, status, R.string.windows_runtimes_done);
                    refreshEmphasis(showRuntimesState(state, install));
                    pulse(state);
                }
            });
        });

        return showRuntimesState(state, install);
    }

    private boolean bindProgram(View target) {
        programState = target.findViewById(R.id.program_state);
        programProgress = target.findViewById(R.id.program_progress);
        stepAction = target.findViewById(R.id.program_folder);

        stepAction.setOnClickListener(button ->
                pick(new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE), REQUEST_FOLDER));
        target.findViewById(R.id.program_file).setOnClickListener(button ->
                pick(new Intent(Intent.ACTION_OPEN_DOCUMENT)
                        .addCategory(Intent.CATEGORY_OPENABLE)
                        .setType("*/*"), REQUEST_FILE));

        return showProgramState(programState);
    }

    private void bindReady(View target) {
        boolean windows = WindowsInstall.filesPresent(this);
        boolean runtimes = WindowsInstall.runtimesPresent(this);
        boolean programs = librarySize() != 0;
        boolean ready = windows && runtimes && programs;

        ((TextView) target.findViewById(R.id.ready_title))
                .setText(ready ? R.string.setup_ready_title : R.string.setup_almost_title);
        ((TextView) target.findViewById(R.id.ready_body))
                .setText(ready ? R.string.setup_ready_body : R.string.setup_almost_body);

        readyRow(target.findViewById(R.id.ready_windows), windows, R.string.setup_ready_windows);
        readyRow(target.findViewById(R.id.ready_runtimes), runtimes, R.string.setup_ready_runtimes);
        readyRow(target.findViewById(R.id.ready_program), programs, R.string.setup_ready_program);

        ((TextView) target.findViewById(R.id.ready_device)).setText(describeDevice());
    }

    private void readyRow(TextView row, boolean done, int labelId) {
        row.setText(getString(done ? R.string.setup_mark_done : R.string.setup_mark_todo)
                + "   " + getString(labelId));
        row.setTextColor(color(done ? R.color.log_ok : R.color.text_secondary));
    }

    private CharSequence describeDevice() {
        long free = getFilesDir().getUsableSpace();
        boolean vulkan = getPackageManager().hasSystemFeature(PackageManager.FEATURE_VULKAN_HARDWARE_VERSION);

        StringBuilder text = new StringBuilder();
        text.append(getString(R.string.setup_device_storage, formatSize(free)));
        text.append(" · ").append(getString(vulkan ? R.string.setup_device_vulkan : R.string.setup_device_no_vulkan));

        if (free < WINDOWS_BYTES) {
            text.append('\n').append(getString(R.string.setup_device_storage_low, formatSize(WINDOWS_BYTES)));
        }

        return text;
    }

    private boolean showWindowsState(TextView chip) {
        boolean present = WindowsInstall.filesPresent(this);
        chip.setText(present ? R.string.setup_windows_state_installed : R.string.setup_windows_state_missing);
        chip.setTextColor(color(present ? R.color.log_ok : R.color.text_secondary));
        return present;
    }

    private boolean showRuntimesState(TextView chip, MaterialButton action) {
        boolean present = WindowsInstall.runtimesPresent(this);
        chip.setText(present ? R.string.windows_runtimes_installed : R.string.windows_runtimes_missing);
        chip.setTextColor(color(present ? R.color.log_ok : R.color.text_secondary));
        action.setText(present ? R.string.windows_runtimes_again : R.string.windows_runtimes);
        return present;
    }

    private boolean showProgramState(TextView chip) {
        int count = librarySize();
        chip.setText(count == 0
                ? getString(R.string.setup_program_none)
                : getString(R.string.setup_program_count, count));
        chip.setTextColor(color(count == 0 ? R.color.text_secondary : R.color.log_ok));
        return count != 0;
    }

    private void pick(Intent intent, int requestCode) {
        try {
            startActivityForResult(intent, requestCode);
        } catch (ActivityNotFoundException missing) {
            snack(getString(R.string.setup_no_picker));
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (resultCode != RESULT_OK || data == null || data.getData() == null) {
            return;
        }

        Uri uri = data.getData();

        if (requestCode == REQUEST_ISO) {
            installWindows(uri);
            return;
        }

        if (requestCode == REQUEST_FOLDER || requestCode == REQUEST_FILE) {
            importProgram(uri, requestCode == REQUEST_FOLDER);
        }
    }

    private void importProgram(Uri uri, boolean folder) {
        TextView state = programState;
        LinearProgressIndicator bar = programProgress;
        if (state == null || bar == null) {
            return;
        }

        busy(true);
        reveal(bar);

        worker.execute(() -> {
            try {
                Library.ImportResult result = folder
                        ? library.importFolder(this, uri)
                        : library.importExecutable(this, uri);

                runOnUiThread(() -> {
                    bar.setVisibility(View.GONE);
                    busy(false);
                    finishImport(result, state);
                });
            } catch (Exception failure) {
                runOnUiThread(() -> {
                    bar.setVisibility(View.GONE);
                    busy(false);
                    snack(getString(R.string.setup_import_failed, failure.getMessage()));
                });
            }
        });
    }

    private void finishImport(Library.ImportResult result, TextView state) {
        if (result.executables.isEmpty()) {
            library.discard(result.directory);
            snack(getString(R.string.setup_no_executable));
            return;
        }

        if (result.executables.size() == 1) {
            commit(result.directory, result.executables.get(0), state);
            return;
        }

        CharSequence[] options = result.executables.toArray(new CharSequence[0]);
        Theming.dialog(this)
                .setTitle(R.string.library_pick_executable)
                .setItems(options, (dialog, choice) -> commit(result.directory, result.executables.get(choice), state))
                .setOnCancelListener(dialog -> library.discard(result.directory))
                .show();
    }

    private void commit(File directory, String executable, TextView state) {
        try {
            library.commit(directory, executable);
            refreshEmphasis(showProgramState(state));
            pulse(state);
        } catch (Exception failure) {
            snack(getString(R.string.setup_import_failed, failure.getMessage()));
        }
    }

    private void startWork(MaterialButton action, LinearProgressIndicator bar, TextView detail, int messageId) {
        busy(true);
        action.setEnabled(false);
        bar.setIndeterminate(true);
        reveal(bar);
        detail.setTextColor(color(R.color.text_secondary));
        detail.setText(messageId);
        reveal(detail);
    }

    private void finishWork(MaterialButton action, LinearProgressIndicator bar, TextView detail, int status,
                            int doneId) {
        boolean ok = status == BrovanNative.STATUS_OK;

        busy(false);
        action.setEnabled(true);
        bar.setVisibility(View.GONE);
        detail.setText(ok ? getString(doneId) : getString(R.string.windows_failed));
        detail.setTextColor(color(ok ? R.color.log_ok : R.color.log_error));
    }

    private void advance(LinearProgressIndicator bar, long done, long total) {
        if (bar.isIndeterminate()) {
            bar.setIndeterminate(false);
            bar.setMax(1000);
        }

        bar.setProgressCompat((int) (done * 1000 / total), true);
    }

    private void busy(boolean value) {
        busy = value;
        back.setEnabled(!value);
        next.setEnabled(!value);
        skip.setEnabled(!value);
    }

    private void updateChrome(boolean done) {
        back.setVisibility(index == 0 ? View.INVISIBLE : View.VISIBLE);
        skip.setVisibility(index == PAGES.length - 1 ? View.INVISIBLE : View.VISIBLE);

        ColorStateList reached = ColorStateList.valueOf(palette.get(Palette.Role.ACCENT));
        ColorStateList ahead = ColorStateList.valueOf(palette.get(Palette.Role.OUTLINE));
        for (int i = 0; i < steps.size(); i++) {
            steps.get(i).setBackgroundTintList(i <= index ? reached : ahead);
        }
        refreshEmphasis(done);
    }

    private void buildSteps() {
        LinearLayout row = findViewById(R.id.setup_steps);

        for (int i = 0; i < PAGES.length; i++) {
            View step = new View(this);
            LinearLayout.LayoutParams size = new LinearLayout.LayoutParams(0, dp(4), 1f);
            size.setMarginStart(dp(2));
            size.setMarginEnd(dp(2));
            step.setLayoutParams(size);
            step.setBackgroundResource(R.drawable.bg_dot);
            row.addView(step);
            steps.add(step);
        }
    }

    private void refreshEmphasis(boolean done) {
        if (stepAction != null) {
            emphasize(stepAction, !done);
        }
        emphasize(next, done);

        if (index == 0) {
            next.setText(R.string.setup_get_started);
        } else if (index == PAGES.length - 1) {
            next.setText(R.string.setup_finish);
        } else {
            next.setText(done ? R.string.setup_continue : R.string.setup_skip_step);
        }
    }

    private void emphasize(MaterialButton button, boolean emphasized) {
        ButtonColors colors = emphasized ? filled : tonal;
        button.setBackgroundTintList(colors.fill);
        button.setTextColor(colors.text);
    }

    private static final class ButtonColors {
        final ColorStateList fill;
        final ColorStateList text;

        ButtonColors(int fill, int text, int disabledBase) {
            this.fill = new ColorStateList(ENABLED_STATES, new int[]{
                    ColorUtils.setAlphaComponent(disabledBase, DISABLED_FILL_ALPHA), fill});
            this.text = new ColorStateList(ENABLED_STATES, new int[]{
                    ColorUtils.setAlphaComponent(disabledBase, DISABLED_TEXT_ALPHA), text});
        }
    }

    private void swap(View incoming, boolean forward) {
        View outgoing = page;
        int shift = dp(forward ? 20 : -20);

        incoming.setAlpha(0f);
        incoming.setTranslationX(shift);
        host.addView(incoming);
        Theming.apply(incoming, Palette.defaults(), palette);
        incoming.animate()
                .alpha(1f)
                .translationX(0f)
                .setStartDelay(outgoing == null ? 0 : 70)
                .setDuration(260)
                .setInterpolator(new DecelerateInterpolator())
                .start();

        if (outgoing != null) {
            outgoing.animate()
                    .alpha(0f)
                    .translationX(-shift)
                    .setDuration(150)
                    .setInterpolator(new AccelerateInterpolator())
                    .withEndAction(() -> host.removeView(outgoing))
                    .start();
        }

        page = incoming;
        stagger(incoming);
    }

    /// Each row of the incoming page arrives on its own beat, so the page reads top to bottom.
    private void stagger(View target) {
        View column = target.findViewById(R.id.page_column);
        if (!(column instanceof ViewGroup)) {
            return;
        }

        ViewGroup rows = (ViewGroup) column;
        for (int i = 0; i < rows.getChildCount(); i++) {
            View row = rows.getChildAt(i);
            row.setAlpha(0f);
            row.setTranslationY(dp(10));
            row.animate()
                    .alpha(1f)
                    .translationY(0f)
                    .setStartDelay(100 + i * 60L)
                    .setDuration(320)
                    .setInterpolator(new DecelerateInterpolator())
                    .start();
        }
    }

    private void reveal(View target) {
        if (target.getVisibility() == View.VISIBLE) {
            return;
        }

        target.setAlpha(0f);
        target.setTranslationY(dp(8));
        target.setVisibility(View.VISIBLE);
        target.animate().alpha(1f).translationY(0f).setDuration(200)
                .setInterpolator(new DecelerateInterpolator()).start();
    }

    private void pulse(View target) {
        target.setAlpha(0.4f);
        target.setScaleX(0.97f);
        target.setScaleY(0.97f);
        target.animate().alpha(1f).scaleX(1f).scaleY(1f).setDuration(280)
                .setInterpolator(new DecelerateInterpolator()).start();
    }

    private int librarySize() {
        try {
            return library.list().size();
        } catch (java.io.IOException failure) {
            snack(failure.getMessage());
            return 0;
        }
    }

    private int color(int id) {
        return ContextCompat.getColor(this, id);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private static String formatSize(long bytes) {
        return String.format(Locale.US, "%.1f GB", bytes / (double) (1L << 30));
    }

    private void snack(String message) {
        Snackbar.make(host, message, Snackbar.LENGTH_LONG).show();
    }
}
