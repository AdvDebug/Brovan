package dev.brovan.app;

import android.animation.ValueAnimator;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.OvershootInterpolator;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.materialswitch.MaterialSwitch;
import com.google.android.material.progressindicator.LinearProgressIndicator;
import com.google.android.material.snackbar.Snackbar;
import com.google.android.material.textfield.TextInputEditText;

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
    private static final String STATE_ISO = "iso";

    /** Roughly what the extracted Windows files occupy; the download needs headroom on top. */
    private static final long WINDOWS_BYTES = 8L << 30;

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final List<View> dots = new ArrayList<>();

    private Library library;
    private Settings settings;
    private ViewGroup host;
    private LinearProgressIndicator progress;
    private TextView stepLabel;
    private MaterialButton back;
    private MaterialButton next;
    private MaterialButton skip;
    private View page;
    private int index;
    private boolean busy;

    private Uri iso;
    private TextView isoLabel;
    private TextView programState;
    private LinearProgressIndicator programProgress;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_setup);

        library = new Library(this);
        settings = new Settings(this);

        host = findViewById(R.id.setup_page);
        progress = findViewById(R.id.setup_progress);
        stepLabel = findViewById(R.id.setup_step_label);
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

        buildDots();

        if (savedInstanceState != null) {
            String saved = savedInstanceState.getString(STATE_ISO);
            iso = saved == null ? null : Uri.parse(saved);
        }

        go(savedInstanceState == null ? 0 : savedInstanceState.getInt(STATE_INDEX), true);
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putInt(STATE_INDEX, index);
        outState.putString(STATE_ISO, iso == null ? null : iso.toString());
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
        isoLabel = null;
        programState = null;
        programProgress = null;

        View incoming = LayoutInflater.from(this).inflate(PAGES[index], host, false);
        bind(incoming);
        swap(incoming, forward);
        updateChrome();
    }

    private void bind(View target) {
        switch (index) {
            case 0:
                bindWelcome(target);
                break;
            case 1:
                bindWindows(target);
                break;
            case 2:
                bindRuntimes(target);
                break;
            case 3:
                bindProgram(target);
                break;
            default:
                bindReady(target);
                break;
        }
    }

    private void bindWelcome(View target) {
        feature(target, R.id.feature_programs, R.drawable.ic_windows,
                R.string.setup_welcome_programs, R.string.setup_welcome_programs_body);
        feature(target, R.id.feature_graphics, R.drawable.ic_play,
                R.string.setup_welcome_graphics, R.string.setup_welcome_graphics_body);
        feature(target, R.id.feature_controls, R.drawable.ic_settings,
                R.string.setup_welcome_controls, R.string.setup_welcome_controls_body);
    }

    private void feature(View target, int id, int iconId, int titleId, int bodyId) {
        View row = target.findViewById(id);
        ((ImageView) row.findViewById(R.id.feature_icon)).setImageResource(iconId);
        ((TextView) row.findViewById(R.id.feature_title)).setText(titleId);
        ((TextView) row.findViewById(R.id.feature_body)).setText(bodyId);
    }

    private void bindWindows(View target) {
        TextView state = target.findViewById(R.id.windows_state);
        MaterialSwitch licensed = target.findViewById(R.id.windows_licensed);
        TextInputEditText source = target.findViewById(R.id.windows_source);
        MaterialButton install = target.findViewById(R.id.windows_install);
        LinearProgressIndicator bar = target.findViewById(R.id.windows_progress);
        TextView detail = target.findViewById(R.id.windows_progress_text);

        showWindowsState(state);

        isoLabel = target.findViewById(R.id.windows_iso);
        showIso();

        target.findViewById(R.id.windows_open_page).setOnClickListener(button -> openMicrosoft());
        target.findViewById(R.id.windows_choose).setOnClickListener(button ->
                pick(new Intent(Intent.ACTION_OPEN_DOCUMENT)
                        .addCategory(Intent.CATEGORY_OPENABLE)
                        .setType("*/*"), REQUEST_ISO));

        install.setOnClickListener(button -> {
            if (!licensed.isChecked()) {
                shake(licensed);
                snack(getString(R.string.windows_needs_license));
                return;
            }

            CharSequence typed = source.getText();
            String url = typed == null || typed.toString().trim().isEmpty() ? null : typed.toString().trim();

            startWork(install, bar, detail, R.string.windows_working);
            WindowsInstall.windows(this, worker, url, iso, new WindowsInstall.Listener() {
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
                    finishWork(install, bar, detail, status, R.string.windows_done);
                    showWindowsState(state);
                    pulse(state);
                }
            });
        });
    }

    private void bindRuntimes(View target) {
        TextView state = target.findViewById(R.id.runtimes_state);
        MaterialButton install = target.findViewById(R.id.runtimes_install);
        LinearProgressIndicator bar = target.findViewById(R.id.runtimes_progress);
        TextView detail = target.findViewById(R.id.runtimes_progress_text);

        showRuntimesState(state, install);

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
                    showRuntimesState(state, install);
                    pulse(state);
                }
            });
        });
    }

    private void bindProgram(View target) {
        programState = target.findViewById(R.id.program_state);
        programProgress = target.findViewById(R.id.program_progress);

        showProgramState(programState);

        target.findViewById(R.id.program_folder).setOnClickListener(button ->
                pick(new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE), REQUEST_FOLDER));
        target.findViewById(R.id.program_file).setOnClickListener(button ->
                pick(new Intent(Intent.ACTION_OPEN_DOCUMENT)
                        .addCategory(Intent.CATEGORY_OPENABLE)
                        .setType("*/*"), REQUEST_FILE));
    }

    private void bindReady(View target) {
        boolean windows = WindowsInstall.filesPresent(this);
        boolean runtimes = WindowsInstall.runtimesPresent(this);
        boolean programs = !library.list().isEmpty();
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

        StringBuilder text = new StringBuilder();
        text.append(getString(R.string.setup_device_storage, formatSize(free)));

        if (free < WINDOWS_BYTES) {
            text.append('\n').append(getString(R.string.setup_device_storage_low, formatSize(WINDOWS_BYTES)));
        }

        boolean vulkan = getPackageManager().hasSystemFeature(PackageManager.FEATURE_VULKAN_HARDWARE_VERSION);
        text.append('\n').append(getString(vulkan ? R.string.setup_device_vulkan : R.string.setup_device_no_vulkan));
        text.append('\n').append(getString(R.string.setup_device_android, Build.VERSION.RELEASE, Build.MODEL));

        return text;
    }

    private void showWindowsState(TextView chip) {
        boolean present = WindowsInstall.filesPresent(this);
        chip.setText(present ? R.string.setup_windows_state_installed : R.string.setup_windows_state_missing);
        chip.setTextColor(color(present ? R.color.log_ok : R.color.text_secondary));
    }

    private void showRuntimesState(TextView chip, MaterialButton action) {
        boolean present = WindowsInstall.runtimesPresent(this);
        chip.setText(present ? R.string.windows_runtimes_installed : R.string.windows_runtimes_missing);
        chip.setTextColor(color(present ? R.color.log_ok : R.color.text_secondary));
        action.setText(present ? R.string.windows_runtimes_again : R.string.windows_runtimes);
    }

    private void showProgramState(TextView chip) {
        int count = library.list().size();
        chip.setText(count == 0
                ? getString(R.string.setup_program_none)
                : getString(R.string.setup_program_count, count));
        chip.setTextColor(color(count == 0 ? R.color.text_secondary : R.color.log_ok));
    }

    private void showIso() {
        if (isoLabel == null || iso == null) {
            return;
        }

        isoLabel.setText(getString(R.string.windows_chosen, iso.getLastPathSegment()));
        reveal(isoLabel);
    }

    private void openMicrosoft() {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW,
                    Uri.parse("https://www.microsoft.com/software-download/windows11")));
        } catch (ActivityNotFoundException missing) {
            snack(getString(R.string.setup_no_browser));
        }
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
            iso = uri;
            showIso();
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
        new AlertDialog.Builder(this)
                .setTitle(R.string.library_pick_executable)
                .setItems(options, (dialog, choice) -> commit(result.directory, result.executables.get(choice), state))
                .setOnCancelListener(dialog -> library.discard(result.directory))
                .show();
    }

    private void commit(File directory, String executable, TextView state) {
        try {
            library.commit(directory, executable);
            showProgramState(state);
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

    private void updateChrome() {
        stepLabel.setText(getString(R.string.setup_step_of, index + 1, PAGES.length));
        progress.setProgressCompat((index + 1) * 100 / PAGES.length, true);
        next.setText(index == PAGES.length - 1 ? R.string.setup_finish : R.string.setup_continue);
        back.setVisibility(index == 0 ? View.INVISIBLE : View.VISIBLE);
        skip.setVisibility(index == PAGES.length - 1 ? View.INVISIBLE : View.VISIBLE);
        updateDots();
    }

    private void buildDots() {
        LinearLayout row = findViewById(R.id.setup_dots);

        for (int i = 0; i < PAGES.length; i++) {
            View dot = new View(this);
            LinearLayout.LayoutParams size = new LinearLayout.LayoutParams(dp(8), dp(8));
            size.setMarginStart(dp(4));
            size.setMarginEnd(dp(4));
            dot.setLayoutParams(size);
            dot.setBackgroundResource(R.drawable.bg_dot);
            row.addView(dot);
            dots.add(dot);
        }
    }

    private void updateDots() {
        for (int i = 0; i < dots.size(); i++) {
            View dot = dots.get(i);
            boolean active = i == index;

            dot.setBackgroundTintList(ColorStateList.valueOf(color(active ? R.color.accent : R.color.outline)));
            widen(dot, dp(active ? 22 : 8));
        }
    }

    private void widen(View dot, int target) {
        int current = dot.getLayoutParams().width;
        if (current == target) {
            return;
        }

        ValueAnimator animator = ValueAnimator.ofInt(current, target);
        animator.setDuration(260);
        animator.setInterpolator(new DecelerateInterpolator());
        animator.addUpdateListener(step -> {
            dot.getLayoutParams().width = (int) step.getAnimatedValue();
            dot.requestLayout();
        });
        animator.start();
    }

    private void swap(View incoming, boolean forward) {
        View outgoing = page;
        int shift = dp(forward ? 40 : -40);

        incoming.setAlpha(0f);
        incoming.setTranslationX(shift);
        host.addView(incoming);
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
            row.setTranslationY(dp(18));
            row.animate()
                    .alpha(1f)
                    .translationY(0f)
                    .setStartDelay(110 + i * 45L)
                    .setDuration(280)
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
        target.setScaleX(0.9f);
        target.setScaleY(0.9f);
        target.animate().scaleX(1f).scaleY(1f).setDuration(320)
                .setInterpolator(new OvershootInterpolator()).start();
    }

    private void shake(View target) {
        float distance = dp(8);
        target.animate().translationX(distance).setDuration(60)
                .withEndAction(() -> target.animate().translationX(-distance).setDuration(120)
                        .withEndAction(() -> target.animate().translationX(0f).setDuration(60).start())
                        .start())
                .start();
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
