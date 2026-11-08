package dev.brovan.app;

import android.content.ActivityNotFoundException;
import android.app.ActivityManager;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.text.Editable;
import android.text.SpannableString;
import android.text.TextWatcher;
import android.text.style.ForegroundColorSpan;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.GridLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.drawerlayout.widget.DrawerLayout;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.LinearSnapHelper;
import androidx.recyclerview.widget.PagerSnapHelper;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.SnapHelper;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.google.android.material.materialswitch.MaterialSwitch;
import com.google.android.material.navigation.NavigationView;
import com.google.android.material.progressindicator.CircularProgressIndicator;
import com.google.android.material.progressindicator.LinearProgressIndicator;
import com.google.android.material.snackbar.Snackbar;
import com.google.android.material.textfield.MaterialAutoCompleteTextView;
import com.google.android.material.textfield.TextInputLayout;

import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.IntConsumer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import dev.brovan.BrovanNative;

public class MainActivity extends AppCompatActivity {

    private static final String STATE_SCREEN = "screen";

    private static final int REQUEST_FOLDER = 1;
    private static final int REQUEST_FILE = 2;
    private static final int REQUEST_ISO = 3;

    private final ExecutorService worker = Executors.newSingleThreadExecutor();

    private Library library;
    private Settings settings;
    private Palette palette;
    private View[] roleSwatches;
    private MaterialCardView[] presetChips;
    private NavigationView navigation;
    private DrawerLayout drawer;
    private FrameLayout content;
    private MaterialToolbar toolbar;
    private ProgramAdapter adapter;
    private RecyclerView programList;
    private SnapHelper snap;
    private TextView emptyTitle;
    private TextView emptyBody;
    private View emptyState;
    private CircularProgressIndicator progress;
    private Uri selectedIso;
    private TextView isoLabel;
    private View isoImport;
    private FileBrowser files;
    private int currentScreen;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        settings = new Settings(this);
        palette = settings.palette();
        Theming.install(this, palette);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Theming.apply(this, Palette.defaults(), palette);

        library = new Library(this);

        // Refreshes the guest-side files bundled in the APK, so an app update cannot leave
        // a stale Vulkan shim behind for the new emulator to load.
        worker.execute(() -> GuestAssets.deploy(this));

        drawer = findViewById(R.id.drawer);
        paintStatusBar();
        content = findViewById(R.id.content);
        toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(view -> drawer.open());

        navigation = findViewById(R.id.navigation);
        navigation.setNavigationItemSelectedListener(item -> {
            show(item.getItemId());
            drawer.close();
            return true;
        });
        insetDrawerHeader(navigation);

        openScreen(savedInstanceState == null
                ? R.id.nav_library
                : savedInstanceState.getInt(STATE_SCREEN, R.id.nav_library));

        if (savedInstanceState == null && !windowsFilesPresent() && !settings.setupDismissed()) {
            startActivity(new Intent(this, SetupActivity.class));
        }
    }

    @Override
    protected void onResume() {
        super.onResume();

        // The wizard can import a program, so the library it hands back to is a screen behind.
        if (currentScreen == R.id.nav_library && adapter != null) {
            refresh();
        }

        // A program that ran between the two visits has written to the same storage.
        if (currentScreen == R.id.nav_files && files != null) {
            files.refresh();
        }
    }

    // The drawer layout paints the status bar, so the open drawer reaches the top edge.
    private void paintStatusBar() {
        drawer.setStatusBarBackgroundColor(palette.get(Palette.Role.BACKGROUND));
        getWindow().setStatusBarColor(Color.TRANSPARENT);
    }

    private void insetDrawerHeader(NavigationView navigation) {
        View header = navigation.getHeaderView(0);
        if (header == null) {
            return;
        }

        int basePadding = header.getPaddingTop();
        ViewCompat.setOnApplyWindowInsetsListener(header, (view, insets) -> {
            int top = insets.getInsets(WindowInsetsCompat.Type.systemBars()).top;
            view.setPadding(view.getPaddingLeft(), basePadding + top, view.getPaddingRight(),
                    view.getPaddingBottom());
            return insets;
        });
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        worker.shutdownNow();
    }

    @Override
    protected void onSaveInstanceState(@NonNull Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putInt(STATE_SCREEN, currentScreen);
    }

    private void openScreen(int itemId) {
        navigation.setCheckedItem(itemId);
        show(itemId);
    }

    private void show(int itemId) {
        content.removeAllViews();

        currentScreen = itemId;
        files = null;

        if (itemId == R.id.nav_windows) {
            toolbar.setTitle(R.string.nav_windows);
            content.addView(createWindows());
        } else if (itemId == R.id.nav_files) {
            toolbar.setTitle(R.string.nav_files);
            files = new FileBrowser(this, worker);
            content.addView(files.create(content));
        } else if (itemId == R.id.nav_theme) {
            toolbar.setTitle(R.string.nav_theme);
            content.addView(createTheme());
        } else if (itemId == R.id.nav_settings) {
            toolbar.setTitle(R.string.nav_settings);
            content.addView(createSettings());
        } else if (itemId == R.id.nav_about) {
            toolbar.setTitle(R.string.nav_about);
            content.addView(createAbout());
        } else {
            toolbar.setTitle(R.string.nav_library);
            content.addView(createLibrary());
        }

        Theming.apply(content, Palette.defaults(), palette);
    }

    private View createLibrary() {
        View view = LayoutInflater.from(this).inflate(R.layout.screen_library, content, false);

        emptyState = view.findViewById(R.id.empty);
        emptyTitle = view.findViewById(R.id.empty_title);
        emptyBody = view.findViewById(R.id.empty_body);
        progress = view.findViewById(R.id.progress);

        programList = view.findViewById(R.id.apps);
        adapter = new ProgramAdapter(new File(getCacheDir(), "icons"), worker, new ProgramAdapter.Listener() {
            @Override
            public void onLaunch(Program program) {
                launch(program);
            }

            @Override
            public void onActions(Program program) {
                showProgramActions(program);
            }
        });
        programList.setAdapter(adapter);
        applyLibraryStyle(ProgramAdapter.Style.of(settings.libraryStyle()));

        view.findViewById(R.id.add).setOnClickListener(this::showAddOptions);
        bindSearch(view);

        refresh();
        return view;
    }

    private void bindSearch(View view) {
        EditText search = view.findViewById(R.id.search);
        View clear = view.findViewById(R.id.search_clear);

        search.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence text, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence text, int start, int before, int count) {
            }

            @Override
            public void afterTextChanged(Editable text) {
                clear.setVisibility(text.length() == 0 ? View.GONE : View.VISIBLE);
                adapter.search(text.toString());
                showEmptyState();
            }
        });

        clear.setOnClickListener(button -> search.setText(""));
    }

    private void showStyles() {
        ProgramAdapter.Style[] styles = ProgramAdapter.Style.values();

        GridLayout grid = new GridLayout(this);
        grid.setColumnCount(2);
        grid.setPadding(dp(18), dp(6), dp(18), dp(2));

        AlertDialog[] dialog = new AlertDialog[1];

        for (int i = 0; i < styles.length; i++) {
            int index = i;
            View option = styleOption(styles[i]);
            option.setOnClickListener(view -> {
                settings.setLibraryStyle(index);
                if (currentScreen == R.id.nav_library) {
                    applyLibraryStyle(styles[index]);
                } else if (currentScreen == R.id.nav_theme) {
                    ((TextView) content.findViewById(R.id.library_style)).setText(styles[index].labelId());
                }
                dialog[0].dismiss();
            });

            GridLayout.LayoutParams params = new GridLayout.LayoutParams();
            params.width = 0;
            params.columnSpec = GridLayout.spec(i % 2, 1f);
            params.rowSpec = GridLayout.spec(i / 2);
            params.setMargins(dp(5), dp(5), dp(5), dp(5));
            grid.addView(option, params);
        }

        dialog[0] = Theming.dialog(this)
                .setTitle(R.string.library_style)
                .setView(grid)
                .setNegativeButton(android.R.string.cancel, null)
                .create();

        dialog[0].show();
    }

    private View styleOption(ProgramAdapter.Style style) {
        boolean chosen = style == adapter.style();
        int accent = palette.get(chosen ? Palette.Role.ACCENT : Palette.Role.TEXT_SECONDARY);

        MaterialCardView card = new MaterialCardView(this);
        card.setCardBackgroundColor(palette.get(
                chosen ? Palette.Role.SURFACE_VARIANT : Palette.Role.SURFACE));
        card.setRadius(dp(16));
        card.setCardElevation(0f);
        card.setStrokeWidth(dp(chosen ? 2 : 1));
        card.setStrokeColor(chosen ? accent : palette.get(Palette.Role.OUTLINE));
        card.setClickable(true);
        card.setFocusable(true);

        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setGravity(Gravity.CENTER_HORIZONTAL);
        body.setPadding(dp(12), dp(14), dp(12), dp(12));

        ImageView preview = new ImageView(this);
        preview.setImageResource(style.previewId());
        preview.setImageTintList(ColorStateList.valueOf(accent));
        body.addView(preview, new LinearLayout.LayoutParams(dp(54), dp(40)));

        TextView label = new TextView(this);
        label.setText(style.labelId());
        label.setTextSize(13f);
        label.setTextColor(palette.get(chosen ? Palette.Role.TEXT_PRIMARY : Palette.Role.TEXT_SECONDARY));

        LinearLayout.LayoutParams labelParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        labelParams.topMargin = dp(10);
        body.addView(label, labelParams);

        card.addView(body);
        return card;
    }

    private void applyLibraryStyle(ProgramAdapter.Style style) {
        adapter.setStyle(style);

        programList.setLayoutManager(style.horizontal()
                ? new LinearLayoutManager(this, RecyclerView.HORIZONTAL, false)
                : new GridLayoutManager(this, style.columns(widthDp())));

        if (snap != null) {
            snap.attachToRecyclerView(null);
            snap = null;
        }

        programList.clearOnScrollListeners();

        if (style == ProgramAdapter.Style.CAROUSEL) {
            snap = new PagerSnapHelper();
        } else if (style == ProgramAdapter.Style.SHELF) {
            snap = new LinearSnapHelper();
            programList.addOnScrollListener(centreFocus);
        }

        if (snap != null) {
            snap.attachToRecyclerView(programList);
        }

        applyListBounds(style);
    }

    private void applyListBounds(ProgramAdapter.Style style) {
        boolean band = style == ProgramAdapter.Style.SHELF;

        FrameLayout.LayoutParams bounds = (FrameLayout.LayoutParams) programList.getLayoutParams();
        bounds.height = band ? FrameLayout.LayoutParams.WRAP_CONTENT : FrameLayout.LayoutParams.MATCH_PARENT;
        bounds.gravity = band ? Gravity.CENTER_VERTICAL : Gravity.TOP;
        programList.setLayoutParams(bounds);

        if (!style.horizontal()) {
            programList.setPadding(dp(12), dp(4), dp(12), dp(96));
            return;
        }

        programList.setPadding(0, 0, 0, 0);
        programList.post(() -> {
            int side = Math.max(0, (programList.getWidth() - style.pageWidth(programList.getWidth())) / 2);
            programList.setPadding(side, 0, side, 0);
            centreFocus.onScrolled(programList, 0, 0);
        });
    }

    private View createWindows() {
        View view = LayoutInflater.from(this).inflate(R.layout.screen_windows, content, false);

        TextView status = view.findViewById(R.id.windows_status);
        MaterialButton install = view.findViewById(R.id.windows_install);
        LinearProgressIndicator bar = view.findViewById(R.id.windows_progress);
        TextView detail = view.findViewById(R.id.windows_progress_text);
        MaterialButton openPage = view.findViewById(R.id.windows_open_page);
        MaterialButton choose = view.findViewById(R.id.windows_choose);
        MaterialButton runtimes = view.findViewById(R.id.windows_runtimes);
        TextView runtimesStatus = view.findViewById(R.id.windows_runtimes_status);
        LinearProgressIndicator runtimesBar = view.findViewById(R.id.windows_runtimes_progress);
        TextView runtimesDetail = view.findViewById(R.id.windows_runtimes_progress_text);

        isoLabel = detail;
        isoImport = install;

        openPage.setOnClickListener(button -> {
            try {
                startActivity(new Intent(Intent.ACTION_VIEW,
                        Uri.parse("https://www.microsoft.com/software-download/windows11")));
            } catch (ActivityNotFoundException missing) {
                snack(getString(R.string.no_browser));
            }
        });

        choose.setOnClickListener(button -> pick(new Intent(Intent.ACTION_OPEN_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .setType("*/*"), REQUEST_ISO));

        showStatus(status, windowsFilesPresent());
        showRuntimeState(runtimesStatus, runtimes);
        bindDxvk(view);

        runtimes.setOnClickListener(button -> {
            startInstall(runtimesBar, runtimesDetail, R.string.windows_runtimes_working, install, runtimes);
            WindowsInstall.runtimes(this, worker, new WindowsInstall.Listener() {
                @Override
                public void onProgress(long filesDone, long filesTotal, long bytesDone, long bytesTotal) {
                    // The package sizes are only known once the Visual Studio manifest is in, so the download
                    // runs indeterminate until the native side reports a byte total.
                    if (bytesTotal <= 0) {
                        runtimesDetail.setText(getString(R.string.setup_progress_downloaded, bytesDone >> 20));
                        return;
                    }

                    advance(runtimesBar, bytesDone, bytesTotal);
                    runtimesDetail.setText(getString(R.string.setup_progress_bytes, bytesDone >> 20, bytesTotal >> 20));
                }

                @Override
                public void onFinished(int result) {
                    finishInstall(runtimesBar, runtimesDetail, result, R.string.windows_runtimes_done, install, runtimes);
                    showRuntimeState(runtimesStatus, runtimes);
                }
            });
        });

        install.setOnClickListener(button -> {
            if (selectedIso == null) {
                snack(getString(R.string.windows_needs_media));
                return;
            }

            startInstall(bar, detail, R.string.windows_working, install, runtimes);
            WindowsInstall.windows(this, worker, selectedIso, new WindowsInstall.Listener() {
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
                public void onFinished(int result) {
                    finishInstall(bar, detail, result, R.string.windows_done, install, runtimes);
                    showStatus(status, windowsFilesPresent());
                    showRuntimeState(runtimesStatus, runtimes);
                }
            });
        });

        return view;
    }

    private void startInstall(LinearProgressIndicator bar, TextView detail, int messageId,
                              MaterialButton... actions) {
        for (MaterialButton action : actions) {
            action.setEnabled(false);
        }

        setRuntimeActions(false);
        bar.setIndeterminate(true);
        bar.setVisibility(View.VISIBLE);
        detail.setVisibility(View.VISIBLE);
        detail.setText(messageId);
    }

    private void finishInstall(LinearProgressIndicator bar, TextView detail, int result, int doneId,
                               MaterialButton... actions) {
        for (MaterialButton action : actions) {
            action.setEnabled(true);
        }

        setRuntimeActions(true);
        bar.setVisibility(View.GONE);
        detail.setText(result == BrovanNative.STATUS_OK ? getString(doneId) : getString(R.string.windows_failed));
    }

    private void setRuntimeActions(boolean enabled) {
        if (currentScreen != R.id.nav_windows) {
            return;
        }
        for (int id : new int[]{R.id.windows_install, R.id.windows_runtimes, R.id.dxvk_install}) {
            View action = content.findViewById(id);
            if (action != null) {
                action.setEnabled(enabled);
            }
        }
    }

    private void advance(LinearProgressIndicator bar, long done, long total) {
        if (bar.isIndeterminate()) {
            bar.setIndeterminate(false);
            bar.setMax(1000);
        }

        bar.setProgressCompat((int) (done * 1000 / total), true);
    }

    private boolean windowsFilesPresent() {
        return WindowsInstall.filesPresent(this);
    }

    private void showRuntimeState(TextView status, MaterialButton action) {
        boolean present = WindowsInstall.runtimesPresent(this);

        showStatus(status, present);
        action.setText(present ? R.string.runtime_update : R.string.runtime_install);
        action.setContentDescription(getString(present ? R.string.windows_runtimes_again : R.string.windows_runtimes));
    }

    private void showStatus(TextView chip, boolean present) {
        showStatus(chip, present, getString(present ? R.string.runtime_installed : R.string.runtime_missing));
    }

    private void showStatus(TextView chip, boolean present, CharSequence text) {
        int color = getColor(present ? R.color.log_ok : R.color.log_warn);
        chip.setText(text);
        chip.setTextColor(color);
        chip.setCompoundDrawableTintList(ColorStateList.valueOf(color));
    }

    private final RecyclerView.OnScrollListener centreFocus = new RecyclerView.OnScrollListener() {
        @Override
        public void onScrolled(@NonNull RecyclerView list, int dx, int dy) {
            float centre = list.getWidth() / 2f;
            if (centre <= 0f) {
                return;
            }

            for (int i = 0; i < list.getChildCount(); i++) {
                View child = list.getChildAt(i);
                float offset = Math.abs(centre - (child.getLeft() + child.getRight()) / 2f);
                float away = Math.min(1f, offset / centre);

                child.setScaleX(1f - away * 0.14f);
                child.setScaleY(1f - away * 0.14f);
                child.setAlpha(1f - away * 0.4f);
            }
        }
    };

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private int widthDp() {
        return (int) (getResources().getDisplayMetrics().widthPixels
                / getResources().getDisplayMetrics().density);
    }

    private void refresh() {
        try {
            ActivityManager manager = getSystemService(ActivityManager.class);
            List<ActivityManager.RunningAppProcessInfo> running = manager == null ? null : manager.getRunningAppProcesses();
            if (running != null) {
                Set<Integer> active = new HashSet<>();
                for (ActivityManager.RunningAppProcessInfo process : running) {
                    if ((getPackageName() + ":guest").equals(process.processName)) {
                        active.add(process.pid);
                    }
                }
                library.checkRuns(active);
            }
            adapter.submit(library.list());
            showEmptyState();
        } catch (IOException failure) {
            snack(failure.getMessage());
        }
    }

    private void showEmptyState() {
        boolean empty = adapter.getItemCount() == 0;
        emptyState.setVisibility(empty ? View.VISIBLE : View.GONE);

        if (!empty) {
            return;
        }

        boolean nothingImported = adapter.isLibraryEmpty();
        emptyTitle.setText(nothingImported ? R.string.library_empty_title : R.string.library_search_empty_title);
        emptyBody.setText(nothingImported ? R.string.library_empty_body : R.string.library_search_empty_body);
    }

    private void showAddOptions(View anchor) {
        Theming.dialog(this)
                .setTitle(R.string.library_add_title)
                .setItems(new CharSequence[]{
                        getString(R.string.library_add_folder),
                        getString(R.string.library_add_file)}, (dialog, index) -> {
                    if (index == 0) {
                        pick(new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE), REQUEST_FOLDER);
                    } else {
                        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT)
                                .addCategory(Intent.CATEGORY_OPENABLE)
                                .setType("*/*");
                        pick(intent, REQUEST_FILE);
                    }
                })
                .show();
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

        if (requestCode == FileBrowser.REQUEST_IMPORT || requestCode == FileBrowser.REQUEST_EXPORT) {
            if (resultCode == RESULT_OK && files != null) {
                files.onPicked(requestCode, data);
            }
            return;
        }

        if (resultCode != RESULT_OK || data == null || data.getData() == null) {
            return;
        }

        Uri uri = data.getData();

        if (requestCode == REQUEST_ISO) {
            selectedIso = uri;
            if (isoLabel != null) {
                isoLabel.setVisibility(View.VISIBLE);
                isoLabel.setText(getString(R.string.windows_chosen, uri.getLastPathSegment()));
                isoImport.setVisibility(View.VISIBLE);
            }
            return;
        }
        boolean folder = requestCode == REQUEST_FOLDER;
        if (!folder && requestCode != REQUEST_FILE) {
            return;
        }

        progress.setVisibility(View.VISIBLE);
        worker.execute(() -> {
            try {
                Library.ImportResult result = folder
                        ? library.importFolder(this, uri)
                        : library.importExecutable(this, uri);

                runOnUiThread(() -> {
                    progress.setVisibility(View.GONE);
                    finishImport(result);
                });
            } catch (Exception failure) {
                runOnUiThread(() -> {
                    progress.setVisibility(View.GONE);
                    snack(getString(R.string.setup_import_failed, failure.getMessage()));
                });
            }
        });
    }

    private void finishImport(Library.ImportResult result) {
        if (result.executables.isEmpty()) {
            library.discard(result.directory);
            snack(getString(R.string.setup_no_executable));
            return;
        }

        if (result.executables.size() == 1) {
            commit(result.directory, result.executables.get(0));
            return;
        }

        CharSequence[] options = result.executables.toArray(new CharSequence[0]);
        Theming.dialog(this)
                .setTitle(R.string.library_pick_executable)
                .setItems(options, (dialog, index) -> commit(result.directory, result.executables.get(index)))
                .setOnCancelListener(dialog -> library.discard(result.directory))
                .show();
    }

    private void commit(File directory, String executable) {
        try {
            library.commit(directory, executable);
            refresh();
        } catch (Exception failure) {
            snack(getString(R.string.library_save_failed, failure.getMessage()));
        }
    }

    private void openProfile(Program program) {
        startActivity(new Intent(this, ProfileActivity.class)
                .putExtra(ProgramSettings.EXTRA_PROFILE_ID, program.id()));
    }

    private void showProgramActions(Program program) {
        boolean failed = !program.lastFailure().isEmpty();
        SpannableString remove = new SpannableString(getString(R.string.library_remove));
        remove.setSpan(new ForegroundColorSpan(getColor(R.color.log_error)), 0, remove.length(), 0);
        CharSequence[] actions = failed
                ? new CharSequence[]{getString(R.string.program_settings), getString(R.string.program_last_run), remove}
                : new CharSequence[]{getString(R.string.program_settings), remove};
        Theming.dialog(this)
                .setTitle(program.name())
                .setItems(actions, (dialog, index) -> {
                    if (index == 0) {
                        openProfile(program);
                    } else if (failed && index == 1) {
                        Theming.dialog(this).setTitle(R.string.program_last_run)
                                .setMessage(program.lastFailure())
                                .setPositiveButton(android.R.string.ok, null).show();
                    } else {
                        confirmRemove(program);
                    }
                }).show();
    }

    private void confirmRemove(Program program) {
        AlertDialog confirm = Theming.dialog(this)
                .setTitle(getString(R.string.library_remove_title, program.name()))
                .setMessage(R.string.library_remove_body)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.library_remove, (dialog, which) -> remove(program))
                .show();
        confirm.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(getColor(R.color.log_error));
    }

    private void remove(Program program) {
        worker.execute(() -> {
            try {
                library.remove(program);
                runOnUiThread(() -> {
                    if (!isDestroyed() && currentScreen == R.id.nav_library) {
                        refresh();
                    }
                });
            } catch (IOException failure) {
                runOnUiThread(() -> snack(failure.getMessage()));
            }
        });
    }

    private void launch(Program program) {
        try {
            startActivity(PlayerActivity.intentFor(this, program, settings));
        } catch (IOException failure) {
            snack(failure.getMessage());
        }
    }

    private View createSettings() {
        View view = LayoutInflater.from(this).inflate(R.layout.screen_settings, content, false);
        choice(view, R.id.network, getResources().getStringArray(R.array.network_modes), settings.network(),
                settings::setNetwork);
        choice(view, R.id.controls, getResources().getStringArray(R.array.control_schemes), settings.controlScheme(),
                settings::setControlScheme);
        choice(view, R.id.pointer, getResources().getStringArray(R.array.pointer_modes), settings.pointerMode(),
                settings::setPointerMode);
        choice(view, R.id.render_scale, getResources().getStringArray(R.array.render_scales), settings.renderScale(),
                settings::setRenderScale);
        choice(view, R.id.display_scale, Settings.displayScaleLabels(this), settings.displayScale(),
                settings::setDisplayScale);
        choice(view, R.id.low_memory, getResources().getStringArray(R.array.low_memory_levels), settings.lowMemory(),
                settings::setLowMemory);
        view.findViewById(R.id.edit_controls).setOnClickListener(button ->
                startActivity(new Intent(this, ControlsActivity.class)));
        bindSwitch(view, R.id.jit_cache, settings.jitCache(), settings::setJitCache);
        bindSwitch(view, R.id.relax_vulkan, settings.relaxVulkan(), settings::setRelaxVulkan);
        bindSwitch(view, R.id.sustained, settings.sustainedPerformance(), settings::setSustainedPerformance);
        bindSwitch(view, R.id.developer, settings.developerMode(), settings::setDeveloperMode);
        return view;
    }

    private void bindSwitch(View view, int id, boolean checked, Consumer<Boolean> onChange) {
        MaterialSwitch toggle = view.findViewById(id);
        toggle.setChecked(checked);
        toggle.setOnCheckedChangeListener((button, value) -> onChange.accept(value));
        ((View) toggle.getParent()).setOnClickListener(row -> toggle.toggle());
    }

    private void choice(View view, int id, String[] labels, int selected, IntConsumer onChange) {
        TextView value = view.findViewById(id);
        int initial = Math.max(0, Math.min(selected, labels.length - 1));
        value.setText(labels[initial]);
        value.setTag(initial);
        View row = (View) value.getParent();
        row.setFocusable(true);
        row.setOnClickListener(clicked -> Theming.rowDialog(value)
                .setSingleChoiceItems(labels, (int) value.getTag(), (dialog, position) -> {
                    value.setText(labels[position]);
                    value.setTag(position);
                    onChange.accept(position);
                    dialog.dismiss();
                }).setNegativeButton(android.R.string.cancel, null).show());
    }

    private void bindDxvk(View view) {
        TextView status = view.findViewById(R.id.dxvk_status);
        MaterialAutoCompleteTextView version = view.findViewById(R.id.dxvk_version);
        MaterialButton install = view.findViewById(R.id.dxvk_install);
        LinearProgressIndicator bar = view.findViewById(R.id.dxvk_progress);
        TextView detail = view.findViewById(R.id.dxvk_progress_text);

        showDxvkState(status, install);
        showDxvkVersions(version, Collections.emptyList());

        boolean[] requested = {false};
        View.OnClickListener openVersions = button -> {
            version.showDropDown();
            if (requested[0]) {
                return;
            }
            requested[0] = true;
            worker.execute(() -> {
                List<String> tags = Dxvk.versions();
                runOnUiThread(() -> {
                    if (!version.isAttachedToWindow()) {
                        return;
                    }
                    showDxvkVersions(version, tags);
                    if (tags.isEmpty()) {
                        detail.setVisibility(View.VISIBLE);
                        detail.setText(R.string.settings_dxvk_offline);
                    }
                    version.showDropDown();
                });
            });
        };
        version.setOnClickListener(openVersions);
        ((TextInputLayout) view.findViewById(R.id.dxvk_version_layout)).setEndIconOnClickListener(openVersions);

        install.setOnClickListener(button -> {
            startInstall(bar, detail, R.string.settings_dxvk_working, install);
            WindowsInstall.dxvk(this, worker, settings.dxvkVersion(), new WindowsInstall.Listener() {
                @Override
                public void onProgress(long filesDone, long filesTotal, long bytesDone, long bytesTotal) {
                    if (bytesTotal <= 0) {
                        detail.setText(getString(R.string.setup_progress_downloaded, bytesDone >> 20));
                        return;
                    }

                    advance(bar, bytesDone, bytesTotal);
                    detail.setText(getString(R.string.setup_progress_bytes, bytesDone >> 20, bytesTotal >> 20));
                }

                @Override
                public void onFinished(int result) {
                    install.setEnabled(true);
                    setRuntimeActions(true);
                    bar.setVisibility(View.GONE);
                    detail.setText(result == BrovanNative.STATUS_OK
                            ? getString(R.string.settings_dxvk_done)
                            : getString(R.string.settings_dxvk_failed));
                    showDxvkState(status, install);
                }
            });
        });
    }

    private void showDxvkVersions(MaterialAutoCompleteTextView picker, List<String> tags) {
        List<String> labels = new ArrayList<>();
        labels.add(getString(R.string.settings_dxvk_version_latest));

        String chosen = settings.dxvkVersion();
        if (!chosen.isEmpty() && !tags.contains(chosen)) {
            labels.add(chosen);
        }
        labels.addAll(tags);

        picker.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, labels));
        picker.setText(chosen.isEmpty() ? labels.get(0) : chosen, false);
        picker.setOnItemClickListener((parent, item, position, id) ->
                settings.setDxvkVersion(position == 0 ? Dxvk.LATEST : labels.get(position)));
    }

    private void showDxvkState(TextView status, MaterialButton action) {
        String installed = Dxvk.installedVersion(this);

        showStatus(status, !installed.isEmpty(), installed.isEmpty()
                ? getString(R.string.runtime_missing)
                : getString(R.string.runtime_dxvk_installed, installed));
        action.setText(installed.isEmpty() ? R.string.runtime_install : R.string.runtime_reinstall);
        action.setContentDescription(getString(installed.isEmpty()
                ? R.string.settings_dxvk_install : R.string.settings_dxvk_install_again));
    }

    private View createTheme() {
        View view = LayoutInflater.from(this).inflate(R.layout.screen_theme, content, false);

        TextView style = view.findViewById(R.id.library_style);
        style.setText(ProgramAdapter.Style.of(settings.libraryStyle()).labelId());
        ((View) style.getParent()).setOnClickListener(button -> showStyles());

        LinearLayout roles = view.findViewById(R.id.theme_roles);
        Palette.Role[] all = Palette.Role.values();
        roleSwatches = new View[all.length];

        for (int i = 0; i < all.length; i++) {
            Palette.Role role = all[i];
            View row = LayoutInflater.from(this).inflate(R.layout.item_theme_role, roles, false);

            ((TextView) row.findViewById(R.id.role_name)).setText(role.labelId);
            roleSwatches[i] = row.findViewById(R.id.role_swatch);
            ColorPicker.swatch(roleSwatches[i], palette.get(role));

            row.setOnClickListener(button -> ColorPicker.show(this, role.labelId, palette.get(role), palette,
                    rgb -> editTheme(edited -> edited.set(role, rgb))));

            roles.addView(row);
        }

        View customBody = view.findViewById(R.id.theme_custom_body);
        View customChevron = view.findViewById(R.id.theme_custom_chevron);
        view.findViewById(R.id.theme_custom).setOnClickListener(row -> {
            boolean open = customBody.getVisibility() != View.VISIBLE;
            customBody.setVisibility(open ? View.VISIBLE : View.GONE);
            customChevron.setRotation(open ? 180f : 0f);
        });

        LinearLayout presets = view.findViewById(R.id.theme_presets);
        Palette.Preset[] presetValues = Palette.Preset.values();
        presetChips = new MaterialCardView[presetValues.length];
        for (int i = 0; i < presetValues.length; i++) {
            presetChips[i] = presetChip(presetValues[i], presets);
            presets.addView(presetChips[i]);
        }
        view.post(this::paintPresets);

        view.findViewById(R.id.theme_reset).setOnClickListener(button -> {
            settings.clearPalette();
            editTheme(edited -> {
                for (Palette.Role role : Palette.Role.values()) {
                    edited.set(role, role.fallback);
                }
            });
        });

        return view;
    }

    private interface ThemeEdit {
        void apply(Palette palette);
    }

    private void editTheme(ThemeEdit edit) {
        Palette before = palette.copy();
        edit.apply(palette);

        settings.setPalette(palette);

        if (before.isLight() != palette.isLight()) {
            recreate();
            return;
        }

        Theming.apply(this, before, palette);
        paintStatusBar();

        if (roleSwatches != null) {
            Palette.Role[] all = Palette.Role.values();

            for (int i = 0; i < all.length; i++) {
                ColorPicker.swatch(roleSwatches[i], palette.get(all[i]));
            }
        }

        content.post(this::paintPresets);
    }

    // Theming.apply also recolours the preset swatches that match the old palette, so they are painted again after it.
    private void paintPresets() {
        if (presetChips == null || currentScreen != R.id.nav_theme) {
            return;
        }

        Palette.Preset[] all = Palette.Preset.values();
        for (int i = 0; i < all.length; i++) {
            Palette colors = all[i].palette();
            swatchPreset(presetChips[i], colors);

            boolean current = palette.sameAs(colors);
            presetChips[i].setStrokeColor(palette.get(current ? Palette.Role.ACCENT : Palette.Role.OUTLINE));
            presetChips[i].setStrokeWidth(dp(current ? 2 : 1));
        }
    }

    private static void swatchPreset(View chip, Palette colors) {
        ColorPicker.swatch(chip.findViewById(R.id.preset_background), colors.get(Palette.Role.BACKGROUND));
        ColorPicker.swatch(chip.findViewById(R.id.preset_surface), colors.get(Palette.Role.SURFACE));
        ColorPicker.swatch(chip.findViewById(R.id.preset_accent), colors.get(Palette.Role.ACCENT));
    }

    private MaterialCardView presetChip(Palette.Preset preset, ViewGroup parent) {
        MaterialCardView chip = (MaterialCardView) LayoutInflater.from(this).inflate(R.layout.item_theme_preset, parent,
                false);
        Palette colors = preset.palette();

        ((TextView) chip.findViewById(R.id.preset_name)).setText(preset.labelId);
        swatchPreset(chip, colors);

        chip.setOnClickListener(button -> editTheme(edited -> {
            for (Palette.Role role : Palette.Role.values()) {
                edited.set(role, colors.get(role));
            }
        }));

        return chip;
    }

    private View createAbout() {
        View view = LayoutInflater.from(this).inflate(R.layout.screen_about, content, false);

        view.findViewById(R.id.open_github).setOnClickListener(button -> openLink(R.string.about_github));
        view.findViewById(R.id.open_linkedin).setOnClickListener(button -> openLink(R.string.about_linkedin));
        view.findViewById(R.id.open_discord).setOnClickListener(button -> copyDiscord());

        return view;
    }

    private void openLink(int urlId) {
        String url = getString(urlId);

        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        } catch (ActivityNotFoundException missing) {
            snack(url);
        }
    }

    private void copyDiscord() {
        String name = getString(R.string.about_discord);
        ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);

        if (clipboard != null) {
            clipboard.setPrimaryClip(ClipData.newPlainText(getString(R.string.about_open_discord), name));
        }

        snack(getString(R.string.about_discord_copied, name));
    }

    private void snack(String message) {
        Snackbar.make(content, message, Snackbar.LENGTH_LONG).show();
    }

    @Override
    public void onBackPressed() {
        if (drawer.isOpen()) {
            drawer.close();
            return;
        }

        if (files != null && files.goUp()) {
            return;
        }

        super.onBackPressed();
    }
}
