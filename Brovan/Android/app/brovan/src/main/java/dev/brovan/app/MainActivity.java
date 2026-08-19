package dev.brovan.app;

import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.drawerlayout.widget.DrawerLayout;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.materialswitch.MaterialSwitch;
import com.google.android.material.navigation.NavigationView;
import com.google.android.material.progressindicator.CircularProgressIndicator;
import com.google.android.material.progressindicator.LinearProgressIndicator;
import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.snackbar.Snackbar;
import com.google.android.material.textfield.MaterialAutoCompleteTextView;

import java.io.File;

import dev.brovan.BrovanNative;
import dev.brovan.BrovanSurfaceView;
import dev.brovan.input.ControlOverlay;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {

    private static final int REQUEST_FOLDER = 1;
    private static final int REQUEST_FILE = 2;
    private static final int REQUEST_ISO = 3;

    private final ExecutorService worker = Executors.newSingleThreadExecutor();

    private Library library;
    private Settings settings;
    private NavigationView navigation;
    private DrawerLayout drawer;
    private FrameLayout content;
    private MaterialToolbar toolbar;
    private ProgramAdapter adapter;
    private View emptyState;
    private CircularProgressIndicator progress;
    private Uri selectedIso;
    private TextView isoLabel;
    private FileBrowser files;
    private int currentScreen;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        library = new Library(this);
        settings = new Settings(this);

        // Refreshes the guest-side files bundled in the APK, so an app update cannot leave
        // a stale Vulkan shim behind for the new emulator to load.
        worker.execute(() -> GuestAssets.deploy(this));

        drawer = findViewById(R.id.drawer);
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

        openScreen(R.id.nav_library);

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
    }

    private View createLibrary() {
        View view = LayoutInflater.from(this).inflate(R.layout.screen_library, content, false);

        emptyState = view.findViewById(R.id.empty);
        progress = view.findViewById(R.id.progress);

        RecyclerView list = view.findViewById(R.id.apps);
        list.setLayoutManager(new GridLayoutManager(this, columnCount()));
        adapter = new ProgramAdapter(new ProgramAdapter.Listener() {
            @Override
            public void onLaunch(Program program) {
                launch(program);
            }

            @Override
            public void onLongPress(Program program) {
                confirmRemoval(program);
            }
        });
        list.setAdapter(adapter);

        view.findViewById(R.id.add).setOnClickListener(this::showAddOptions);

        refresh();
        return view;
    }

    /// Windows system files screen: the only place the emulator is allowed to fetch Microsoft's files.
    private View createWindows() {
        View view = LayoutInflater.from(this).inflate(R.layout.screen_windows, content, false);

        TextView status = view.findViewById(R.id.windows_status);
        MaterialSwitch licensed = view.findViewById(R.id.windows_licensed);
        TextInputEditText source = view.findViewById(R.id.windows_source);
        MaterialButton install = view.findViewById(R.id.windows_install);
        LinearProgressIndicator bar = view.findViewById(R.id.windows_progress);
        TextView detail = view.findViewById(R.id.windows_progress_text);
        MaterialButton openPage = view.findViewById(R.id.windows_open_page);
        MaterialButton choose = view.findViewById(R.id.windows_choose);
        MaterialButton runtimes = view.findViewById(R.id.windows_runtimes);
        TextView runtimesStatus = view.findViewById(R.id.windows_runtimes_status);

        isoLabel = detail;

        openPage.setOnClickListener(button -> {
            try {
                startActivity(new Intent(Intent.ACTION_VIEW,
                        Uri.parse("https://www.microsoft.com/software-download/windows11")));
            } catch (ActivityNotFoundException missing) {
                snack("No browser is available on this device.");
            }
        });

        choose.setOnClickListener(button -> pick(new Intent(Intent.ACTION_OPEN_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .setType("*/*"), REQUEST_ISO));

        status.setText(windowsFilesPresent() ? R.string.windows_installed : R.string.windows_missing);

        showRuntimeState(runtimesStatus, runtimes);

        runtimes.setOnClickListener(button -> {
            if (!licensed.isChecked()) {
                snack(getString(R.string.windows_needs_license));
                return;
            }

            startInstall(bar, detail, R.string.windows_runtimes_working, install, runtimes);
            WindowsInstall.runtimes(this, worker, new WindowsInstall.Listener() {
                @Override
                public void onProgress(long filesDone, long filesTotal, long bytesDone, long bytesTotal) {
                    // The package sizes are only known once the Visual Studio manifest is in, so the download
                    // runs indeterminate until the native side reports a byte total.
                    if (bytesTotal <= 0) {
                        detail.setText(getString(R.string.setup_progress_downloaded, bytesDone >> 20));
                        return;
                    }

                    advance(bar, bytesDone, bytesTotal);
                    detail.setText(getString(R.string.setup_progress_bytes, bytesDone >> 20, bytesTotal >> 20));
                }

                @Override
                public void onFinished(int result) {
                    finishInstall(bar, detail, result, R.string.windows_runtimes_done, install, runtimes);
                    showRuntimeState(runtimesStatus, runtimes);
                }
            });
        });

        install.setOnClickListener(button -> {
            if (!licensed.isChecked()) {
                snack(getString(R.string.windows_needs_license));
                return;
            }

            CharSequence typed = source.getText();
            String media = typed == null || typed.toString().trim().isEmpty() ? null : typed.toString().trim();

            licensed.setEnabled(false);
            startInstall(bar, detail, R.string.windows_working, install, runtimes);
            WindowsInstall.windows(this, worker, media, selectedIso, new WindowsInstall.Listener() {
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
                    licensed.setEnabled(true);
                    finishInstall(bar, detail, result, R.string.windows_done, install, runtimes);
                    status.setText(windowsFilesPresent() ? R.string.windows_installed : R.string.windows_missing);
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

        bar.setVisibility(View.GONE);
        detail.setText(result == BrovanNative.STATUS_OK ? getString(doneId) : getString(R.string.windows_failed));
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

        status.setText(present ? R.string.windows_runtimes_installed : R.string.windows_runtimes_missing);
        action.setText(present ? R.string.windows_runtimes_again : R.string.windows_runtimes);
    }

    private int columnCount() {
        int widthDp = (int) (getResources().getDisplayMetrics().widthPixels
                / getResources().getDisplayMetrics().density);
        return Math.max(2, widthDp / 190);
    }

    private void refresh() {
        List<Program> programs = library.list();
        adapter.submit(programs);
        emptyState.setVisibility(programs.isEmpty() ? View.VISIBLE : View.GONE);
    }

    private void showAddOptions(View anchor) {
        new AlertDialog.Builder(this)
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
            snack("No file picker is available on this device.");
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
                    snack("Import failed: " + failure.getMessage());
                });
            }
        });
    }

    private void finishImport(Library.ImportResult result) {
        if (result.executables.isEmpty()) {
            library.discard(result.directory);
            snack("No .exe found in that folder.");
            return;
        }

        if (result.executables.size() == 1) {
            commit(result.directory, result.executables.get(0));
            return;
        }

        CharSequence[] options = result.executables.toArray(new CharSequence[0]);
        new AlertDialog.Builder(this)
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
            snack("Could not save: " + failure.getMessage());
        }
    }

    private void confirmRemoval(Program program) {
        new AlertDialog.Builder(this)
                .setTitle(program.name())
                .setItems(new CharSequence[]{getString(R.string.library_remove)}, (dialog, index) -> {
                    library.remove(program);
                    refresh();
                })
                .show();
    }

    private void launch(Program program) {
        startActivity(PlayerActivity.intentFor(this, program, settings));
    }

    private View createSettings() {
        View view = LayoutInflater.from(this).inflate(R.layout.screen_settings, content, false);

        MaterialAutoCompleteTextView network = view.findViewById(R.id.network);
        network.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, Settings.NETWORK_MODES));
        network.setText(Settings.NETWORK_MODES[settings.network()], false);
        network.setOnItemClickListener((parent, item, position, id) -> settings.setNetwork(position));

        ControlOverlay.Scheme[] schemes = ControlOverlay.Scheme.values();
        String[] schemeLabels = new String[schemes.length];
        for (int i = 0; i < schemes.length; i++) {
            schemeLabels[i] = schemes[i].label();
        }

        MaterialAutoCompleteTextView controls = view.findViewById(R.id.controls);
        controls.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, schemeLabels));
        controls.setText(schemeLabels[settings.controlScheme()], false);
        controls.setOnItemClickListener((parent, item, position, id) -> settings.setControlScheme(position));

        BrovanSurfaceView.PointerMode[] pointers = BrovanSurfaceView.PointerMode.values();
        String[] pointerLabels = new String[pointers.length];
        for (int i = 0; i < pointers.length; i++) {
            pointerLabels[i] = pointers[i].label();
        }

        MaterialAutoCompleteTextView pointer = view.findViewById(R.id.pointer);
        pointer.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, pointerLabels));
        pointer.setText(pointerLabels[settings.pointerMode()], false);
        pointer.setOnItemClickListener((parent, item, position, id) -> settings.setPointerMode(position));

        view.findViewById(R.id.edit_controls).setOnClickListener(button ->
                startActivity(new Intent(this, ControlsActivity.class)));

        MaterialSwitch jitCache = view.findViewById(R.id.jit_cache);
        jitCache.setChecked(settings.jitCache());
        jitCache.setOnCheckedChangeListener((button, checked) -> settings.setJitCache(checked));

        MaterialSwitch developer = view.findViewById(R.id.developer);
        developer.setChecked(settings.developerMode());
        developer.setOnCheckedChangeListener((button, checked) -> settings.setDeveloperMode(checked));

        MaterialSwitch fit = view.findViewById(R.id.keep_aspect);
        fit.setChecked(settings.fitWindow());
        fit.setOnCheckedChangeListener((button, checked) -> settings.setFitWindow(checked));

        bindDxvk(view);

        return view;
    }

    private void bindDxvk(View view) {
        TextView status = view.findViewById(R.id.dxvk_status);
        MaterialAutoCompleteTextView version = view.findViewById(R.id.dxvk_version);
        MaterialButton install = view.findViewById(R.id.dxvk_install);
        LinearProgressIndicator bar = view.findViewById(R.id.dxvk_progress);
        TextView detail = view.findViewById(R.id.dxvk_progress_text);

        showDxvkState(status, install);
        showDxvkVersions(version, Collections.emptyList());

        // The release list needs the network, so the picker starts with the stored choice and grows once
        // GitHub answers. Picking nothing still works: an empty version installs the newest release.
        worker.execute(() -> {
            List<String> tags = Dxvk.versions();
            runOnUiThread(() -> {
                if (version.isAttachedToWindow()) {
                    showDxvkVersions(version, tags);
                    if (tags.isEmpty()) {
                        detail.setVisibility(View.VISIBLE);
                        detail.setText(R.string.settings_dxvk_offline);
                    }
                }
            });
        });

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

        status.setText(installed.isEmpty()
                ? getString(R.string.settings_dxvk_missing)
                : getString(R.string.settings_dxvk_installed, installed));
        action.setText(installed.isEmpty() ? R.string.settings_dxvk_install : R.string.settings_dxvk_install_again);
    }

    private View createAbout() {
        View view = LayoutInflater.from(this).inflate(R.layout.screen_about, content, false);
        MaterialButton open = view.findViewById(R.id.open_github);
        open.setOnClickListener(button -> {
            try {
                startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(getString(R.string.about_github))));
            } catch (ActivityNotFoundException missing) {
                snack(getString(R.string.about_github));
            }
        });
        return view;
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
