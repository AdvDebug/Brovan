package dev.brovan.app;

import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
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
import dev.brovan.input.ControlOverlay;
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
    private DrawerLayout drawer;
    private FrameLayout content;
    private MaterialToolbar toolbar;
    private ProgramAdapter adapter;
    private View emptyState;
    private CircularProgressIndicator progress;
    private Uri selectedIso;
    private TextView isoLabel;

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

        NavigationView navigation = findViewById(R.id.navigation);
        navigation.setNavigationItemSelectedListener(item -> {
            show(item.getItemId());
            drawer.close();
            return true;
        });
        navigation.setCheckedItem(R.id.nav_library);
        insetDrawerHeader(navigation);

        show(R.id.nav_library);
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

    private void show(int itemId) {
        content.removeAllViews();

        if (itemId == R.id.nav_windows) {
            toolbar.setTitle(R.string.nav_windows);
            content.addView(createWindows());
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

            runtimes.setEnabled(false);
            install.setEnabled(false);
            bar.setIndeterminate(true);
            bar.setVisibility(View.VISIBLE);
            detail.setVisibility(View.VISIBLE);
            detail.setText(R.string.windows_runtimes_working);

            // The package sizes are only known once the Visual Studio manifest is in, so the download runs
            // indeterminate until the native side reports a byte total.
            BrovanNative.setInstallListener((filesDone, filesTotal, bytesDone, bytesTotal) -> runOnUiThread(() -> {
                if (bytesTotal <= 0) {
                    detail.setText(String.format(java.util.Locale.US, "%d MB", bytesDone >> 20));
                    return;
                }

                if (bar.isIndeterminate()) {
                    bar.setIndeterminate(false);
                    bar.setMax(1000);
                }

                bar.setProgress((int) (bytesDone * 1000 / bytesTotal), true);
                detail.setText(String.format(java.util.Locale.US, "%d of %d MB",
                        bytesDone >> 20, bytesTotal >> 20));
            }));

            worker.execute(() -> {
                int result = BrovanNative.init(getFilesDir().getAbsolutePath());

                if (result == BrovanNative.STATUS_OK || result == BrovanNative.STATUS_MISSING_WINDOWS_LIBS
                        || result == BrovanNative.STATUS_MISSING_REGISTRY) {
                    result = BrovanNative.installRuntimes(true);
                }

                int outcome = result;
                runOnUiThread(() -> {
                    BrovanNative.setInstallListener(null);
                    bar.setVisibility(View.GONE);
                    runtimes.setEnabled(true);
                    install.setEnabled(true);
                    detail.setText(outcome == BrovanNative.STATUS_OK
                            ? R.string.windows_runtimes_done : R.string.windows_failed);
                    showRuntimeState(runtimesStatus, runtimes);
                });
            });
        });

        install.setOnClickListener(button -> {
            if (!licensed.isChecked()) {
                snack(getString(R.string.windows_needs_license));
                return;
            }

            CharSequence typed = source.getText();
            String media = typed == null || typed.toString().trim().isEmpty() ? null : typed.toString().trim();
            Uri iso = selectedIso;

            install.setEnabled(false);
            licensed.setEnabled(false);
            runtimes.setEnabled(false);
            bar.setIndeterminate(true);
            bar.setVisibility(View.VISIBLE);
            detail.setVisibility(View.VISIBLE);
            detail.setText(R.string.windows_working);

            BrovanNative.setInstallListener((filesDone, filesTotal, bytesDone, bytesTotal) -> runOnUiThread(() -> {
                if (filesTotal <= 0) {
                    return;
                }

                if (bar.isIndeterminate()) {
                    bar.setIndeterminate(false);
                    bar.setMax(1000);
                }

                bar.setProgress((int) (filesDone * 1000 / filesTotal), true);
                detail.setText(String.format(java.util.Locale.US, "%d of %d files, %d of %d MB",
                        filesDone, filesTotal, bytesDone >> 20, bytesTotal >> 20));
            }));

            worker.execute(() -> {
                int result = BrovanNative.init(getFilesDir().getAbsolutePath());

                if (result == BrovanNative.STATUS_OK || result == BrovanNative.STATUS_MISSING_WINDOWS_LIBS
                        || result == BrovanNative.STATUS_MISSING_REGISTRY) {
                    ParcelFileDescriptor descriptor = null;

                    try {
                        int handle = -1;

                        if (iso != null) {
                            descriptor = getContentResolver().openFileDescriptor(iso, "r");
                            handle = descriptor == null ? -1 : descriptor.getFd();
                        }

                        result = BrovanNative.installWindows(handle >= 0 ? null : media, handle, true, 1);
                    } catch (Exception failure) {
                        result = BrovanNative.STATUS_FAILED;
                    } finally {
                        if (descriptor != null) {
                            try {
                                descriptor.close();
                            } catch (java.io.IOException ignored) {
                            }
                        }
                    }
                }

                int outcome = result;
                runOnUiThread(() -> {
                    BrovanNative.setInstallListener(null);
                    bar.setVisibility(View.GONE);
                    install.setEnabled(true);
                    licensed.setEnabled(true);
                    runtimes.setEnabled(true);
                    detail.setText(outcome == BrovanNative.STATUS_OK ? R.string.windows_done : R.string.windows_failed);
                    status.setText(windowsFilesPresent() ? R.string.windows_installed : R.string.windows_missing);
                    showRuntimeState(runtimesStatus, runtimes);
                });
            });
        });

        return view;
    }

    private boolean windowsFilesPresent() {
        return new File(getFilesDir(), "WindowsLibs").isDirectory();
    }

    private void showRuntimeState(TextView status, MaterialButton action) {
        boolean present = new File(getFilesDir(), "WindowsLibs/msvcp140.dll").exists();

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

        MaterialSwitch jitCache = view.findViewById(R.id.jit_cache);
        jitCache.setChecked(settings.jitCache());
        jitCache.setOnCheckedChangeListener((button, checked) -> settings.setJitCache(checked));

        MaterialSwitch developer = view.findViewById(R.id.developer);
        developer.setChecked(settings.developerMode());
        developer.setOnCheckedChangeListener((button, checked) -> settings.setDeveloperMode(checked));

        MaterialSwitch fit = view.findViewById(R.id.keep_aspect);
        fit.setChecked(settings.fitWindow());
        fit.setOnCheckedChangeListener((button, checked) -> settings.setFitWindow(checked));

        return view;
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

        super.onBackPressed();
    }
}
