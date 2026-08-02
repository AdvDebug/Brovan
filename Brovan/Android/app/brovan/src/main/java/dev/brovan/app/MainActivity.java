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

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.drawerlayout.widget.DrawerLayout;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.materialswitch.MaterialSwitch;
import com.google.android.material.navigation.NavigationView;
import com.google.android.material.progressindicator.CircularProgressIndicator;
import com.google.android.material.snackbar.Snackbar;
import com.google.android.material.textfield.MaterialAutoCompleteTextView;

import java.io.File;

import dev.brovan.input.ControlOverlay;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {

    private static final int REQUEST_FOLDER = 1;
    private static final int REQUEST_FILE = 2;

    private final ExecutorService worker = Executors.newSingleThreadExecutor();

    private Library library;
    private Settings settings;
    private DrawerLayout drawer;
    private FrameLayout content;
    private MaterialToolbar toolbar;
    private ProgramAdapter adapter;
    private View emptyState;
    private CircularProgressIndicator progress;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        library = new Library(this);
        settings = new Settings(this);

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

        show(R.id.nav_library);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        worker.shutdownNow();
    }

    private void show(int itemId) {
        content.removeAllViews();

        if (itemId == R.id.nav_settings) {
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

        MaterialAutoCompleteTextView backend = view.findViewById(R.id.backend);
        backend.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, Settings.BACKENDS));
        backend.setText(Settings.BACKENDS[settings.backend()], false);
        backend.setOnItemClickListener((parent, item, position, id) -> settings.setBackend(position));

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
