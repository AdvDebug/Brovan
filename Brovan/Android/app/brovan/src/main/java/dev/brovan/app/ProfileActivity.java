package dev.brovan.app;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.textfield.TextInputLayout;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import dev.brovan.BrovanSurfaceView;
import dev.brovan.input.ControlOverlay;

public class ProfileActivity extends AppCompatActivity {

    private static final int REQUEST_CONTROLS = 1;
    private static final String STATE_CHANGES = "changes";
    private static final String STATE_BASELINE = "baseline";

    private Library library;
    private Settings defaults;
    private Program program;
    private Bundle baseline;
    private final Map<String, String> changes = new HashMap<>();
    private EditText name;
    private EditText executable;
    private EditText arguments;
    private EditText workingDirectory;
    private EditText pointerSpeed;

    @Override
    protected void onCreate(Bundle state) {
        defaults = new Settings(this);
        Palette palette = defaults.palette();
        Theming.install(this, palette);
        super.onCreate(state);
        setContentView(R.layout.activity_profile);
        Theming.apply(this, Palette.defaults(), palette);
        library = new Library(this);
        try {
            program = library.find(getIntent().getStringExtra(ProgramSettings.EXTRA_PROFILE_ID));
        } catch (IOException failure) {
            Toast.makeText(this, failure.getMessage(), Toast.LENGTH_LONG).show();
            finish();
            return;
        }

        if (state != null) {
            Bundle saved = state.getBundle(STATE_CHANGES);
            if (saved != null) {
                for (String key : saved.keySet()) {
                    changes.put(key, saved.getString(key));
                }
            }
        }

        MaterialToolbar toolbar = findViewById(R.id.profile_toolbar);
        toolbar.setTitle(program.name());
        toolbar.setNavigationOnClickListener(view -> close());
        name = findViewById(R.id.profile_name);
        executable = findViewById(R.id.profile_executable);
        arguments = findViewById(R.id.profile_arguments);
        workingDirectory = findViewById(R.id.profile_directory);
        pointerSpeed = findViewById(R.id.profile_pointer_speed);
        name.setText(program.name());
        executable.setText(program.executableName());
        arguments.setText(program.arguments());
        workingDirectory.setText(program.workingDirectory());
        pointerSpeed.setText(currentValues().getProperty("pointer_speed", ""));
        ((TextInputLayout) findViewById(R.id.profile_pointer_speed_container))
                .setPlaceholderText(getString(R.string.program_default_value, Float.toString(defaults.pointerSpeed())));
        baseline = state == null ? null : state.getBundle(STATE_BASELINE);
        if (baseline == null) {
            baseline = new Bundle();
            baseline.putString(Library.KEY_NAME, program.name());
            baseline.putString(Library.KEY_EXECUTABLE, program.executableName());
            baseline.putString(Library.KEY_ARGUMENTS, program.arguments());
            baseline.putString(Library.KEY_WORKING_DIRECTORY, program.workingDirectory());
            baseline.putString("pointer_speed", program.values().getProperty("pointer_speed", ""));
        }

        findViewById(R.id.profile_save).setOnClickListener(view -> save());
        ((TextInputLayout) findViewById(R.id.profile_executable_container))
                .setEndIconOnClickListener(view -> pickExecutable());
        findViewById(R.id.profile_layout).setOnClickListener(view -> {
            Intent intent = new Intent(this, ControlsActivity.class)
                    .putExtra(ProgramSettings.EXTRA_PROFILE_ID, program.id())
                    .putExtra(ControlsActivity.EXTRA_LAYOUT, effective().controlLayout());
            startActivityForResult(intent, REQUEST_CONTROLS);
        });
        findViewById(R.id.profile_reset).setOnClickListener(view -> {
            for (String key : ProgramSettings.OVERRIDE_KEYS) {
                changes.put(key, null);
            }
            pointerSpeed.setText("");
            bindOptions();
        });

        bindOptions();
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                close();
            }
        });
    }

    private Properties currentValues() {
        Properties values = program.values();
        for (Map.Entry<String, String> change : changes.entrySet()) {
            if (change.getValue() == null) {
                values.remove(change.getKey());
            } else {
                values.setProperty(change.getKey(), change.getValue());
            }
        }
        return values;
    }

    private ProgramSettings effective() {
        return new ProgramSettings(library,
                new Program(program.id(), program.directory(), currentValues(), program.lastFailure()), defaults);
    }

    private void bindOptions() {
        String[] schemes = new String[ControlOverlay.Scheme.values().length];
        for (int index = 0; index < schemes.length; index++) {
            schemes[index] = ControlOverlay.Scheme.values()[index].label();
        }
        String[] pointers = new String[BrovanSurfaceView.PointerMode.values().length];
        for (int index = 0; index < pointers.length; index++) {
            pointers[index] = BrovanSurfaceView.PointerMode.values()[index].label();
        }
        ProgramSettings own = effective();
        choice(R.id.profile_controls, "controls", schemes, defaults.controlScheme(), own.controlScheme());
        choice(R.id.profile_pointer, "pointer", pointers, defaults.pointerMode(), own.pointerMode());
        choice(R.id.profile_network, "network", Settings.NETWORK_MODES, defaults.network(), own.network());
        choice(R.id.profile_scale, "render_scale", Settings.RENDER_SCALE_LABELS, defaults.renderScale(), own.renderScale());
        choice(R.id.profile_memory, "low_memory", Settings.LOW_MEMORY_LABELS, defaults.lowMemory(), own.lowMemory());
        toggle(R.id.profile_jit, "jit_cache", defaults.jitCache(), own.jitCache());
        toggle(R.id.profile_vulkan, "relax_vulkan", defaults.relaxVulkan(), own.relaxVulkan());
        toggle(R.id.profile_sustained, "sustained", defaults.sustainedPerformance(), own.sustainedPerformance());
        toggle(R.id.profile_developer, "developer", defaults.developerMode(), own.developerMode());
    }

    private void choice(int id, String key, String[] labels, int defaultIndex, int currentIndex) {
        int safeDefault = Math.max(0, Math.min(defaultIndex, labels.length - 1));
        String inherited = getString(R.string.program_default_value, labels[safeDefault]);
        boolean overridden = currentValues().containsKey(key);
        TextView value = findViewById(id);
        value.setText(overridden ? labels[currentIndex] : inherited);
        CharSequence[] options = new CharSequence[labels.length + 1];
        options[0] = inherited;
        System.arraycopy(labels, 0, options, 1, labels.length);
        View.OnClickListener listener = view -> Theming.dialog(this)
                .setSingleChoiceItems(options, overridden ? currentIndex + 1 : 0, (dialog, index) -> {
                    changes.put(key, index == 0 ? null : Integer.toString(index - 1));
                    bindOptions();
                    dialog.dismiss();
                }).setNegativeButton(android.R.string.cancel, null).show();
        value.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        ((View) value.getParent()).setFocusable(true);
        ((View) value.getParent()).setOnClickListener(listener);
    }

    private void toggle(int id, String key, boolean fallback, boolean current) {
        String inherited = getString(R.string.program_default_value,
                getString(fallback ? R.string.setting_on : R.string.setting_off));
        boolean overridden = currentValues().containsKey(key);
        TextView value = findViewById(id);
        value.setText(overridden ? getString(current ? R.string.setting_on : R.string.setting_off) : inherited);
        CharSequence[] options = {inherited, getString(R.string.setting_on), getString(R.string.setting_off)};
        View.OnClickListener listener = view -> Theming.dialog(this)
                .setSingleChoiceItems(options, overridden ? (current ? 1 : 2) : 0, (dialog, index) -> {
                    changes.put(key, index == 0 ? null : Boolean.toString(index == 1));
                    bindOptions();
                    dialog.dismiss();
                }).setNegativeButton(android.R.string.cancel, null).show();
        value.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        ((View) value.getParent()).setFocusable(true);
        ((View) value.getParent()).setOnClickListener(listener);
    }

    private void pickExecutable() {
        String[] choices = Library.findExecutables(program.directory()).toArray(new String[0]);
        if (choices.length == 0) {
            Toast.makeText(this, R.string.setup_no_executable, Toast.LENGTH_LONG).show();
            return;
        }
        Theming.dialog(this).setTitle(R.string.library_pick_executable)
                .setItems(choices, (dialog, index) -> executable.setText(choices[index])).show();
    }

    private void save() {
        Map<String, String> updates = new HashMap<>(changes);
        if (!name.getText().toString().equals(baseline.getString(Library.KEY_NAME))) {
            updates.put(Library.KEY_NAME, name.getText().toString().trim());
        }
        if (!executable.getText().toString().equals(baseline.getString(Library.KEY_EXECUTABLE))) {
            updates.put(Library.KEY_EXECUTABLE, executable.getText().toString().trim());
        }
        if (!arguments.getText().toString().equals(baseline.getString(Library.KEY_ARGUMENTS))) {
            updates.put(Library.KEY_ARGUMENTS, arguments.getText().toString());
        }
        if (!workingDirectory.getText().toString().equals(baseline.getString(Library.KEY_WORKING_DIRECTORY))) {
            updates.put(Library.KEY_WORKING_DIRECTORY, workingDirectory.getText().toString().trim());
        }
        String speed = pointerSpeed.getText().toString().trim();
        if (!speed.isEmpty()) {
            try {
                float parsed = Float.parseFloat(speed);
                if (!Float.isFinite(parsed) || parsed < 0.4f || parsed > 3f) {
                    throw new NumberFormatException();
                }
            } catch (NumberFormatException invalid) {
                pointerSpeed.setError(getString(R.string.program_speed_range));
                return;
            }
        }
        if (updates.containsKey("pointer_speed") || !speed.equals(baseline.getString("pointer_speed"))) {
            updates.put("pointer_speed", speed.isEmpty() ? null : speed);
        }
        try {
            program = library.update(program.id(), updates);
            changes.clear();
            finish();
        } catch (IOException failure) {
            Theming.dialog(this).setTitle(R.string.program_save_error)
                    .setMessage(failure.getMessage()).setPositiveButton(android.R.string.ok, null).show();
        }
    }

    private boolean dirty() {
        return !changes.isEmpty()
                || !name.getText().toString().equals(baseline.getString(Library.KEY_NAME))
                || !executable.getText().toString().equals(baseline.getString(Library.KEY_EXECUTABLE))
                || !arguments.getText().toString().equals(baseline.getString(Library.KEY_ARGUMENTS))
                || !workingDirectory.getText().toString().equals(baseline.getString(Library.KEY_WORKING_DIRECTORY))
                || !pointerSpeed.getText().toString().equals(baseline.getString("pointer_speed"));
    }

    private void close() {
        if (!dirty()) {
            finish();
            return;
        }
        Theming.dialog(this).setTitle(R.string.program_discard)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.program_discard_action, (dialog, which) -> finish()).show();
    }

    @Override
    protected void onSaveInstanceState(Bundle state) {
        super.onSaveInstanceState(state);
        Bundle saved = new Bundle();
        for (Map.Entry<String, String> change : changes.entrySet()) {
            saved.putString(change.getKey(), change.getValue());
        }
        state.putBundle(STATE_CHANGES, saved);
        state.putBundle(STATE_BASELINE, baseline);
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == REQUEST_CONTROLS && result == RESULT_OK) {
            try {
                program = library.find(program.id());
                changes.remove("layout");
                changes.remove("controls");
                bindOptions();
            } catch (IOException failure) {
                Toast.makeText(this, failure.getMessage(), Toast.LENGTH_LONG).show();
            }
        }
    }
}
