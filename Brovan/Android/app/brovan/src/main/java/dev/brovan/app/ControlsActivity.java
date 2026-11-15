package dev.brovan.app;

import android.os.Bundle;
import java.io.IOException;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import dev.brovan.input.ControlLayout;
import dev.brovan.input.ControlOverlay;

public class ControlsActivity extends AppCompatActivity implements ControlEditor.Host {

    static final String EXTRA_LAYOUT = "initial_layout";

    private Settings settings;
    private Library library;
    private Program program;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        settings = new Settings(this);
        Palette palette = settings.palette();
        Theming.install(this, palette);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_controls);
        Theming.apply(this, Palette.defaults(), palette);

        ControlOverlay overlay = findViewById(R.id.controls);

        library = new Library(this);
        String profileId = getIntent().getStringExtra(ProgramSettings.EXTRA_PROFILE_ID);
        String initial = getIntent().getStringExtra(EXTRA_LAYOUT);
        if (profileId != null) {
            try {
                program = library.find(profileId);
                if (initial == null) {
                    initial = new ProgramSettings(library, program, settings).controlLayout();
                }
            } catch (IOException failure) {
                Toast.makeText(this, failure.getMessage(), Toast.LENGTH_LONG).show();
                finish();
                return;
            }
        }
        ControlLayout layout = ControlLayout.fromJson(initial == null ? settings.controlLayout() : initial);
        if (layout.items().isEmpty()) {
            layout = ControlLayout.forScheme(ControlOverlay.Scheme.WASD);
        }

        overlay.setAccent(palette.get(Palette.Role.ACCENT), palette.get(Palette.Role.ON_ACCENT));
        new ControlEditor(this, overlay, findViewById(R.id.control_editor), palette, this).start(layout);
    }

    @Override
    public void onSave(ControlLayout layout) {
        if (program == null) {
            settings.setControlLayout(layout.toJson());
            settings.setControlScheme(ControlOverlay.Scheme.CUSTOM.ordinal());
        } else {
            try {
                new ProgramSettings(library, program, settings).setCustomLayout(layout.toJson());
            } catch (IOException failure) {
                Toast.makeText(this, getString(R.string.program_save_failed, failure.getMessage()),
                        Toast.LENGTH_LONG).show();
                return;
            }
        }
        setResult(RESULT_OK);
        finish();
    }

    @Override
    public void onCancel() {
        finish();
    }
}
