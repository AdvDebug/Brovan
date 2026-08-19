package dev.brovan.app;

import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import android.text.Editable;
import android.text.TextWatcher;
import android.text.format.Formatter;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.HorizontalScrollView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.documentfile.provider.DocumentFile;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.progressindicator.CircularProgressIndicator;
import com.google.android.material.snackbar.Snackbar;
import com.google.android.material.textfield.TextInputEditText;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Date;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Executor;

/**
 * Browses the emulator's own storage. The imported programs, the Windows system files and the
 * emulated C: drive all sit under {@link Context#getFilesDir()}, which no other app can reach.
 */
final class FileBrowser {

    static final int REQUEST_IMPORT = 4;
    static final int REQUEST_EXPORT = 5;

    /// Read in one piece to keep the editor responsive. A longer file opens read-only.
    private static final int TEXT_LIMIT = 128 * 1024;
    private static final int COPY_BUFFER = 64 * 1024;
    private static final int SPINNER_DELAY = 150;

    private final AppCompatActivity activity;
    private final Executor worker;
    private final File root;

    private final List<Entry> loaded = new ArrayList<>();
    private final List<Entry> shown = new ArrayList<>();
    private final Deque<Integer> resumeAt = new ArrayDeque<>();
    private final EntryAdapter adapter = new EntryAdapter();

    private View view;
    private RecyclerView entries;
    private LinearLayout path;
    private HorizontalScrollView pathScroll;
    private TextView summary;
    private TextView empty;
    private TextInputEditText filter;
    private CircularProgressIndicator progress;

    private File current;
    private String query = "";
    private long freeSpace;
    private int generation;
    private int settled;
    private int pendingScroll = -1;
    private File exporting;

    FileBrowser(AppCompatActivity activity, Executor worker) {
        this.activity = activity;
        this.worker = worker;
        this.root = activity.getFilesDir();
    }

    View create(ViewGroup parent) {
        view = LayoutInflater.from(activity).inflate(R.layout.screen_files, parent, false);

        path = view.findViewById(R.id.path);
        pathScroll = view.findViewById(R.id.path_scroll);
        summary = view.findViewById(R.id.files_summary);
        empty = view.findViewById(R.id.files_empty);
        progress = view.findViewById(R.id.files_progress);
        filter = view.findViewById(R.id.files_filter);

        entries = view.findViewById(R.id.entries);
        entries.setLayoutManager(new LinearLayoutManager(activity));
        entries.setHasFixedSize(true);
        entries.setItemAnimator(null);
        entries.setAdapter(adapter);

        filter.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence text, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence text, int start, int before, int count) {
            }

            @Override
            public void afterTextChanged(Editable text) {
                query = text.toString().trim().toLowerCase(Locale.ROOT);
                applyFilter();
            }
        });

        view.findViewById(R.id.files_add).setOnClickListener(button -> showAddOptions());

        open(root);
        return view;
    }

    /** Walks back up one folder, or reports that the browser is already at the top. */
    boolean goUp() {
        if (current == null || current.equals(root)) {
            return false;
        }

        File parent = current.getParentFile();
        if (parent == null) {
            return false;
        }

        pendingScroll = resumeAt.isEmpty() ? -1 : resumeAt.pop();
        open(parent);
        return true;
    }

    void refresh() {
        if (current != null) {
            load();
        }
    }

    void onPicked(int requestCode, Intent data) {
        if (data == null) {
            return;
        }

        if (requestCode == REQUEST_EXPORT) {
            if (data.getData() != null) {
                exportTo(data.getData());
            }
            return;
        }

        List<Uri> sources = new ArrayList<>();
        ClipData clip = data.getClipData();

        if (clip != null) {
            for (int index = 0; index < clip.getItemCount(); index++) {
                sources.add(clip.getItemAt(index).getUri());
            }
        } else if (data.getData() != null) {
            sources.add(data.getData());
        }

        if (!sources.isEmpty()) {
            importInto(sources);
        }
    }

    private void open(File folder) {
        current = folder;

        if (!query.isEmpty()) {
            filter.setText("");
        }

        showPath();
        load();
    }

    private void load() {
        int token = ++generation;
        File folder = current;

        // A folder that lists in a few milliseconds should not flash a spinner on the way past.
        entries.postDelayed(() -> {
            if (token == generation && settled != token) {
                progress.setVisibility(View.VISIBLE);
            }
        }, SPINNER_DELAY);

        worker.execute(() -> {
            List<Entry> found = read(activity, folder);
            long free = root.getUsableSpace();

            activity.runOnUiThread(() -> {
                if (token != generation || activity.isDestroyed()) {
                    return;
                }

                settled = token;
                loaded.clear();
                loaded.addAll(found);
                freeSpace = free;

                progress.setVisibility(View.GONE);
                applyFilter();

                if (pendingScroll >= 0) {
                    entries.scrollToPosition(Math.min(pendingScroll, Math.max(0, shown.size() - 1)));
                    pendingScroll = -1;
                }
            });
        });
    }

    /**
     * Lists one folder with a single stat per entry. isDirectory, length and lastModified each cost
     * their own, which the System32 listing alone would pay several thousand times.
     */
    private static List<Entry> read(Context context, File folder) {
        List<Entry> found = new ArrayList<>();
        String[] names = folder.list();

        if (names == null) {
            return found;
        }

        DateFormat dates = android.text.format.DateFormat.getDateFormat(context);
        String folderLabel = context.getString(R.string.files_folder);
        StringBuilder child = new StringBuilder(folder.getPath()).append('/');
        int base = child.length();

        for (String name : names) {
            child.setLength(base);
            child.append(name);

            StructStat stat;
            try {
                stat = Os.stat(child.toString());
            } catch (ErrnoException unreachable) {
                found.add(new Entry(name, false, context.getString(R.string.files_unreadable)));
                continue;
            }

            boolean directory = OsConstants.S_ISDIR(stat.st_mode);
            String size = directory ? folderLabel : Formatter.formatShortFileSize(context, stat.st_size);
            String detail = context.getString(R.string.files_detail, size,
                    dates.format(new Date(stat.st_mtime * 1000L)));

            found.add(new Entry(name, directory, detail));
        }

        found.sort((left, right) -> left.folder != right.folder
                ? (left.folder ? -1 : 1)
                : String.CASE_INSENSITIVE_ORDER.compare(left.name, right.name));

        return found;
    }

    private void applyFilter() {
        shown.clear();

        if (query.isEmpty()) {
            shown.addAll(loaded);
        } else {
            for (int index = 0; index < loaded.size(); index++) {
                Entry entry = loaded.get(index);
                if (entry.lower.contains(query)) {
                    shown.add(entry);
                }
            }
        }

        adapter.notifyDataSetChanged();

        boolean filtered = !query.isEmpty();
        summary.setText(filtered
                ? activity.getString(R.string.files_summary_filtered, shown.size(), loaded.size())
                : activity.getString(R.string.files_summary, loaded.size(),
                        Formatter.formatShortFileSize(activity, freeSpace)));

        empty.setText(filtered ? R.string.files_no_match : R.string.files_empty);
        empty.setVisibility(shown.isEmpty() ? View.VISIBLE : View.GONE);
    }

    private void showPath() {
        path.removeAllViews();

        List<File> chain = new ArrayList<>();
        for (File folder = current; folder != null; folder = folder.getParentFile()) {
            chain.add(folder);
            if (folder.equals(root)) {
                break;
            }
        }

        for (int index = chain.size() - 1; index >= 0; index--) {
            File folder = chain.get(index);

            if (index != chain.size() - 1) {
                TextView divider = new TextView(activity, null, 0, R.style.PathSeparator);
                divider.setText(R.string.files_separator);
                path.addView(divider);
            }

            TextView segment = new TextView(activity, null, 0, R.style.PathSegment);
            segment.setText(folder.equals(root) ? activity.getString(R.string.files_root) : folder.getName());

            if (index == 0) {
                segment.setTextColor(activity.getColor(R.color.text_primary));
            } else {
                segment.setOnClickListener(button -> {
                    resumeAt.clear();
                    open(folder);
                });
            }

            path.addView(segment);
        }

        pathScroll.post(() -> pathScroll.fullScroll(View.FOCUS_RIGHT));
    }

    private void showAddOptions() {
        new AlertDialog.Builder(activity)
                .setTitle(R.string.files_add_title)
                .setItems(new CharSequence[]{
                        activity.getString(R.string.files_new_folder),
                        activity.getString(R.string.files_import),
                        activity.getString(R.string.files_refresh)}, (dialog, index) -> {
                    if (index == 0) {
                        newFolder();
                    } else if (index == 1) {
                        launch(new Intent(Intent.ACTION_OPEN_DOCUMENT)
                                .addCategory(Intent.CATEGORY_OPENABLE)
                                .putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
                                .setType("*/*"), REQUEST_IMPORT);
                    } else {
                        load();
                    }
                })
                .show();
    }

    private void showActions(Entry entry) {
        File target = new File(current, entry.name);

        List<CharSequence> labels = new ArrayList<>();
        List<Runnable> actions = new ArrayList<>();

        if (!entry.folder) {
            labels.add(activity.getString(R.string.files_open));
            actions.add(() -> openText(target));

            labels.add(activity.getString(R.string.files_export));
            actions.add(() -> {
                exporting = target;
                launch(new Intent(Intent.ACTION_CREATE_DOCUMENT)
                        .addCategory(Intent.CATEGORY_OPENABLE)
                        .putExtra(Intent.EXTRA_TITLE, entry.name)
                        .setType("application/octet-stream"), REQUEST_EXPORT);
            });
        }

        labels.add(activity.getString(R.string.files_rename));
        actions.add(() -> rename(target));

        labels.add(activity.getString(R.string.files_delete));
        actions.add(() -> confirmDelete(target, entry.folder));

        new AlertDialog.Builder(activity)
                .setTitle(entry.name)
                .setItems(labels.toArray(new CharSequence[0]), (dialog, index) -> actions.get(index).run())
                .show();
    }

    private void openText(File file) {
        progress.setVisibility(View.VISIBLE);
        worker.execute(() -> {
            byte[] data;
            boolean truncated = file.length() > TEXT_LIMIT;

            try {
                data = readCapped(file);
            } catch (IOException failure) {
                activity.runOnUiThread(() -> {
                    progress.setVisibility(View.GONE);
                    snack(activity.getString(R.string.files_read_failed));
                });
                return;
            }

            String text;
            boolean binary = false;

            try {
                text = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(data)).toString();
            } catch (CharacterCodingException notText) {
                text = new String(data, StandardCharsets.UTF_8);
                binary = true;
            }

            String body = text;
            boolean unedited = binary;
            activity.runOnUiThread(() -> {
                progress.setVisibility(View.GONE);
                if (!activity.isDestroyed()) {
                    showText(file, body, truncated, unedited);
                }
            });
        });
    }

    private void showText(File file, String text, boolean truncated, boolean binary) {
        View body = LayoutInflater.from(activity).inflate(R.layout.dialog_file_text, null, false);
        EditText editor = body.findViewById(R.id.text_body);
        editor.setText(text);

        AlertDialog.Builder builder = new AlertDialog.Builder(activity)
                .setTitle(file.getName())
                .setView(body)
                .setNegativeButton(android.R.string.cancel, null);

        // Saving a file the decoder could not read would write the replacement characters back over it.
        if (truncated || binary) {
            TextView note = body.findViewById(R.id.text_note);
            note.setVisibility(View.VISIBLE);
            note.setText(binary
                    ? activity.getString(R.string.files_binary)
                    : activity.getString(R.string.files_truncated,
                            Formatter.formatShortFileSize(activity, TEXT_LIMIT)));
            editor.setKeyListener(null);
        } else {
            builder.setPositiveButton(R.string.files_save,
                    (dialog, button) -> saveText(file, editor.getText().toString()));
        }

        builder.show();
    }

    private void saveText(File file, String text) {
        worker.execute(() -> {
            boolean saved = true;

            try (OutputStream output = new FileOutputStream(file)) {
                output.write(text.getBytes(StandardCharsets.UTF_8));
            } catch (IOException failure) {
                saved = false;
            }

            boolean written = saved;
            activity.runOnUiThread(() -> {
                if (activity.isDestroyed()) {
                    return;
                }

                if (written) {
                    load();
                } else {
                    snack(activity.getString(R.string.files_write_failed));
                }
            });
        });
    }

    private void newFolder() {
        askName(R.string.files_new_folder, "", name -> {
            File target = new File(current, name);

            if (target.exists()) {
                snack(activity.getString(R.string.files_name_taken));
                return;
            }

            if (target.mkdir()) {
                load();
            } else {
                snack(activity.getString(R.string.files_folder_failed));
            }
        });
    }

    private void rename(File target) {
        askName(R.string.files_rename, target.getName(), name -> {
            File renamed = new File(current, name);

            if (renamed.exists()) {
                snack(activity.getString(R.string.files_name_taken));
                return;
            }

            if (target.renameTo(renamed)) {
                load();
            } else {
                snack(activity.getString(R.string.files_rename_failed, target.getName()));
            }
        });
    }

    private void askName(int titleId, String initial, NameListener listener) {
        View body = LayoutInflater.from(activity).inflate(R.layout.dialog_file_name, null, false);
        TextInputEditText field = body.findViewById(R.id.file_name);
        field.setText(initial);
        field.setSelection(initial.length());

        new AlertDialog.Builder(activity)
                .setTitle(titleId)
                .setView(body)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(android.R.string.ok, (dialog, button) -> {
                    CharSequence typed = field.getText();
                    String name = typed == null ? "" : typed.toString().trim();

                    if (usable(name)) {
                        listener.onName(name);
                    } else {
                        snack(activity.getString(R.string.files_name_invalid));
                    }
                })
                .show();
    }

    private void confirmDelete(File target, boolean folder) {
        new AlertDialog.Builder(activity)
                .setTitle(activity.getString(folder ? R.string.files_delete_folder : R.string.files_delete_file,
                        target.getName()))
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.files_delete, (dialog, button) -> {
                    progress.setVisibility(View.VISIBLE);
                    worker.execute(() -> {
                        Library.delete(target);
                        boolean gone = !target.exists();

                        activity.runOnUiThread(() -> {
                            if (activity.isDestroyed()) {
                                return;
                            }

                            snack(activity.getString(gone ? R.string.files_deleted : R.string.files_delete_failed,
                                    target.getName()));
                            load();
                        });
                    });
                })
                .show();
    }

    private void importInto(List<Uri> sources) {
        File folder = current;

        progress.setVisibility(View.VISIBLE);
        worker.execute(() -> {
            int copied = 0;

            for (Uri source : sources) {
                DocumentFile document = DocumentFile.fromSingleUri(activity, source);
                String name = document == null ? null : document.getName();

                if (name == null) {
                    continue;
                }

                try {
                    Library.copyFile(activity, source, freeName(folder, name));
                    copied++;
                } catch (IOException failure) {
                    // The count reported below carries the failures.
                }
            }

            int done = copied;
            activity.runOnUiThread(() -> {
                if (activity.isDestroyed()) {
                    return;
                }

                snack(done == 0
                        ? activity.getString(R.string.files_import_failed)
                        : activity.getString(R.string.files_imported, done, sources.size()));
                load();
            });
        });
    }

    private void exportTo(Uri destination) {
        File source = exporting;
        exporting = null;

        if (source == null) {
            return;
        }

        progress.setVisibility(View.VISIBLE);
        worker.execute(() -> {
            boolean saved = true;

            try (InputStream input = new FileInputStream(source);
                 OutputStream output = activity.getContentResolver().openOutputStream(destination)) {
                if (output == null) {
                    throw new IOException("no destination");
                }

                byte[] buffer = new byte[COPY_BUFFER];
                int read;
                while ((read = input.read(buffer)) > 0) {
                    output.write(buffer, 0, read);
                }
            } catch (IOException failure) {
                saved = false;
            }

            boolean written = saved;
            activity.runOnUiThread(() -> {
                if (activity.isDestroyed()) {
                    return;
                }

                progress.setVisibility(View.GONE);
                snack(written
                        ? activity.getString(R.string.files_exported, source.getName())
                        : activity.getString(R.string.files_export_failed));
            });
        });
    }

    private void launch(Intent intent, int requestCode) {
        try {
            activity.startActivityForResult(intent, requestCode);
        } catch (ActivityNotFoundException missing) {
            snack(activity.getString(R.string.setup_no_picker));
        }
    }

    private void snack(String message) {
        Snackbar.make(view, message, Snackbar.LENGTH_LONG).show();
    }

    private int firstVisible() {
        LinearLayoutManager layout = (LinearLayoutManager) entries.getLayoutManager();
        return layout == null ? 0 : Math.max(0, layout.findFirstVisibleItemPosition());
    }

    private static byte[] readCapped(File file) throws IOException {
        try (InputStream input = new FileInputStream(file)) {
            ByteArrayOutputStream collected = new ByteArrayOutputStream(COPY_BUFFER);
            byte[] buffer = new byte[COPY_BUFFER];
            int total = 0;
            int read;

            while (total < TEXT_LIMIT
                    && (read = input.read(buffer, 0, Math.min(buffer.length, TEXT_LIMIT - total))) > 0) {
                collected.write(buffer, 0, read);
                total += read;
            }

            return collected.toByteArray();
        }
    }

    private static File freeName(File folder, String name) {
        File candidate = new File(folder, name);
        if (!candidate.exists()) {
            return candidate;
        }

        int dot = name.lastIndexOf('.');
        String stem = dot > 0 ? name.substring(0, dot) : name;
        String extension = dot > 0 ? name.substring(dot) : "";

        for (int suffix = 2; candidate.exists(); suffix++) {
            candidate = new File(folder, stem + " (" + suffix + ")" + extension);
        }

        return candidate;
    }

    private static boolean usable(String name) {
        return !name.isEmpty() && !name.equals(".") && !name.equals("..")
                && name.indexOf('/') < 0 && name.indexOf('\0') < 0;
    }

    private interface NameListener {
        void onName(String name);
    }

    private static final class Entry {
        final String name;
        final String lower;
        final String detail;
        final boolean folder;

        Entry(String name, boolean folder, String detail) {
            this.name = name;
            this.lower = name.toLowerCase(Locale.ROOT);
            this.folder = folder;
            this.detail = detail;
        }
    }

    private final class EntryAdapter extends RecyclerView.Adapter<EntryHolder> {

        @NonNull
        @Override
        public EntryHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            return new EntryHolder(LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_file, parent, false));
        }

        @Override
        public void onBindViewHolder(@NonNull EntryHolder holder, int position) {
            Entry entry = shown.get(position);
            holder.name.setText(entry.name);
            holder.detail.setText(entry.detail);
            holder.icon.setImageResource(entry.folder ? R.drawable.ic_folder : R.drawable.ic_file);
        }

        @Override
        public int getItemCount() {
            return shown.size();
        }
    }

    /// The listeners are bound once per holder, so scrolling a folder of several thousand files
    /// does not allocate a closure for every row it passes.
    private final class EntryHolder extends RecyclerView.ViewHolder {
        final ImageView icon;
        final TextView name;
        final TextView detail;

        EntryHolder(View row) {
            super(row);
            icon = row.findViewById(R.id.icon);
            name = row.findViewById(R.id.name);
            detail = row.findViewById(R.id.detail);

            row.setOnClickListener(button -> {
                Entry entry = bound();
                if (entry == null) {
                    return;
                }

                if (entry.folder) {
                    resumeAt.push(firstVisible());
                    open(new File(current, entry.name));
                } else {
                    showActions(entry);
                }
            });

            row.setOnLongClickListener(button -> {
                Entry entry = bound();
                if (entry != null) {
                    showActions(entry);
                }
                return true;
            });
        }

        private Entry bound() {
            int position = getBindingAdapterPosition();
            return position < 0 || position >= shown.size() ? null : shown.get(position);
        }
    }
}
