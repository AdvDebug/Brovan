package dev.brovan.app;

import android.content.Context;
import android.net.Uri;
import android.util.AtomicFile;

import androidx.documentfile.provider.DocumentFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.channels.FileLock;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.HashSet;
import java.util.UUID;

final class Library {

    private static final String ROOT = "programs";
    private static final String MANIFEST = "program.properties";
    static final String KEY_NAME = "name";
    static final String KEY_EXECUTABLE = "executable";
    static final String KEY_ARGUMENTS = "arguments";
    static final String KEY_WORKING_DIRECTORY = "working_directory";
    private static final String KEY_DIRECTORY = "directory";
    private static final Object STORE_GATE = new Object();

    private final File root;
    private final File store;

    Library(Context context) {
        root = new File(context.getFilesDir(), ROOT);
        store = context.getDir("launcher", Context.MODE_PRIVATE);
    }

    List<Program> list() throws IOException {
        return locked(() -> {
            migrate();
            List<Program> programs = readPrograms();
            programs.removeIf(program -> !program.directory().isDirectory());
            programs.sort(Comparator.comparing(program -> program.name().toLowerCase(Locale.ROOT)));
            return programs;
        });
    }

    Program find(String id) throws IOException {
        return locked(() -> readProgram(id));
    }

    private List<Program> readPrograms() throws IOException {
        List<Program> programs = new ArrayList<>();
        for (String id : profileIds()) {
            programs.add(readProgram(id));
        }
        return programs;
    }

    private Set<String> profileIds() throws IOException {
        String[] names = store.list();
        if (names == null) {
            throw new IOException("Could not read the program library.");
        }
        Set<String> ids = new HashSet<>();
        for (String name : names) {
            String suffix = name.endsWith(".properties.bak") ? ".properties.bak" : ".properties";
            if (name.endsWith(suffix)) {
                ids.add(name.substring(0, name.length() - suffix.length()));
            }
        }
        return ids;
    }

    private Program readProgram(String id) throws IOException {
        Properties values = read(record(id));
        String directory = values.getProperty(KEY_DIRECTORY);
        if (directory == null || values.getProperty(KEY_EXECUTABLE) == null) {
            throw new IOException("The program profile is incomplete.");
        }
        return new Program(id, child(root, directory), values, readRun(id).getProperty("failure", ""));
    }

    Program update(String id, Map<String, String> changes) throws IOException {
        return locked(() -> {
            Properties values = read(record(id));
            for (Map.Entry<String, String> change : changes.entrySet()) {
                if (KEY_DIRECTORY.equals(change.getKey())) {
                    throw new IOException("The program directory cannot be changed here.");
                }
                if (change.getValue() == null) {
                    values.remove(change.getKey());
                } else {
                    values.setProperty(change.getKey(), change.getValue());
                }
            }
            File directory = child(root, values.getProperty(KEY_DIRECTORY, ""));
            File executable = child(directory, values.getProperty(KEY_EXECUTABLE, ""));
            if (!executable.isFile()) {
                throw new IOException("Choose an executable in the program folder.");
            }
            String workingDirectory = values.getProperty(KEY_WORKING_DIRECTORY, "");
            if (!workingDirectory.isEmpty() && !workingDirectory.equals(".") && !isGuestPath(workingDirectory)
                    && !child(executable.getParentFile(), workingDirectory).isDirectory()) {
                throw new IOException("The start-in folder does not exist.");
            }
            if (values.getProperty(KEY_NAME, "").trim().isEmpty()) {
                throw new IOException("Enter a program name.");
            }
            write(record(id), values);
            return readProgram(id);
        });
    }

    private void migrate() throws IOException {
        File done = new File(store, "migrated");
        if (done.exists()) {
            return;
        }
        List<Program> existing = readPrograms();
        File[] directories = root.listFiles(File::isDirectory);
        if (directories == null) {
            if (root.exists()) {
                throw new IOException("Could not read imported program folders.");
            }
            directories = new File[0];
        }
        for (File directory : directories) {
            File legacy = new File(directory, MANIFEST);
            if (!legacy.isFile() && !new File(directory, MANIFEST + ".bak").isFile()) {
                continue;
            }
            Properties values = read(new AtomicFile(legacy));
            String executable = values.getProperty(KEY_EXECUTABLE);
            if (executable == null || !child(directory, executable).isFile()) {
                continue;
            }
            Program previous = null;
            for (Program program : existing) {
                if (program.directory().getCanonicalFile().equals(directory.getCanonicalFile())) {
                    previous = program;
                    break;
                }
            }
            String id = previous == null ? UUID.randomUUID().toString() : previous.id();
            File backup = new File(store, id + ".legacy");
            if (!backup.exists() && !new File(store, id + ".legacy.bak").exists()) {
                copyBackup(legacy, new AtomicFile(backup));
            }
            if (previous == null) {
                Properties migrated = new Properties();
                migrated.putAll(values);
                migrated.setProperty(KEY_DIRECTORY, directory.getName());
                write(record(id), migrated);
                existing.add(readProgram(id));
            }
            values.remove(KEY_NAME);
            values.remove(KEY_EXECUTABLE);
            values.remove(KEY_ARGUMENTS);
            values.remove(KEY_WORKING_DIRECTORY);
            for (String key : ProgramSettings.OVERRIDE_KEYS) {
                values.remove(key);
            }
            if (values.isEmpty()) {
                new AtomicFile(legacy).delete();
                if (legacy.exists()) {
                    throw new IOException("Could not remove the old program settings.");
                }
            } else {
                stripLegacySettings(legacy);
            }
        }
        if (!done.createNewFile() && !done.exists()) {
            throw new IOException("Could not finish migrating the program library.");
        }
    }

    /** Copies a whole folder, then reports the executables it contains so the caller can pick the entry. */
    ImportResult importFolder(Context context, Uri treeUri) throws IOException {
        DocumentFile source = DocumentFile.fromTreeUri(context, treeUri);
        if (source == null || !source.isDirectory()) {
            throw new IOException("That is not a folder.");
        }

        File destination = allocate(source.getName());
        copyTree(context, source, destination);
        return new ImportResult(destination, findExecutables(destination));
    }

    ImportResult importExecutable(Context context, Uri fileUri) throws IOException {
        DocumentFile source = DocumentFile.fromSingleUri(context, fileUri);
        if (source == null || !source.isFile()) {
            throw new IOException("That is not a file.");
        }

        String fileName = source.getName();
        if (fileName == null) {
            throw new IOException("That file has no name.");
        }

        File destination = allocate(stripExtension(fileName));
        if (!destination.mkdirs() && !destination.isDirectory()) {
            throw new IOException("Could not create " + destination);
        }

        copyFile(context, source.getUri(), new File(destination, fileName));
        return new ImportResult(destination, findExecutables(destination));
    }

    Program commit(File directory, String executableRelativePath) throws IOException {
        return locked(() -> {
            migrate();
            if (!child(root, directory.getName()).equals(directory.getCanonicalFile())
                    || !child(directory, executableRelativePath).isFile()) {
                throw new IOException("The imported program is not in the library.");
            }
            String id = UUID.randomUUID().toString();
            Properties values = new Properties();
            values.setProperty(KEY_DIRECTORY, directory.getName());
            values.setProperty(KEY_NAME, directory.getName());
            values.setProperty(KEY_EXECUTABLE, executableRelativePath);
            write(record(id), values);
            return readProgram(id);
        });
    }

    void remove(Program program) throws IOException {
        delete(program.directory());
        if (program.directory().exists()) {
            throw new IOException("Some program files could not be deleted.");
        }
        filesRemoved(program.directory());
    }

    void discard(File directory) {
        delete(directory);
    }

    void filesRemoved(File target) throws IOException {
        locked(() -> {
            for (Program program : readPrograms()) {
                if (within(program.directory(), target) && !program.directory().exists()) {
                    record(program.id()).delete();
                    runRecord(program.id()).delete();
                    new AtomicFile(new File(store, program.id() + ".legacy")).delete();
                }
            }
            return null;
        });
    }

    void renamed(File source, File destination) throws IOException {
        locked(() -> {
            for (String id : profileIds()) {
                AtomicFile record = record(id);
                Properties values = read(record);
                File directory = child(root, values.getProperty(KEY_DIRECTORY, ""));
                File executable = child(directory, values.getProperty(KEY_EXECUTABLE, ""));
                boolean changed = false;
                if (within(directory, source)) {
                    values.setProperty(KEY_DIRECTORY, relative(root, replaceRoot(directory, source, destination)));
                    changed = true;
                } else {
                    if (within(executable, source)) {
                        values.setProperty(KEY_EXECUTABLE,
                                relative(directory, replaceRoot(executable, source, destination)));
                        changed = true;
                    }
                    String start = values.getProperty(KEY_WORKING_DIRECTORY, "");
                    File imageDirectory = executable.getParentFile();
                    if (!start.isEmpty() && !start.equals(".") && !isGuestPath(start)
                            && !within(imageDirectory, source) && within(child(imageDirectory, start), source)) {
                        values.setProperty(KEY_WORKING_DIRECTORY,
                                relative(imageDirectory, replaceRoot(child(imageDirectory, start), source, destination)));
                        changed = true;
                    }
                }
                if (changed) {
                    write(record, values);
                }
            }
            return null;
        });
    }

    private static File replaceRoot(File path, File source, File destination) throws IOException {
        String tail = path.getCanonicalPath().substring(source.getCanonicalPath().length());
        return new File(destination.getCanonicalPath() + tail);
    }

    static boolean isGuestPath(String path) {
        return path.startsWith("\\\\") || (path.length() >= 3 && Character.isLetter(path.charAt(0))
                && path.charAt(1) == ':' && (path.charAt(2) == '\\' || path.charAt(2) == '/'));
    }

    static File child(File directory, String relative) throws IOException {
        File base = directory.getCanonicalFile();
        File result = new File(base, relative).getCanonicalFile();
        if (relative.isEmpty() || !within(result, base) || result.equals(base)) {
            throw new IOException("The path must stay inside the program folder.");
        }
        return result;
    }

    private static boolean within(File file, File parent) throws IOException {
        String path = file.getCanonicalPath();
        String base = parent.getCanonicalPath();
        return path.equals(base) || path.startsWith(base + File.separator);
    }

    private static String relative(File root, File child) throws IOException {
        if (!within(child, root) || child.getCanonicalFile().equals(root.getCanonicalFile())) {
            throw new IOException("The path is outside the library.");
        }
        return child.getCanonicalPath().substring(root.getCanonicalPath().length() + 1);
    }

    String beginRun(String id, int pid) throws IOException {
        return locked(() -> {
            read(record(id));
            String token = UUID.randomUUID().toString();
            Properties run = new Properties();
            run.setProperty("token", token);
            run.setProperty("pid", Integer.toString(pid));
            run.setProperty("started", Long.toString(System.currentTimeMillis()));
            run.setProperty("running", "true");
            write(runRecord(id), run);
            return token;
        });
    }

    void finishRun(String id, String token, String failure) throws IOException {
        locked(() -> {
            Properties run = readRun(id);
            if (!token.equals(run.getProperty("token"))) {
                return null;
            }
            run.setProperty("running", "false");
            run.setProperty("failure", failure == null ? "" : failure);
            write(runRecord(id), run);
            return null;
        });
    }

    void checkRuns(Set<Integer> activePids) throws IOException {
        locked(() -> {
            for (Program program : readPrograms()) {
                Properties run = readRun(program.id());
                if (!Boolean.parseBoolean(run.getProperty("running"))) {
                    continue;
                }
                int pid;
                try {
                    pid = Integer.parseInt(run.getProperty("pid", "0"));
                } catch (NumberFormatException invalid) {
                    throw new IOException("The last run record could not be read.", invalid);
                }
                if (!activePids.contains(pid)) {
                    run.setProperty("running", "false");
                    run.setProperty("failure", "The program stopped without reporting an exit.");
                    write(runRecord(program.id()), run);
                }
            }
            return null;
        });
    }

    private Properties readRun(String id) throws IOException {
        AtomicFile file = runRecord(id);
        try {
            return read(file);
        } catch (FileNotFoundException absent) {
            File base = file.getBaseFile();
            if (base.exists() || new File(base.getPath() + ".bak").exists()) {
                throw absent;
            }
            return new Properties();
        }
    }

    private AtomicFile record(String id) throws IOException {
        checkId(id);
        return new AtomicFile(new File(store, id + ".properties"));
    }

    private AtomicFile runRecord(String id) throws IOException {
        checkId(id);
        return new AtomicFile(new File(store, id + ".run"));
    }

    private static void checkId(String id) throws IOException {
        try {
            if (id == null || !UUID.fromString(id).toString().equals(id)) {
                throw new IllegalArgumentException();
            }
        } catch (IllegalArgumentException invalid) {
            throw new IOException("The program ID is invalid.", invalid);
        }
    }

    private static Properties read(AtomicFile file) throws IOException {
        Properties values = new Properties();
        try (InputStream input = file.openRead()) {
            values.load(input);
        } catch (IllegalArgumentException invalid) {
            throw new IOException("The program profile could not be read.", invalid);
        }
        return values;
    }

    private static void write(AtomicFile file, Properties values) throws IOException {
        FileOutputStream output = file.startWrite();
        try {
            values.store(output, null);
            file.finishWrite(output);
        } catch (IOException | RuntimeException failure) {
            file.failWrite(output);
            throw failure;
        }
        if (!read(file).equals(values)) {
            throw new IOException("The program settings were not saved.");
        }
    }

    private static void copyBackup(File source, AtomicFile destination) throws IOException {
        FileOutputStream output = destination.startWrite();
        try (InputStream input = new FileInputStream(source)) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) {
                output.write(buffer, 0, count);
            }
            destination.finishWrite(output);
        } catch (IOException | RuntimeException failure) {
            destination.failWrite(output);
            throw failure;
        }
    }

    private static void stripLegacySettings(File source) throws IOException {
        Set<String> keys = new HashSet<>();
        keys.add(KEY_NAME);
        keys.add(KEY_EXECUTABLE);
        keys.add(KEY_ARGUMENTS);
        keys.add(KEY_WORKING_DIRECTORY);
        java.util.Collections.addAll(keys, ProgramSettings.OVERRIDE_KEYS);
        String text = new String(Files.readAllBytes(source.toPath()), StandardCharsets.ISO_8859_1);
        String[] lines = text.split("(?<=\\n)|(?<=\\r)(?!\\n)");
        StringBuilder kept = new StringBuilder();
        for (int index = 0; index < lines.length; index++) {
            StringBuilder block = new StringBuilder(lines[index]);
            String trimmed = lines[index].trim();
            if (!trimmed.isEmpty() && !trimmed.startsWith("#") && !trimmed.startsWith("!")) {
                while (continued(lines[index]) && index + 1 < lines.length) {
                    block.append(lines[++index]);
                }
            }
            Properties entry = new Properties();
            entry.load(new StringReader(block.toString()));
            if (java.util.Collections.disjoint(entry.stringPropertyNames(), keys)) {
                kept.append(block);
            }
        }
        AtomicFile file = new AtomicFile(source);
        FileOutputStream output = file.startWrite();
        try {
            output.write(kept.toString().getBytes(StandardCharsets.ISO_8859_1));
            file.finishWrite(output);
        } catch (IOException | RuntimeException failure) {
            file.failWrite(output);
            throw failure;
        }
    }

    private static boolean continued(String line) {
        int end = line.length();
        while (end != 0 && (line.charAt(end - 1) == '\r' || line.charAt(end - 1) == '\n')) {
            end--;
        }
        int start = end;
        while (start != 0 && line.charAt(start - 1) == '\\') {
            start--;
        }
        return (end - start) % 2 != 0;
    }

    private interface StoreAction<T> {
        T run() throws IOException;
    }

    private <T> T locked(StoreAction<T> action) throws IOException {
        synchronized (STORE_GATE) {
            try (RandomAccessFile lockFile = new RandomAccessFile(new File(store, ".lock"), "rw");
                 FileLock held = lockFile.getChannel().lock()) {
                return action.run();
            }
        }
    }

    private File allocate(String preferredName) {
        String base = sanitize(preferredName);
        File candidate = new File(root, base);

        for (int suffix = 2; candidate.exists(); suffix++) {
            candidate = new File(root, base + " (" + suffix + ")");
        }

        return candidate;
    }

    private static void copyTree(Context context, DocumentFile source, File destination) throws IOException {
        if (!destination.mkdirs() && !destination.isDirectory()) {
            throw new IOException("Could not create " + destination);
        }

        for (DocumentFile child : source.listFiles()) {
            String name = child.getName();
            if (name == null) {
                continue;
            }

            File target = new File(destination, name);
            if (child.isDirectory()) {
                copyTree(context, child, target);
            } else {
                copyFile(context, child.getUri(), target);
            }
        }
    }

    static void copyFile(Context context, Uri source, File destination) throws IOException {
        try (InputStream input = context.getContentResolver().openInputStream(source);
             OutputStream output = new FileOutputStream(destination)) {
            if (input == null) {
                throw new IOException("Could not read " + source);
            }

            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = input.read(buffer)) > 0) {
                output.write(buffer, 0, read);
            }
        }
    }

    static List<String> findExecutables(File directory) {
        List<String> executables = new ArrayList<>();
        collectExecutables(directory, "", executables);
        executables.sort(Comparator.naturalOrder());
        return executables;
    }

    private static void collectExecutables(File directory, String prefix, List<String> into) {
        File[] entries = directory.listFiles();
        if (entries == null) {
            return;
        }

        for (File entry : entries) {
            String relative = prefix.isEmpty() ? entry.getName() : prefix + "/" + entry.getName();
            if (entry.isDirectory()) {
                collectExecutables(entry, relative, into);
            } else if (entry.getName().toLowerCase(Locale.ROOT).endsWith(".exe")) {
                into.add(relative);
            }
        }
    }

    private static String sanitize(String name) {
        if (name == null || name.trim().isEmpty()) {
            return "Program";
        }

        return name.replaceAll("[^A-Za-z0-9 ._-]", "_").trim();
    }

    private static String stripExtension(String name) {
        int dot = name.lastIndexOf('.');
        return dot > 0 ? name.substring(0, dot) : name;
    }

    static void delete(File file) {
        File[] children = file.listFiles();
        if (children != null) {
            for (File child : children) {
                delete(child);
            }
        }

        file.delete();
    }

    static final class ImportResult {
        final File directory;
        final List<String> executables;

        ImportResult(File directory, List<String> executables) {
            this.directory = directory;
            this.executables = executables;
        }
    }
}
