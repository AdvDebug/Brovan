package dev.brovan.app;

import android.content.Context;
import android.net.Uri;

import androidx.documentfile.provider.DocumentFile;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

/**
 * Imported programs, each stored in its own folder under files/programs so a program keeps the assets it
 * shipped with and can open them by relative path.
 */
final class Library {

    private static final String ROOT = "programs";
    private static final String MANIFEST = "program.properties";
    private static final String KEY_NAME = "name";
    private static final String KEY_EXECUTABLE = "executable";

    private final File root;

    Library(Context context) {
        root = new File(context.getFilesDir(), ROOT);
    }

    List<Program> list() {
        List<Program> programs = new ArrayList<>();
        File[] directories = root.listFiles(File::isDirectory);
        if (directories == null) {
            return programs;
        }

        for (File directory : directories) {
            Program program = read(directory);
            if (program != null) {
                programs.add(program);
            }
        }

        programs.sort(Comparator.comparing(program -> program.name().toLowerCase(Locale.ROOT)));
        return programs;
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

    void commit(File directory, String executableRelativePath) throws IOException {
        File file = new File(directory, MANIFEST);
        Properties manifest = new Properties();

        if (file.isFile()) {
            try (InputStream stream = new java.io.FileInputStream(file)) {
                manifest.load(stream);
            }
        }

        manifest.setProperty(KEY_NAME, directory.getName());
        manifest.setProperty(KEY_EXECUTABLE, executableRelativePath);

        try (OutputStream stream = new FileOutputStream(file)) {
            manifest.store(stream, null);
        }
    }

    void remove(Program program) {
        delete(program.directory());
    }

    void discard(File directory) {
        delete(directory);
    }

    private Program read(File directory) {
        File manifest = new File(directory, MANIFEST);
        if (!manifest.isFile()) {
            return null;
        }

        Properties properties = new Properties();
        try (InputStream stream = new java.io.FileInputStream(manifest)) {
            properties.load(stream);
        } catch (IOException failure) {
            return null;
        }

        String executable = properties.getProperty(KEY_EXECUTABLE);
        if (executable == null || !new File(directory, executable).isFile()) {
            return null;
        }

        return new Program(directory, properties.getProperty(KEY_NAME, directory.getName()), executable);
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

    private static List<String> findExecutables(File directory) {
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
