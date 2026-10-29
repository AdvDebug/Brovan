package dev.brovan.app;

import java.io.File;
import java.io.IOException;
import java.util.Properties;

public final class Program {

    private final String id;
    private final File directory;
    private final Properties values;
    private final String lastFailure;

    Program(String id, File directory, Properties values, String lastFailure) {
        this.id = id;
        this.directory = directory;
        this.values = new Properties();
        this.values.putAll(values);
        this.lastFailure = lastFailure;
    }

    public String id() { return id; }
    public File directory() { return directory; }
    public File executable() { return new File(directory, executableName()); }
    public String name() { return values.getProperty(Library.KEY_NAME, directory.getName()); }
    public String executableName() { return values.getProperty(Library.KEY_EXECUTABLE, ""); }
    public String arguments() { return values.getProperty(Library.KEY_ARGUMENTS, ""); }
    public String workingDirectory() { return values.getProperty(Library.KEY_WORKING_DIRECTORY, ""); }
    public String lastFailure() { return lastFailure; }

    String startDirectory() throws IOException {
        String value = workingDirectory();
        File directory = executable().getParentFile();
        if (value.isEmpty() || value.equals(".")) {
            return directory.getAbsolutePath();
        }
        return Library.isGuestPath(value) ? value : Library.child(directory, value).getAbsolutePath();
    }

    Properties values() {
        Properties copy = new Properties();
        copy.putAll(values);
        return copy;
    }
}
