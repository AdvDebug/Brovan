package dev.brovan.app;

import java.io.File;

/** A program the user imported, together with the folder holding the files it needs. */
public final class Program {

    private final File directory;
    private final String name;
    private final String executableName;

    Program(File directory, String name, String executableName) {
        this.directory = directory;
        this.name = name;
        this.executableName = executableName;
    }

    public File directory() {
        return directory;
    }

    public File executable() {
        return new File(directory, executableName);
    }

    public String name() {
        return name;
    }

    public String executableName() {
        return executableName;
    }
}
