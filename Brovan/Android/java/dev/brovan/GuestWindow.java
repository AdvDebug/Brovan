package dev.brovan;

/** A top-level window owned by the emulated process. */
public final class GuestWindow {

    private final long hwnd;
    private final int width;
    private final int height;
    private final boolean visible;
    private final String title;

    GuestWindow(long hwnd, int width, int height, boolean visible, String title) {
        this.hwnd = hwnd;
        this.width = width;
        this.height = height;
        this.visible = visible;
        this.title = title;
    }

    public long hwnd() {
        return hwnd;
    }

    public int width() {
        return width;
    }

    public int height() {
        return height;
    }

    public boolean visible() {
        return visible;
    }

    public String title() {
        return title.isEmpty() ? "(untitled)" : title;
    }

    @Override
    public String toString() {
        return title() + "  " + width + "x" + height + (visible ? "" : "  (hidden)");
    }
}
