package dev.brovan.input;

/**
 * Win32 virtual-key codes paired with their set-1 scan codes. Games read either one, so both have to be
 * right when the key comes from a touch control rather than a real keyboard.
 */
public enum VirtualKey {

    UP(0x26, 0x48),
    DOWN(0x28, 0x50),
    LEFT(0x25, 0x4B),
    RIGHT(0x27, 0x4D),

    W(0x57, 0x11),
    A(0x41, 0x1E),
    S(0x53, 0x1F),
    D(0x44, 0x20),
    Q(0x51, 0x10),
    E(0x45, 0x12),
    F(0x46, 0x21),
    R(0x52, 0x13),

    SPACE(0x20, 0x39),
    ENTER(0x0D, 0x1C),
    ESCAPE(0x1B, 0x01),
    SHIFT(0xA0, 0x2A),
    CONTROL(0xA2, 0x1D),
    ALT(0x12, 0x38),
    TAB(0x09, 0x0F);

    private final int code;
    private final int scanCode;

    VirtualKey(int code, int scanCode) {
        this.code = code;
        this.scanCode = scanCode;
    }

    public int code() {
        return code;
    }

    public int scanCode() {
        return scanCode;
    }
}
