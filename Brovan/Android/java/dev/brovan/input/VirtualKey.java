package dev.brovan.input;

/**
 * Win32 virtual-key codes paired with their set-1 scan codes. Games read either one, so both have to be
 * right when the key comes from a touch control rather than a real keyboard.
 *
 * The arrow and navigation keys carry the second byte of their extended sequence, without the 0xE0 prefix,
 * which is what the guest side already expects. Numpad keys are left out because they share those bytes.
 */
public enum VirtualKey {

    A(0x41, 0x1E, "A"),
    B(0x42, 0x30, "B"),
    C(0x43, 0x2E, "C"),
    D(0x44, 0x20, "D"),
    E(0x45, 0x12, "E"),
    F(0x46, 0x21, "F"),
    G(0x47, 0x22, "G"),
    H(0x48, 0x23, "H"),
    I(0x49, 0x17, "I"),
    J(0x4A, 0x24, "J"),
    K(0x4B, 0x25, "K"),
    L(0x4C, 0x26, "L"),
    M(0x4D, 0x32, "M"),
    N(0x4E, 0x31, "N"),
    O(0x4F, 0x18, "O"),
    P(0x50, 0x19, "P"),
    Q(0x51, 0x10, "Q"),
    R(0x52, 0x13, "R"),
    S(0x53, 0x1F, "S"),
    T(0x54, 0x14, "T"),
    U(0x55, 0x16, "U"),
    V(0x56, 0x2F, "V"),
    W(0x57, 0x11, "W"),
    X(0x58, 0x2D, "X"),
    Y(0x59, 0x15, "Y"),
    Z(0x5A, 0x2C, "Z"),

    DIGIT_1(0x31, 0x02, "1"),
    DIGIT_2(0x32, 0x03, "2"),
    DIGIT_3(0x33, 0x04, "3"),
    DIGIT_4(0x34, 0x05, "4"),
    DIGIT_5(0x35, 0x06, "5"),
    DIGIT_6(0x36, 0x07, "6"),
    DIGIT_7(0x37, 0x08, "7"),
    DIGIT_8(0x38, 0x09, "8"),
    DIGIT_9(0x39, 0x0A, "9"),
    DIGIT_0(0x30, 0x0B, "0"),

    F1(0x70, 0x3B, "F1"),
    F2(0x71, 0x3C, "F2"),
    F3(0x72, 0x3D, "F3"),
    F4(0x73, 0x3E, "F4"),
    F5(0x74, 0x3F, "F5"),
    F6(0x75, 0x40, "F6"),
    F7(0x76, 0x41, "F7"),
    F8(0x77, 0x42, "F8"),
    F9(0x78, 0x43, "F9"),
    F10(0x79, 0x44, "F10"),
    F11(0x7A, 0x57, "F11"),
    F12(0x7B, 0x58, "F12"),

    UP(0x26, 0x48, "Up"),
    DOWN(0x28, 0x50, "Down"),
    LEFT(0x25, 0x4B, "Left"),
    RIGHT(0x27, 0x4D, "Right"),

    SPACE(0x20, 0x39, "Space"),
    ENTER(0x0D, 0x1C, "Enter"),
    ESCAPE(0x1B, 0x01, "Esc"),
    TAB(0x09, 0x0F, "Tab"),
    BACKSPACE(0x08, 0x0E, "Backspace"),
    SHIFT(0xA0, 0x2A, "Shift"),
    CONTROL(0xA2, 0x1D, "Ctrl"),
    ALT(0x12, 0x38, "Alt"),
    CAPS_LOCK(0x14, 0x3A, "Caps"),

    INSERT(0x2D, 0x52, "Insert"),
    DELETE(0x2E, 0x53, "Delete"),
    HOME(0x24, 0x47, "Home"),
    END(0x23, 0x4F, "End"),
    PAGE_UP(0x21, 0x49, "Page up"),
    PAGE_DOWN(0x22, 0x51, "Page down"),

    MINUS(0xBD, 0x0C, "-"),
    EQUALS(0xBB, 0x0D, "="),
    LEFT_BRACKET(0xDB, 0x1A, "["),
    RIGHT_BRACKET(0xDD, 0x1B, "]"),
    SEMICOLON(0xBA, 0x27, ";"),
    APOSTROPHE(0xDE, 0x28, "'"),
    GRAVE(0xC0, 0x29, "`"),
    BACKSLASH(0xDC, 0x2B, "\\"),
    COMMA(0xBC, 0x33, ","),
    PERIOD(0xBE, 0x34, "."),
    SLASH(0xBF, 0x35, "/");

    private final int code;
    private final int scanCode;
    private final String label;

    VirtualKey(int code, int scanCode, String label) {
        this.code = code;
        this.scanCode = scanCode;
        this.label = label;
    }

    public int code() {
        return code;
    }

    public int scanCode() {
        return scanCode;
    }

    public String label() {
        return label;
    }

    public static VirtualKey byName(String name, VirtualKey fallback) {
        if (name == null) {
            return fallback;
        }

        try {
            return valueOf(name);
        } catch (IllegalArgumentException unknown) {
            return fallback;
        }
    }
}
