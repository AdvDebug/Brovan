package dev.brovan;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.text.InputType;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.Choreographer;
import android.view.GestureDetector;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.inputmethod.BaseInputConnection;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputMethodManager;

import dev.brovan.input.KeyMap;
import dev.brovan.input.VirtualKey;

public class TerminalView extends View {

    public interface LatchListener {
        void onLatchChanged(int latched);
    }

    // Mirrors TerminalScreen's snapshot layout.
    private static final int HEADER_INTS = 8;
    private static final int CELL_INTS = 3;
    private static final int STATE_CURSOR_VISIBLE = 1;
    private static final int FLAG_BOLD = 0x01;
    private static final int FLAG_FAINT = 0x02;
    private static final int FLAG_ITALIC = 0x04;
    private static final int FLAG_UNDERLINE = 0x08;
    private static final int FLAG_INVERSE = 0x10;
    private static final int FLAG_HIDDEN = 0x20;
    private static final int FLAG_STRIKE = 0x40;
    private static final int FLAG_WIDE_TAIL = 0x80;
    private static final int DEFAULT_COLOR = -1;
    private static final int RGB_COLOR = 0x1000000;

    private static final float TEXT_SIZE_SP = 13f;
    private static final float ITALIC_SKEW = -0.25f;
    private static final int CURSOR_COLOR = 0xA0FFFFFF;
    private static final int DEFAULT_FOREGROUND = 0xFFCCCCCC;
    private static final int DEFAULT_BACKGROUND = 0xFF0C0C0C;

    private static final int VK_BACK = VirtualKey.BACKSPACE.code();
    private static final int VK_RETURN = VirtualKey.ENTER.code();
    private static final int VK_DELETE = VirtualKey.DELETE.code();
    private static final int MAX_IME_DELETES = 64;

    // Campbell colors, then the xterm palette.
    private static final int[] PALETTE = buildPalette();

    private final Paint text = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint fill = new Paint();
    private final GestureDetector gestures;
    private final char[] glyph = new char[2];

    private int[] cells = new int[HEADER_INTS];
    private boolean hasFrame;
    private boolean framePending;
    private float cellWidth;
    private float cellHeight;
    private float baseline;
    private int columns;
    private int rows;
    private int scrollBack;
    private float scrollCarry;
    private int latched;
    private boolean inputEnabled = true;
    private LatchListener latchListener;

    public TerminalView(Context context) {
        this(context, null);
    }

    public TerminalView(Context context, AttributeSet attrs) {
        super(context, attrs);

        text.setTypeface(Typeface.MONOSPACE);
        text.setTextSize(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, TEXT_SIZE_SP,
                getResources().getDisplayMetrics()));
        Paint.FontMetrics metrics = text.getFontMetrics();
        cellWidth = text.measureText("M");
        cellHeight = (float) Math.ceil(metrics.descent - metrics.ascent);
        baseline = -metrics.ascent;

        setFocusable(true);
        setFocusableInTouchMode(true);

        gestures = new GestureDetector(context, new GestureDetector.SimpleOnGestureListener() {
            @Override
            public boolean onDown(MotionEvent event) {
                return true;
            }

            @Override
            public boolean onSingleTapUp(MotionEvent event) {
                showKeyboard();
                return true;
            }

            @Override
            public boolean onScroll(MotionEvent first, MotionEvent current, float distanceX, float distanceY) {
                scrollHistory(distanceY);
                return true;
            }
        });
    }

    public void setLatchListener(LatchListener listener) {
        latchListener = listener;
    }

    public void setInputEnabled(boolean enabled) {
        inputEnabled = enabled;
        if (!enabled) {
            setLatched(0);
        }
    }

    public void toggleLatch(int bits) {
        setLatched(latched ^ bits);
    }

    public void showKeyboard() {
        requestFocus();
        InputMethodManager input = getContext().getSystemService(InputMethodManager.class);
        if (input != null) {
            input.showSoftInput(this, InputMethodManager.SHOW_IMPLICIT);
        }
    }

    public void hideKeyboard() {
        InputMethodManager input = getContext().getSystemService(InputMethodManager.class);
        if (input != null) {
            input.hideSoftInputFromWindow(getWindowToken(), 0);
        }
    }

    public void requestFrame() {
        post(this::scheduleFrame);
    }

    private void scheduleFrame() {
        if (framePending) {
            return;
        }

        framePending = true;
        Choreographer.getInstance().postFrameCallback(frameTimeNanos -> {
            framePending = false;
            refresh();
        });
    }

    private void refresh() {
        int written = BrovanNative.terminalSnapshot(cells, scrollBack);
        if (written < 0 && -written > cells.length) {
            int[] larger = new int[-written];
            written = BrovanNative.terminalSnapshot(larger, scrollBack);
            if (written > 0) {
                cells = larger;
            }
        }

        if (written == 0) {
            scheduleFrame();
            return;
        }

        if (written < 0) {
            return;
        }

        scrollBack = cells[6];
        hasFrame = true;
        invalidate();
    }

    private void scrollHistory(float distance) {
        if (!hasFrame) {
            return;
        }

        scrollCarry -= distance;
        int lines = (int) (scrollCarry / cellHeight);
        if (lines == 0) {
            return;
        }

        scrollCarry -= lines * cellHeight;
        int history = cells[5];
        int target = Math.max(0, Math.min(scrollBack + lines, history));
        if (target != scrollBack) {
            scrollBack = target;
            scheduleFrame();
        }
    }

    @Override
    protected void onSizeChanged(int width, int height, int oldWidth, int oldHeight) {
        super.onSizeChanged(width, height, oldWidth, oldHeight);

        int newColumns = Math.max(1, (int) (width / cellWidth));
        int newRows = Math.max(1, (int) (height / cellHeight));
        if (newColumns == columns && newRows == rows) {
            return;
        }

        columns = newColumns;
        rows = newRows;
        BrovanNative.terminalResize(columns, rows);
        scheduleFrame();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        canvas.drawColor(DEFAULT_BACKGROUND);
        if (!hasFrame) {
            return;
        }

        int shownColumns = cells[0];
        int shownRows = cells[1];
        int at = HEADER_INTS;

        for (int row = 0; row < shownRows; row++) {
            float top = row * cellHeight;
            for (int column = 0; column < shownColumns; column++, at += CELL_INTS) {
                int packed = cells[at];
                int rune = packed & 0xFFFFFF;
                int flags = packed >>> 24;
                if ((flags & FLAG_WIDE_TAIL) != 0) {
                    continue;
                }

                int foreground = resolve(cells[at + 1], DEFAULT_FOREGROUND, (flags & FLAG_BOLD) != 0);
                int background = resolve(cells[at + 2], DEFAULT_BACKGROUND, false);
                if ((flags & FLAG_INVERSE) != 0) {
                    int swap = foreground;
                    foreground = background;
                    background = swap;
                }

                boolean wide = column + 1 < shownColumns && ((cells[at + CELL_INTS] >>> 24) & FLAG_WIDE_TAIL) != 0;
                float left = column * cellWidth;
                float width = wide ? cellWidth * 2 : cellWidth;
                if (background != DEFAULT_BACKGROUND) {
                    fill.setColor(background);
                    canvas.drawRect(left, top, left + width, top + cellHeight, fill);
                }

                if (rune <= ' ' || (flags & FLAG_HIDDEN) != 0) {
                    continue;
                }

                text.setColor((flags & FLAG_FAINT) != 0 ? (foreground & 0x00FFFFFF) | 0x99000000 : foreground);
                text.setFakeBoldText((flags & FLAG_BOLD) != 0);
                text.setUnderlineText((flags & FLAG_UNDERLINE) != 0);
                text.setStrikeThruText((flags & FLAG_STRIKE) != 0);
                text.setTextSkewX((flags & FLAG_ITALIC) != 0 ? ITALIC_SKEW : 0f);
                int length = Character.toChars(rune, glyph, 0);
                canvas.drawText(glyph, 0, length, left, top + baseline, text);
            }
        }

        int back = cells[6];
        int cursorRow = cells[3] + back;
        if ((cells[4] & STATE_CURSOR_VISIBLE) != 0 && cursorRow < shownRows) {
            float left = cells[2] * cellWidth;
            float top = cursorRow * cellHeight;
            fill.setColor(CURSOR_COLOR);
            canvas.drawRect(left, top, left + cellWidth, top + cellHeight, fill);
        }
    }

    private static int resolve(int color, int fallback, boolean bold) {
        if (color == DEFAULT_COLOR) {
            return fallback;
        }

        if ((color & RGB_COLOR) != 0) {
            return 0xFF000000 | (color & 0xFFFFFF);
        }

        int index = color & 0xFF;
        return PALETTE[bold && index < 8 ? index + 8 : index];
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        return gestures.onTouchEvent(event) || super.onTouchEvent(event);
    }

    @Override
    public boolean onCheckIsTextEditor() {
        return true;
    }

    // TYPE_NULL keeps the IME from replaying hardware keys out of order.
    @Override
    public InputConnection onCreateInputConnection(EditorInfo info) {
        info.inputType = InputType.TYPE_NULL;
        info.imeOptions = EditorInfo.IME_FLAG_NO_FULLSCREEN | EditorInfo.IME_FLAG_NO_EXTRACT_UI
                | EditorInfo.IME_ACTION_NONE;

        return new BaseInputConnection(this, false) {
            // Clear composing text so the IME does not send it twice.
            @Override
            public boolean commitText(CharSequence value, int newCursorPosition) {
                type(value);
                getEditable().clear();
                return true;
            }

            @Override
            public boolean deleteSurroundingText(int beforeLength, int afterLength) {
                for (int i = 0; i < Math.min(beforeLength, MAX_IME_DELETES); i++) {
                    press(VK_BACK, '\b');
                }

                for (int i = 0; i < Math.min(afterLength, MAX_IME_DELETES); i++) {
                    press(VK_DELETE, '\0');
                }

                return true;
            }
        };
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        return sendKey(true, keyCode, event) || super.onKeyDown(keyCode, event);
    }

    @Override
    public boolean onKeyUp(int keyCode, KeyEvent event) {
        return sendKey(false, keyCode, event) || super.onKeyUp(keyCode, event);
    }

    @Override
    public boolean onKeyMultiple(int keyCode, int repeatCount, KeyEvent event) {
        if (keyCode == KeyEvent.KEYCODE_UNKNOWN && event.getCharacters() != null) {
            type(event.getCharacters());
            return true;
        }

        return super.onKeyMultiple(keyCode, repeatCount, event);
    }

    private boolean sendKey(boolean down, int keyCode, KeyEvent event) {
        int virtualKey = KeyMap.toVirtualKey(keyCode);
        int state = KeyMap.controlKeyState(event.getMetaState()) | latched;
        char character = characterOf(keyCode, event, state);

        // Windows reports AltGr as left Ctrl plus right Alt.
        char altGraph = altGraphOf(event);
        if (altGraph != 0) {
            character = altGraph;
            state |= KeyMap.LEFT_CTRL_PRESSED;
        }

        if (virtualKey == 0 && character == 0) {
            return false;
        }

        if (!inputEnabled) {
            return true;
        }

        BrovanNative.terminalKey(down, virtualKey, character, state);
        if (!down && !isModifier(keyCode)) {
            settle();
        }

        return true;
    }

    private static char characterOf(int keyCode, KeyEvent event, int state) {
        switch (keyCode) {
            case KeyEvent.KEYCODE_DEL: return '\b';
            case KeyEvent.KEYCODE_ENTER:
            case KeyEvent.KEYCODE_NUMPAD_ENTER: return '\r';
            case KeyEvent.KEYCODE_TAB: return '\t';
            case KeyEvent.KEYCODE_ESCAPE: return 0x1B;
            default: break;
        }

        int plain = event.getUnicodeChar(event.getMetaState() & ~(KeyEvent.META_CTRL_MASK | KeyEvent.META_ALT_MASK));
        if (plain == 0 || (plain & KeyCharacterMap.COMBINING_ACCENT) != 0 || plain > Character.MAX_VALUE) {
            return 0;
        }

        return withControl((char) plain, state);
    }

    private static char altGraphOf(KeyEvent event) {
        int meta = event.getMetaState();
        if ((meta & KeyEvent.META_ALT_RIGHT_ON) == 0 || (meta & KeyEvent.META_CTRL_MASK) != 0) {
            return 0;
        }

        int typed = event.getUnicodeChar(meta);
        if (typed <= ' ' || (typed & KeyCharacterMap.COMBINING_ACCENT) != 0 || typed > Character.MAX_VALUE) {
            return 0;
        }

        return (char) typed;
    }

    private static char withControl(char character, int state) {
        if ((state & (KeyMap.LEFT_CTRL_PRESSED | KeyMap.RIGHT_CTRL_PRESSED)) == 0) {
            return character;
        }

        char upper = Character.toUpperCase(character);
        return upper >= '@' && upper <= '_' ? (char) (upper & 0x1F) : character;
    }

    private static boolean isModifier(int keyCode) {
        return KeyEvent.isModifierKey(keyCode);
    }

    private void type(CharSequence value) {
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);
            if (character == '\n') {
                press(VK_RETURN, '\r');
                continue;
            }

            int virtualKey = 0;
            char upper = Character.toUpperCase(character);
            if ((latched & (KeyMap.LEFT_CTRL_PRESSED | KeyMap.RIGHT_CTRL_PRESSED)) != 0 && upper >= 'A' && upper <= 'Z') {
                virtualKey = upper;
            }

            press(virtualKey, withControl(character, latched));
        }
    }

    public void press(int virtualKey, char character) {
        if (!inputEnabled) {
            return;
        }

        BrovanNative.terminalKey(true, virtualKey, character, latched);
        BrovanNative.terminalKey(false, virtualKey, character, latched);
        settle();
    }

    private void settle() {
        if (scrollBack != 0) {
            scrollBack = 0;
            scheduleFrame();
        }

        setLatched(0);
    }

    private void setLatched(int value) {
        if (value == latched) {
            return;
        }

        latched = value;
        if (latchListener != null) {
            latchListener.onLatchChanged(latched);
        }
    }

    private static int[] buildPalette() {
        int[] palette = {
                0xFF0C0C0C, 0xFFC50F1F, 0xFF13A10E, 0xFFC19C00, 0xFF0037DA, 0xFF881798, 0xFF3A96DD, 0xFFCCCCCC,
                0xFF767676, 0xFFE74856, 0xFF16C60C, 0xFFF9F1A5, 0xFF3B78FF, 0xFFB4009E, 0xFF61D6D6, 0xFFF2F2F2,
        };

        int[] colors = new int[256];
        System.arraycopy(palette, 0, colors, 0, palette.length);

        int[] steps = {0, 95, 135, 175, 215, 255};
        for (int index = 16; index < 232; index++) {
            int cube = index - 16;
            colors[index] = 0xFF000000 | (steps[cube / 36] << 16) | (steps[(cube / 6) % 6] << 8) | steps[cube % 6];
        }

        for (int index = 232; index < 256; index++) {
            int grey = 8 + (index - 232) * 10;
            colors[index] = 0xFF000000 | (grey << 16) | (grey << 8) | grey;
        }

        return colors;
    }
}
