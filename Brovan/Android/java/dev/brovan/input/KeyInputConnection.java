package dev.brovan.input;

import android.text.InputType;
import android.view.View;
import android.view.inputmethod.BaseInputConnection;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;

public final class KeyInputConnection extends BaseInputConnection {

    public interface Target {
        void type(CharSequence text);

        void delete(boolean forward);

        /** Returns false to let the IME action arrive as an Enter key event. */
        default boolean editorAction() {
            return false;
        }
    }

    private static final int MAX_DELETES = 64;

    private final Target target;

    private KeyInputConnection(View view, Target target) {
        super(view, false);
        this.target = target;
    }

    // TYPE_NULL makes the IME send plain key events, in order, instead of editing text.
    public static InputConnection create(View view, EditorInfo info, Target target) {
        info.inputType = InputType.TYPE_NULL;
        info.imeOptions = EditorInfo.IME_FLAG_NO_FULLSCREEN | EditorInfo.IME_FLAG_NO_EXTRACT_UI
                | EditorInfo.IME_ACTION_NONE;
        return new KeyInputConnection(view, target);
    }

    // Clear composing text so the IME does not send it twice.
    @Override
    public boolean commitText(CharSequence text, int newCursorPosition) {
        target.type(text);
        getEditable().clear();
        return true;
    }

    @Override
    public boolean deleteSurroundingText(int beforeLength, int afterLength) {
        for (int i = 0; i < Math.min(beforeLength, MAX_DELETES); i++) {
            target.delete(false);
        }

        for (int i = 0; i < Math.min(afterLength, MAX_DELETES); i++) {
            target.delete(true);
        }

        return true;
    }

    @Override
    public boolean performEditorAction(int actionCode) {
        return target.editorAction() || super.performEditorAction(actionCode);
    }
}
