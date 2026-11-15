package dev.brovan.input;

import android.content.Context;
import android.view.View;

public abstract class ControlView extends View {

    protected final ControlPainter painter;

    protected ControlView(Context context, ControlPainter painter) {
        super(context);
        this.painter = painter;
    }

    public void setStyle(ControlItem item) {
        painter.setStyle(item);
        invalidate();
    }
}
