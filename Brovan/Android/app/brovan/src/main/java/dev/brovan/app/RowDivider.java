package dev.brovan.app;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.util.function.IntSupplier;

final class RowDivider extends RecyclerView.ItemDecoration {

    private final Palette palette;
    private final IntSupplier startDp;
    private final Paint line = new Paint();

    RowDivider(Palette palette, IntSupplier startDp) {
        this.palette = palette;
        this.startDp = startDp;
    }

    static void showHeaderEdge(RecyclerView list, View edge) {
        list.addOnScrollListener(new RecyclerView.OnScrollListener() {
            @Override
            public void onScrolled(@NonNull RecyclerView view, int dx, int dy) {
                edge.setVisibility(view.canScrollVertically(-1) ? View.VISIBLE : View.INVISIBLE);
            }
        });
    }

    @Override
    public void onDraw(@NonNull Canvas canvas, @NonNull RecyclerView parent, @NonNull RecyclerView.State state) {
        int start = startDp.getAsInt();
        if (start < 0 || parent.getChildCount() < 2) {
            return;
        }

        float density = parent.getResources().getDisplayMetrics().density;
        float left = parent.getPaddingLeft() + start * density;
        float right = parent.getWidth() - parent.getPaddingRight() - 16 * density;
        float thickness = Math.max(1f, density);
        line.setColor(palette.get(Palette.Role.SURFACE_VARIANT));

        for (int i = 0; i < parent.getChildCount() - 1; i++) {
            View child = parent.getChildAt(i);
            float y = child.getBottom() + child.getTranslationY();
            canvas.drawRect(left, y - thickness / 2f, right, y + thickness / 2f, line);
        }
    }
}
