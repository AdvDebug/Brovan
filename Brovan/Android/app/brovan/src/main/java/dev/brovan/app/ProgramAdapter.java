package dev.brovan.app;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.PixelFormat;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Handler;
import android.os.Looper;
import android.util.LruCache;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executor;

final class ProgramAdapter extends RecyclerView.Adapter<ProgramAdapter.Holder> {

    interface Listener {
        void onLaunch(Program program);

        void onLongPress(Program program);
    }

    enum Style {
        GRID(R.string.library_style_grid, R.drawable.ic_style_grid, R.layout.item_app, 176, 64, 15f, true, 0f),
        COMPACT(R.string.library_style_compact, R.drawable.ic_style_compact, R.layout.item_app, 112, 48, 13f, false, 0f),
        LIST(R.string.library_style_list, R.drawable.ic_style_list, R.layout.item_app_row, 0, 52, 15f, true, 0f),
        LARGE(R.string.library_style_large, R.drawable.ic_style_large, R.layout.item_app_row, 0, 84, 18f, true, 0f),
        CAROUSEL(R.string.library_style_carousel, R.drawable.ic_style_carousel, R.layout.item_app_hero, 0, 0, 26f, true, 1f),
        SHELF(R.string.library_style_shelf, R.drawable.ic_style_shelf, R.layout.item_app_tile, 0, 0, 16f, false, 0.52f);

        private final int labelId;
        private final int previewId;
        private final int layoutId;
        private final int columnDp;
        private final int artDp;
        private final float nameSize;
        private final boolean detail;
        private final float pageFraction;

        Style(int labelId, int previewId, int layoutId, int columnDp, int artDp, float nameSize,
              boolean detail, float pageFraction) {
            this.labelId = labelId;
            this.previewId = previewId;
            this.layoutId = layoutId;
            this.columnDp = columnDp;
            this.artDp = artDp;
            this.nameSize = nameSize;
            this.detail = detail;
            this.pageFraction = pageFraction;
        }

        int labelId() {
            return labelId;
        }

        int previewId() {
            return previewId;
        }

        boolean horizontal() {
            return pageFraction > 0f;
        }

        int pageWidth(int viewport) {
            return Math.round(viewport * pageFraction);
        }

        int columns(int widthDp) {
            return columnDp == 0 ? 1 : Math.max(2, widthDp / columnDp);
        }

        static Style of(int ordinal) {
            Style[] all = values();
            return ordinal >= 0 && ordinal < all.length ? all[ordinal] : GRID;
        }
    }

    private static final int SAMPLE = 16;
    private static final float RADIUS = 18f;

    private final List<Program> all = new ArrayList<>();
    private final List<Program> visible = new ArrayList<>();
    private final LruCache<String, Bitmap> icons = new LruCache<>(64);
    private final Set<String> withoutIcon = new HashSet<>();
    private final Set<String> loading = new HashSet<>();
    private final Map<String, Integer> tints = new HashMap<>();
    private final Handler main = new Handler(Looper.getMainLooper());

    private final File iconCache;
    private final Executor worker;
    private final Listener listener;

    private Style style = Style.GRID;
    private String query = "";

    ProgramAdapter(File iconCache, Executor worker, Listener listener) {
        this.iconCache = iconCache;
        this.worker = worker;
        this.listener = listener;
    }

    void submit(List<Program> updated) {
        all.clear();
        all.addAll(updated);
        applyQuery();
    }

    void setStyle(Style value) {
        style = value;
        notifyDataSetChanged();
    }

    Style style() {
        return style;
    }

    void search(String value) {
        query = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        applyQuery();
    }

    boolean isLibraryEmpty() {
        return all.isEmpty();
    }

    private void applyQuery() {
        visible.clear();

        for (Program program : all) {
            if (matches(program)) {
                visible.add(program);
            }
        }

        notifyDataSetChanged();
    }

    private boolean matches(Program program) {
        if (query.isEmpty()) {
            return true;
        }

        return program.name().toLowerCase(Locale.ROOT).contains(query)
                || program.executableName().toLowerCase(Locale.ROOT).contains(query);
    }

    @Override
    public int getItemViewType(int position) {
        return style.layoutId;
    }

    @NonNull
    @Override
    public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(viewType, parent, false);

        if (style.horizontal() && parent.getWidth() > 0) {
            view.getLayoutParams().width = style.pageWidth(parent.getWidth());
        }

        return new Holder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull Holder holder, int position) {
        Program program = visible.get(position);

        holder.name.setText(program.name());
        holder.name.setTextSize(style.nameSize);
        holder.detail.setText(program.executableName());
        holder.detail.setVisibility(style.detail ? View.VISIBLE : View.GONE);

        if (style.artDp > 0) {
            int size = Math.round(style.artDp * holder.art.getResources().getDisplayMetrics().density);
            ViewGroup.LayoutParams params = holder.art.getLayoutParams();

            if (params.width != size) {
                params.width = size;
                params.height = size;
                holder.art.setLayoutParams(params);
            }
        }

        Integer tint = tints.get(program.directory().getName());
        holder.art.setBackground(backdrop(tint != null ? tint : monogramColor(program.name())));

        holder.itemView.setOnClickListener(view -> listener.onLaunch(program));
        holder.itemView.setOnLongClickListener(view -> {
            listener.onLongPress(program);
            return true;
        });

        if (holder.play != null) {
            holder.play.setOnClickListener(view -> listener.onLaunch(program));
        }

        bindIcon(holder, program);
    }

    @Override
    public int getItemCount() {
        return visible.size();
    }

    private void bindIcon(Holder holder, Program program) {
        String key = program.directory().getName();
        holder.key = key;

        Bitmap ready = icons.get(key);
        if (ready != null) {
            holder.icon.setImageBitmap(ready);
            return;
        }

        holder.icon.setImageDrawable(new Monogram(program.name()));

        if (withoutIcon.contains(key) || !loading.add(key)) {
            return;
        }

        worker.execute(() -> {
            Bitmap loaded = read(program, key);
            int tint = loaded != null ? dominant(loaded) : monogramColor(program.name());
            main.post(() -> finish(key, loaded, tint));
        });
    }

    private void finish(String key, Bitmap loaded, int tint) {
        loading.remove(key);
        tints.put(key, tint);

        if (loaded == null) {
            withoutIcon.add(key);
        } else {
            icons.put(key, loaded);
        }

        for (int position = 0; position < visible.size(); position++) {
            if (key.equals(visible.get(position).directory().getName())) {
                notifyItemChanged(position);
                return;
            }
        }
    }

    private static Drawable backdrop(int tint) {
        float[] hsv = new float[3];
        Color.colorToHSV(tint, hsv);

        int top = Color.HSVToColor(new float[]{hsv[0], Math.min(hsv[1], 0.55f), 0.42f});
        int bottom = Color.HSVToColor(new float[]{hsv[0], Math.min(hsv[1], 0.4f), 0.17f});

        GradientDrawable panel = new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM,
                new int[]{top, bottom});
        panel.setShape(GradientDrawable.RECTANGLE);
        panel.setCornerRadius(RADIUS);
        panel.setStroke(1, Color.argb(40, 255, 255, 255));
        return panel;
    }

    private static int dominant(Bitmap icon) {
        Bitmap small = Bitmap.createScaledBitmap(icon, SAMPLE, SAMPLE, true);
        int[] pixels = new int[SAMPLE * SAMPLE];
        small.getPixels(pixels, 0, SAMPLE, 0, 0, SAMPLE, SAMPLE);
        small.recycle();

        float[] hsv = new float[3];
        float best = -1f;
        float hue = 0f;
        float saturation = 0f;

        for (int pixel : pixels) {
            if ((pixel >>> 24) < 128) {
                continue;
            }

            Color.colorToHSV(pixel, hsv);
            float score = hsv[1] * hsv[2];

            if (score > best) {
                best = score;
                hue = hsv[0];
                saturation = hsv[1];
            }
        }

        if (best <= 0f) {
            return 0xFF5A6472;
        }

        return Color.HSVToColor(new float[]{hue, Math.max(0.25f, Math.min(saturation, 0.6f)), 0.5f});
    }

    private static int monogramColor(String name) {
        return Color.HSVToColor(new float[]{(name.hashCode() & 0x7FFFFFFF) % 360f, 0.4f, 0.52f});
    }

    private Bitmap read(Program program, String key) {
        File exe = program.executable();
        File cached = new File(iconCache, String.format(Locale.ROOT, "%s-%d.png", key, exe.lastModified()));

        Bitmap stored = BitmapFactory.decodeFile(cached.getPath());
        if (stored != null) {
            return stored;
        }

        Bitmap extracted = ExeIcon.extract(exe);
        if (extracted != null) {
            store(cached, extracted);
        }

        return extracted;
    }

    private void store(File destination, Bitmap bitmap) {
        if (!iconCache.isDirectory() && !iconCache.mkdirs()) {
            return;
        }

        try (OutputStream stream = new FileOutputStream(destination)) {
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, stream);
        } catch (IOException unwritable) {
            destination.delete();
        }
    }

    static final class Holder extends RecyclerView.ViewHolder {
        final View art;
        final ImageView icon;
        final TextView name;
        final TextView detail;
        final View play;

        String key;

        Holder(View view) {
            super(view);
            art = view.findViewById(R.id.art);
            icon = view.findViewById(R.id.icon);
            name = view.findViewById(R.id.name);
            detail = view.findViewById(R.id.detail);
            play = view.findViewById(R.id.play);
        }
    }

    private static final class Monogram extends Drawable {

        private final Paint tile = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint glyph = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final String letter;

        Monogram(String name) {
            letter = initial(name);
            tile.setColor(monogramColor(name));
            glyph.setColor(0xFFF2F5FA);
            glyph.setTextAlign(Paint.Align.CENTER);
        }

        private static String initial(String name) {
            for (int i = 0; i < name.length(); i++) {
                if (Character.isLetterOrDigit(name.charAt(i))) {
                    return name.substring(i, i + 1).toUpperCase(Locale.ROOT);
                }
            }

            return "?";
        }

        @Override
        public void draw(@NonNull Canvas canvas) {
            Rect bounds = getBounds();
            float radius = bounds.width() * 0.26f;
            canvas.drawRoundRect(bounds.left, bounds.top, bounds.right, bounds.bottom, radius, radius, tile);

            glyph.setTextSize(bounds.height() * 0.52f);
            float baseline = bounds.exactCenterY() - (glyph.descent() + glyph.ascent()) / 2f;
            canvas.drawText(letter, bounds.exactCenterX(), baseline, glyph);
        }

        @Override
        public void setAlpha(int alpha) {
            tile.setAlpha(alpha);
            glyph.setAlpha(alpha);
        }

        @Override
        public void setColorFilter(ColorFilter filter) {
            tile.setColorFilter(filter);
            glyph.setColorFilter(filter);
        }

        @Override
        public int getOpacity() {
            return PixelFormat.TRANSLUCENT;
        }
    }
}
