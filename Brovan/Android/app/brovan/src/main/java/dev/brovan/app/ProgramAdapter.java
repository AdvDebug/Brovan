package dev.brovan.app;

import android.content.res.ColorStateList;
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
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

final class ProgramAdapter extends RecyclerView.Adapter<ProgramAdapter.Holder> {

    interface Listener {
        void onLaunch(Program program);

        void onActions(Program program);
    }

    enum Style {
        GRID(0, R.string.library_style_grid, R.drawable.ic_style_grid, R.layout.item_app_tile, 176, 0, 16f, 0f),
        COMPACT(1, R.string.library_style_compact, R.drawable.ic_style_compact, R.layout.item_app, 112, 48, 14f, 0f),
        LIST(2, R.string.library_style_list, R.drawable.ic_style_list, R.layout.item_app_row, 0, 56, 16f, 0f),
        CAROUSEL(4, R.string.library_style_carousel, R.drawable.ic_style_carousel, R.layout.item_app_hero, 0, 0, 26f, 1f),
        SHELF(5, R.string.library_style_shelf, R.drawable.ic_style_shelf, R.layout.item_app_tile, 0, 0, 16f, 0.52f);

        // Saved values stay stable across releases; a value with no style opens as List.
        private final int saved;

        private final int labelId;
        private final int previewId;
        private final int layoutId;
        private final int columnDp;
        private final int artDp;
        private final float nameSize;
        private final float pageFraction;

        Style(int saved, int labelId, int previewId, int layoutId, int columnDp, int artDp, float nameSize,
              float pageFraction) {
            this.saved = saved;
            this.labelId = labelId;
            this.previewId = previewId;
            this.layoutId = layoutId;
            this.columnDp = columnDp;
            this.artDp = artDp;
            this.nameSize = nameSize;
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

        int artDp() {
            return artDp;
        }

        boolean rows() {
            return layoutId == R.layout.item_app_row;
        }

        int pageWidth(int viewport) {
            return Math.round(viewport * pageFraction);
        }

        int columns(int widthDp) {
            return columnDp == 0 ? 1 : Math.max(2, widthDp / columnDp);
        }

        int saved() {
            return saved;
        }

        static Style of(int saved) {
            for (Style style : values()) {
                if (style.saved == saved) {
                    return style;
                }
            }
            return LIST;
        }
    }


    private static final LruCache<String, Bitmap> icons = new LruCache<>(64);
    private static final Set<String> withoutIcon = new HashSet<>();
    private static final Set<String> fullBleed = ConcurrentHashMap.newKeySet();
    private static final String FULL_BLEED_SUFFIX = ".full.png";
    private static final String INSET_SUFFIX = ".inset.png";
    private static final String NO_ICON_SUFFIX = ".none";
    private static final ExecutorService LOADER = iconLoader();
    // SIID_APPLICATION, the icon the shell gives an executable that has none.
    private static final int STOCK_APPLICATION_ICON = 15;
    private static final float ICON_INSET = 0.14f;
    private static final float STOCK_ICON_INSET = 0.22f;
    private static final int STOCK_ICON_ALPHA = 230;
    private static volatile Bitmap stockIcon;
    private static boolean stockIconRead;

    private final List<Program> all = new ArrayList<>();
    private final List<Program> visible = new ArrayList<>();
    private final Set<String> loading = new HashSet<>();
    private final Handler main = new Handler(Looper.getMainLooper());

    private final File iconCache;
    private final File stockIcons;
    private final Palette palette;
    private final Listener listener;

    private Style style = Style.GRID;
    private String query = "";

    ProgramAdapter(File iconCache, File stockIcons, Palette palette, Listener listener) {
        this.iconCache = iconCache;
        this.stockIcons = stockIcons;
        this.palette = palette;
        this.listener = listener;
    }

    private static ExecutorService iconLoader() {
        ThreadPoolExecutor loader = new ThreadPoolExecutor(2, 2, 10, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
        loader.allowCoreThreadTimeOut(true);
        return loader;
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
        boolean failed = !program.lastFailure().isEmpty();
        holder.detail.setVisibility(failed ? View.VISIBLE : View.GONE);
        if (failed) {
            holder.detail.setText(R.string.program_last_run_failed);
            holder.detail.setTextColor(palette.get(Palette.Role.WARNING));
        }
        if (holder.actions != null) {
            holder.actions.setOnClickListener(view -> listener.onActions(program));
        }
        holder.itemView.setScaleX(1f);
        holder.itemView.setScaleY(1f);
        holder.itemView.setAlpha(1f);

        if (style.artDp > 0) {
            int size = Math.round(style.artDp * holder.art.getResources().getDisplayMetrics().density);
            ViewGroup.LayoutParams params = holder.art.getLayoutParams();

            if (params.width != size) {
                params.width = size;
                params.height = size;
                holder.art.setLayoutParams(params);
            }
        }

        String key = iconKey(program);
        if (holder.art != null) {
            frameIcon(holder);
        }
        holder.itemView.setOnClickListener(view -> listener.onLaunch(program));
        holder.itemView.setOnLongClickListener(view -> {
            listener.onActions(program);
            return true;
        });

        if (holder.play != null) {
            holder.play.setOnClickListener(view -> listener.onLaunch(program));
        }

        bindIcon(holder, program, key);
    }

    @Override
    public int getItemCount() {
        return visible.size();
    }

    private void frameIcon(Holder holder) {
        int size = holder.art.getLayoutParams().width;
        if (size <= 0) {
            return;
        }

        GradientDrawable tile = new GradientDrawable();
        tile.setColor(palette.get(Palette.Role.OUTLINE));
        tile.setCornerRadius(size * 0.23f);
        holder.art.setBackground(tile);
        holder.art.setClipToOutline(true);
    }

    private static void placeIcon(Holder holder, float inset, boolean fill) {
        holder.icon.setScaleType(fill ? ImageView.ScaleType.CENTER_CROP : ImageView.ScaleType.FIT_CENTER);

        if (holder.art == null) {
            return;
        }

        int padding = Math.round(holder.art.getLayoutParams().width * inset);
        holder.icon.setPadding(padding, padding, padding, padding);
    }

    private static boolean fillsTile(Bitmap icon) {
        if (!icon.hasAlpha()) {
            return true;
        }

        int width = icon.getWidth();
        int height = icon.getHeight();
        int[] pixels = new int[width * height];
        icon.getPixels(pixels, 0, width, 0, 0, width, height);

        int solid = 0;
        for (int pixel : pixels) {
            if ((pixel >>> 24) >= 128) {
                solid++;
            }
        }
        return solid >= pixels.length * 0.85;
    }

    private static String iconKey(Program program) {
        return program.id() + "-" + UUID.nameUUIDFromBytes(
                program.executableName().getBytes(StandardCharsets.UTF_8));
    }

    private void bindIcon(Holder holder, Program program, String key) {
        holder.key = key;

        Bitmap ready = icons.get(key);
        if (ready == null && !loading.contains(key) && !withoutIcon.contains(key)) {
            ready = icon(program, key, false);
            if (ready != null) {
                icons.put(key, ready);
            }
        }

        if (ready != null) {
            boolean fill = fullBleed.contains(key);
            placeIcon(holder, ready == stockIcon ? STOCK_ICON_INSET : fill ? 0f : ICON_INSET, fill);
            holder.icon.setImageAlpha(ready == stockIcon ? STOCK_ICON_ALPHA : 255);
            holder.icon.setImageTintList(null);
            holder.icon.setImageBitmap(ready);
            return;
        }

        placeIcon(holder, STOCK_ICON_INSET, false);
        holder.icon.setImageAlpha(255);
        holder.icon.setImageResource(R.drawable.ic_window);
        holder.icon.setImageTintList(ColorStateList.valueOf(palette.get(Palette.Role.TEXT_SECONDARY)));

        if (withoutIcon.contains(key) || !loading.add(key)) {
            return;
        }

        LOADER.execute(() -> {
            Bitmap loaded = icon(program, key, true);
            main.post(() -> finish(key, loaded));
        });
    }

    private void finish(String key, Bitmap loaded) {
        loading.remove(key);

        if (loaded == null) {
            withoutIcon.add(key);
        } else {
            icons.put(key, loaded);
        }

        for (int position = 0; position < visible.size(); position++) {
            if (key.equals(iconKey(visible.get(position)))) {
                notifyItemChanged(position);
                return;
            }
        }
    }

    private static int monogramColor(String name) {
        return Color.HSVToColor(new float[]{(name.hashCode() & 0x7FFFFFFF) % 360f, 0.4f, 0.52f});
    }

    // Without mayExtract the executable is not parsed, so an icon missing from the cache comes back null.
    private Bitmap icon(Program program, String key, boolean mayExtract) {
        File exe = program.executable();
        String base = key + "-" + exe.lastModified();
        File full = new File(iconCache, base + FULL_BLEED_SUFFIX);
        File inset = new File(iconCache, base + INSET_SUFFIX);
        File none = new File(iconCache, base + NO_ICON_SUFFIX);

        Bitmap stored = decode(full);
        if (stored != null) {
            fullBleed.add(key);
            return stored;
        }
        stored = decode(inset);
        if (stored != null) {
            return stored;
        }
        if (none.isFile()) {
            return stockIcon(stockIcons, iconCache, mayExtract);
        }
        if (!mayExtract) {
            return null;
        }

        Bitmap extracted = ExeIcon.extract(exe);
        if (extracted == null) {
            store(none, null);
            return stockIcon(stockIcons, iconCache, true);
        }

        Bitmap art = trimmed(extracted);
        boolean fill = fillsTile(art);
        if (fill) {
            fullBleed.add(key);
        }
        store(fill ? full : inset, art);
        return art;
    }

    private static Bitmap decode(File file) {
        return file.isFile() ? BitmapFactory.decodeFile(file.getPath()) : null;
    }

    private static Bitmap trimmed(Bitmap icon) {
        int width = icon.getWidth();
        int height = icon.getHeight();
        int[] pixels = new int[width * height];
        icon.getPixels(pixels, 0, width, 0, 0, width, height);

        int left = width, top = height, right = -1, bottom = -1;
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                if ((pixels[y * width + x] >>> 24) > 24) {
                    left = Math.min(left, x);
                    right = Math.max(right, x);
                    top = Math.min(top, y);
                    bottom = Math.max(bottom, y);
                }
            }
        }

        if (right < 0 || (left == 0 && top == 0 && right == width - 1 && bottom == height - 1)) {
            return icon;
        }

        int artWidth = right - left + 1;
        int artHeight = bottom - top + 1;
        int side = Math.max(artWidth, artHeight);
        Bitmap square = Bitmap.createBitmap(side, side, Bitmap.Config.ARGB_8888);
        new Canvas(square).drawBitmap(icon, new Rect(left, top, right + 1, bottom + 1),
                new Rect((side - artWidth) / 2, (side - artHeight) / 2,
                        (side - artWidth) / 2 + artWidth, (side - artHeight) / 2 + artHeight), null);
        return square;
    }

    private static synchronized Bitmap stockIcon(File source, File iconCache, boolean mayExtract) {
        if (stockIconRead) {
            return stockIcon;
        }

        File stored = new File(iconCache, "stock-" + source.lastModified() + INSET_SUFFIX);
        Bitmap icon = decode(stored);
        if (icon == null) {
            if (!mayExtract) {
                return null;
            }
            icon = ExeIcon.extract(source, STOCK_APPLICATION_ICON);
            if (icon != null) {
                store(stored, icon);
            }
        }

        stockIcon = icon;
        stockIconRead = true;
        return icon;
    }

    // A null bitmap leaves an empty marker file.
    private static void store(File destination, Bitmap bitmap) {
        File folder = destination.getParentFile();
        if (folder == null || (!folder.isDirectory() && !folder.mkdirs())) {
            return;
        }

        try (OutputStream stream = new FileOutputStream(destination)) {
            if (bitmap != null) {
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, stream);
            }
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
        final View actions;

        String key;

        Holder(View view) {
            super(view);
            art = view.findViewById(R.id.art);
            icon = view.findViewById(R.id.icon);
            name = view.findViewById(R.id.name);
            detail = view.findViewById(R.id.detail);
            play = view.findViewById(R.id.play);
            actions = view.findViewById(R.id.actions);
        }
    }

    static final class Monogram extends Drawable {

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
