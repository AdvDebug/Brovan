package dev.brovan.app;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.InsetDrawable;
import android.graphics.drawable.LayerDrawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.AutoCompleteTextView;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatDelegate;
import androidx.appcompat.widget.SwitchCompat;
import androidx.appcompat.widget.Toolbar;
import androidx.core.view.LayoutInflaterCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsControllerCompat;

import com.google.android.material.appbar.AppBarLayout;
import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.materialswitch.MaterialSwitch;
import com.google.android.material.navigation.NavigationView;
import com.google.android.material.progressindicator.BaseProgressIndicator;
import com.google.android.material.shape.MaterialShapeDrawable;
import com.google.android.material.slider.Slider;
import com.google.android.material.textfield.TextInputLayout;

import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;

final class Theming {

    private static final int[][] SPECS = {
            {-android.R.attr.state_enabled},
            {android.R.attr.state_enabled, android.R.attr.state_checked},
            {android.R.attr.state_enabled, android.R.attr.state_pressed},
            {android.R.attr.state_enabled, android.R.attr.state_focused},
            {}};

    private static final int[][] PROBES = {
            {},
            {android.R.attr.state_enabled, android.R.attr.state_checked},
            {android.R.attr.state_enabled, android.R.attr.state_pressed},
            {android.R.attr.state_enabled, android.R.attr.state_focused},
            {android.R.attr.state_enabled}};

    private static final String[] PREFIXES = {"android.widget.", "android.view.", "android.webkit."};
    private static final Map<String, Constructor<?>> CONSTRUCTORS = new HashMap<>();

    private Theming() {
    }

    static void install(Activity activity, Palette palette) {
        if (palette.isLight()) {
            activity.getTheme().applyStyle(R.style.ThemeOverlay_Brovan_Light, true);
        }

        if (activity.getLayoutInflater().getFactory2() != null) {
            return;
        }

        Palette from = Palette.defaults();
        AppCompatDelegate delegate = activity instanceof androidx.appcompat.app.AppCompatActivity
                ? ((androidx.appcompat.app.AppCompatActivity) activity).getDelegate()
                : null;

        LayoutInflaterCompat.setFactory2(activity.getLayoutInflater(), new LayoutInflater.Factory2() {
            @Override
            public View onCreateView(View parent, String name, Context context, android.util.AttributeSet attrs) {
                View view = delegate == null ? null : delegate.createView(parent, name, context, attrs);

                if (view == null) {
                    view = build(context, name, attrs);
                }

                if (view != null && !from.sameAs(palette)) {
                    paint(view, from, palette);
                }

                return view;
            }

            @Override
            public View onCreateView(String name, Context context, android.util.AttributeSet attrs) {
                return onCreateView(null, name, context, attrs);
            }
        });
    }

    static void paintOnShow(Dialog dialog, Palette palette) {
        dialog.setOnShowListener(shown -> {
            Window window = dialog.getWindow();

            if (window != null) {
                apply(window.getDecorView(), Palette.defaults(), palette);
            }
        });
    }

    private static View build(Context context, String name, android.util.AttributeSet attrs) {
        if (name.indexOf('.') > 0) {
            return construct(context, name, attrs);
        }

        for (String prefix : PREFIXES) {
            View view = construct(context, prefix + name, attrs);

            if (view != null) {
                return view;
            }
        }

        return null;
    }

    private static View construct(Context context, String name, android.util.AttributeSet attrs) {
        try {
            Constructor<?> constructor = CONSTRUCTORS.get(name);

            if (constructor == null) {
                constructor = context.getClassLoader().loadClass(name)
                        .getConstructor(Context.class, android.util.AttributeSet.class);
                CONSTRUCTORS.put(name, constructor);
            }

            return (View) constructor.newInstance(context, attrs);
        } catch (ReflectiveOperationException | ClassCastException unavailable) {
            return null;
        }
    }

    static void apply(Activity activity, Palette from, Palette to) {
        Window window = activity.getWindow();
        int background = to.get(Palette.Role.BACKGROUND);

        window.setBackgroundDrawable(new ColorDrawable(background));
        window.setStatusBarColor(background);
        window.setNavigationBarColor(background);

        WindowInsetsControllerCompat bars = WindowCompat.getInsetsController(window, window.getDecorView());
        bars.setAppearanceLightStatusBars(to.isLight());
        bars.setAppearanceLightNavigationBars(to.isLight());

        apply(window.getDecorView(), from, to);
    }

    static void apply(View root, Palette from, Palette to) {
        if (from.sameAs(to)) {
            return;
        }

        paint(root, from, to);

        if (root instanceof ViewGroup) {
            ViewGroup group = (ViewGroup) root;

            for (int i = 0; i < group.getChildCount(); i++) {
                apply(group.getChildAt(i), from, to);
            }
        }
    }

    static int color(Context context, Palette.Role role) {
        return new Settings(context).palette().get(role);
    }

    static MaterialAlertDialogBuilder dialog(Context context) {
        return dialog(context, new Settings(context).palette());
    }

    static MaterialAlertDialogBuilder dialog(Context context, Palette palette) {
        MaterialAlertDialogBuilder builder = new MaterialAlertDialogBuilder(context);

        if (!palette.sameAs(Palette.defaults())) {
            GradientDrawable surface = new GradientDrawable();
            surface.setShape(GradientDrawable.RECTANGLE);
            surface.setColor(palette.get(Palette.Role.SURFACE));
            surface.setCornerRadius(context.getResources().getDisplayMetrics().density * 24f);
            builder.setBackground(surface);
        }

        return builder;
    }

    private static void paint(View view, Palette from, Palette to) {
        if (view.getBackground() != null) {
            view.setBackground(repaint(view.getBackground().mutate(), from, to));
        }

        if (view.getForeground() != null) {
            view.setForeground(repaint(view.getForeground().mutate(), from, to));
        }

        if (view.getBackgroundTintList() != null) {
            view.setBackgroundTintList(remap(view.getBackgroundTintList(), from, to));
        }

        if (view instanceof MaterialCardView) {
            MaterialCardView card = (MaterialCardView) view;
            card.setCardBackgroundColor(remap(card.getCardBackgroundColor(), from, to));
            card.setStrokeColor(remap(card.getStrokeColorStateList(), from, to));
        }

        if (view instanceof MaterialButton) {
            MaterialButton button = (MaterialButton) view;
            button.setIconTint(remap(button.getIconTint(), from, to));
            button.setStrokeColor(remap(button.getStrokeColor(), from, to));
        }

        if (view instanceof Slider) {
            Slider slider = (Slider) view;
            slider.setThumbTintList(remap(slider.getThumbTintList(), from, to));
            slider.setTrackActiveTintList(remap(slider.getTrackActiveTintList(), from, to));
            slider.setTrackInactiveTintList(remap(slider.getTrackInactiveTintList(), from, to));
            slider.setHaloTintList(remap(slider.getHaloTintList(), from, to));
            slider.setTickActiveTintList(remap(slider.getTickActiveTintList(), from, to));
            slider.setTickInactiveTintList(remap(slider.getTickInactiveTintList(), from, to));
        }

        if (view instanceof BaseProgressIndicator) {
            BaseProgressIndicator<?> bar = (BaseProgressIndicator<?>) view;
            bar.setIndicatorColor(remap(bar.getIndicatorColor(), from, to));
            bar.setTrackColor(from.remap(bar.getTrackColor(), to));
        }

        if (view instanceof NavigationView) {
            NavigationView navigation = (NavigationView) view;
            navigation.setItemTextColor(remap(navigation.getItemTextColor(), from, to));
            navigation.setItemIconTintList(remap(navigation.getItemIconTintList(), from, to));

            if (navigation.getItemBackground() != null) {
                navigation.setItemBackground(repaint(navigation.getItemBackground().mutate(), from, to));
            }
        }

        if (view instanceof AppBarLayout) {
            AppBarLayout bar = (AppBarLayout) view;
            bar.setLiftOnScroll(false);
            bar.setBackground(new ColorDrawable(to.get(Palette.Role.SURFACE)));
            bar.setStatusBarForeground(null);
        }

        if (view instanceof TextView) {
            TextView text = (TextView) view;
            text.setTextColor(remap(text.getTextColors(), from, to));
            text.setHintTextColor(remap(text.getHintTextColors(), from, to));
        }

        if (view instanceof Toolbar) {
            Toolbar bar = (Toolbar) view;

            if (bar.getNavigationIcon() != null) {
                Drawable icon = bar.getNavigationIcon().mutate();
                icon.setTintList(ColorStateList.valueOf(to.get(Palette.Role.TEXT_PRIMARY)));
                bar.setNavigationIcon(icon);
            }

            bar.setTitleTextColor(to.get(Palette.Role.TEXT_PRIMARY));

            if (bar instanceof MaterialToolbar) {
                ((MaterialToolbar) bar).setNavigationIconTint(to.get(Palette.Role.TEXT_PRIMARY));
            }
        }

        if (view instanceof ImageView && ((ImageView) view).getImageTintList() != null) {
            ImageView image = (ImageView) view;
            image.setImageTintList(remap(image.getImageTintList(), from, to));
        }

        if (view instanceof SwitchCompat) {
            SwitchCompat toggle = (SwitchCompat) view;
            toggle.setThumbTintList(remap(toggle.getThumbTintList(), from, to));
            toggle.setTrackTintList(remap(toggle.getTrackTintList(), from, to));
        }

        if (view instanceof MaterialSwitch) {
            MaterialSwitch toggle = (MaterialSwitch) view;
            toggle.setTrackDecorationTintList(remap(toggle.getTrackDecorationTintList(), from, to));
        }

        if (view instanceof TextInputLayout) {
            TextInputLayout field = (TextInputLayout) view;
            field.setBoxBackgroundColor(from.remap(field.getBoxBackgroundColor(), to));
            field.setBoxStrokeColor(from.remap(field.getBoxStrokeColor(), to));
            field.setDefaultHintTextColor(remap(field.getDefaultHintTextColor(), from, to));
        }

        if (view instanceof AutoCompleteTextView && ((AutoCompleteTextView) view).getDropDownBackground() != null) {
            GradientDrawable popup = new GradientDrawable();
            popup.setShape(GradientDrawable.RECTANGLE);
            popup.setColor(to.get(Palette.Role.SURFACE));
            popup.setStroke(1, to.get(Palette.Role.OUTLINE));
            popup.setCornerRadius(view.getResources().getDisplayMetrics().density * 12f);
            ((AutoCompleteTextView) view).setDropDownBackgroundDrawable(popup);
        }
    }

    private static Drawable repaint(Drawable drawable, Palette from, Palette to) {
        if (drawable instanceof ColorDrawable) {
            ColorDrawable flat = (ColorDrawable) drawable;
            flat.setColor(from.remap(flat.getColor(), to));
            return drawable;
        }

        if (drawable instanceof MaterialShapeDrawable) {
            MaterialShapeDrawable shape = (MaterialShapeDrawable) drawable;
            shape.setFillColor(remap(shape.getFillColor(), from, to));
            shape.setStrokeColor(remap(shape.getStrokeColor(), from, to));
            return drawable;
        }

        if (drawable instanceof GradientDrawable) {
            GradientDrawable shape = (GradientDrawable) drawable;

            if (shape.getColor() != null) {
                shape.setColor(remap(shape.getColor(), from, to));
            }

            if (shape.getColors() != null) {
                shape.setColors(remap(shape.getColors(), from, to));
            }

            return drawable;
        }

        if (drawable instanceof InsetDrawable) {
            Drawable inner = ((InsetDrawable) drawable).getDrawable();

            if (inner != null) {
                repaint(inner, from, to);
            }

            return drawable;
        }

        if (drawable instanceof LayerDrawable) {
            LayerDrawable layers = (LayerDrawable) drawable;

            for (int i = 0; i < layers.getNumberOfLayers(); i++) {
                repaint(layers.getDrawable(i), from, to);
            }
        }

        return drawable;
    }

    private static ColorStateList remap(ColorStateList colors, Palette from, Palette to) {
        if (colors == null) {
            return null;
        }

        if (!colors.isStateful()) {
            return ColorStateList.valueOf(from.remap(colors.getDefaultColor(), to));
        }

        int[] mapped = new int[SPECS.length];
        for (int i = 0; i < SPECS.length; i++) {
            mapped[i] = from.remap(colors.getColorForState(PROBES[i], colors.getDefaultColor()), to);
        }

        return new ColorStateList(SPECS, mapped);
    }

    private static int[] remap(int[] colors, Palette from, Palette to) {
        int[] mapped = new int[colors.length];

        for (int i = 0; i < colors.length; i++) {
            mapped[i] = from.remap(colors[i], to);
        }

        return mapped;
    }
}
