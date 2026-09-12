using Avalonia;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Input;
using Avalonia.Media;
using Avalonia.Media.TextFormatting;
using BrovanGUI.ViewModels;

namespace BrovanGUI.Views
{
    // Only the visible lines are laid out, so the cost does not follow the number of lines kept.
    public sealed class LogView : Control
    {
        private const double TopPadding = 4;
        private const double LeftPadding = 8;

        public static readonly StyledProperty<LineRing?> LinesProperty =
            AvaloniaProperty.Register<LogView, LineRing?>(nameof(Lines));

        public static readonly StyledProperty<double> LineOffsetProperty =
            AvaloniaProperty.Register<LogView, double>(nameof(LineOffset), defaultBindingMode: BindingMode.TwoWay);

        public static readonly StyledProperty<double> HorizontalOffsetProperty =
            AvaloniaProperty.Register<LogView, double>(nameof(HorizontalOffset), defaultBindingMode: BindingMode.TwoWay);

        public static readonly StyledProperty<FontFamily> FontFamilyProperty =
            AvaloniaProperty.Register<LogView, FontFamily>(nameof(FontFamily), FontFamily.Default);

        public static readonly StyledProperty<double> FontSizeProperty =
            AvaloniaProperty.Register<LogView, double>(nameof(FontSize), 12);

        public static readonly StyledProperty<IBrush?> ForegroundProperty =
            AvaloniaProperty.Register<LogView, IBrush?>(nameof(Foreground), Brushes.White);

        public static readonly StyledProperty<IBrush?> GoodBrushProperty =
            AvaloniaProperty.Register<LogView, IBrush?>(nameof(GoodBrush));

        public static readonly StyledProperty<IBrush?> WarnBrushProperty =
            AvaloniaProperty.Register<LogView, IBrush?>(nameof(WarnBrush));

        public static readonly StyledProperty<IBrush?> BadBrushProperty =
            AvaloniaProperty.Register<LogView, IBrush?>(nameof(BadBrush));

        public static readonly StyledProperty<IBrush?> AccentBrushProperty =
            AvaloniaProperty.Register<LogView, IBrush?>(nameof(AccentBrush));

        public static readonly StyledProperty<IBrush?> SelectionBrushProperty =
            AvaloniaProperty.Register<LogView, IBrush?>(nameof(SelectionBrush));

        public static readonly DirectProperty<LogView, double> ScrollMaximumProperty =
            AvaloniaProperty.RegisterDirect<LogView, double>(nameof(ScrollMaximum), Owner => Owner.ScrollMaximum);

        public static readonly DirectProperty<LogView, double> ViewportLinesProperty =
            AvaloniaProperty.RegisterDirect<LogView, double>(nameof(ViewportLines), Owner => Owner.ViewportLines);

        public static readonly DirectProperty<LogView, double> HorizontalMaximumProperty =
            AvaloniaProperty.RegisterDirect<LogView, double>(nameof(HorizontalMaximum), Owner => Owner.HorizontalMaximum);

        private double ScrollMaximumValue;
        private double ViewportLinesValue = 1;
        private double HorizontalMaximumValue;
        private double LineHeight = 18;
        private double CharWidth = 7;
        private bool Follow = true;
        private bool Dragging;
        private long SelectionAnchor = -1;
        private long SelectionEnd = -1;

        static LogView()
        {
            AffectsRender<LogView>(LineOffsetProperty, HorizontalOffsetProperty, ForegroundProperty, GoodBrushProperty,
                WarnBrushProperty, BadBrushProperty, AccentBrushProperty, SelectionBrushProperty);
            FocusableProperty.OverrideDefaultValue<LogView>(true);
        }

        public LogView()
        {
            ClipToBounds = true;
        }

        public LineRing? Lines
        {
            get => GetValue(LinesProperty);
            set => SetValue(LinesProperty, value);
        }

        public double LineOffset
        {
            get => GetValue(LineOffsetProperty);
            set => SetValue(LineOffsetProperty, value);
        }

        public double HorizontalOffset
        {
            get => GetValue(HorizontalOffsetProperty);
            set => SetValue(HorizontalOffsetProperty, value);
        }

        public FontFamily FontFamily
        {
            get => GetValue(FontFamilyProperty);
            set => SetValue(FontFamilyProperty, value);
        }

        public double FontSize
        {
            get => GetValue(FontSizeProperty);
            set => SetValue(FontSizeProperty, value);
        }

        public IBrush? Foreground
        {
            get => GetValue(ForegroundProperty);
            set => SetValue(ForegroundProperty, value);
        }

        public IBrush? GoodBrush
        {
            get => GetValue(GoodBrushProperty);
            set => SetValue(GoodBrushProperty, value);
        }

        public IBrush? WarnBrush
        {
            get => GetValue(WarnBrushProperty);
            set => SetValue(WarnBrushProperty, value);
        }

        public IBrush? BadBrush
        {
            get => GetValue(BadBrushProperty);
            set => SetValue(BadBrushProperty, value);
        }

        public IBrush? AccentBrush
        {
            get => GetValue(AccentBrushProperty);
            set => SetValue(AccentBrushProperty, value);
        }

        public IBrush? SelectionBrush
        {
            get => GetValue(SelectionBrushProperty);
            set => SetValue(SelectionBrushProperty, value);
        }

        public double ScrollMaximum => ScrollMaximumValue;
        public double ViewportLines => ViewportLinesValue;
        public double HorizontalMaximum => HorizontalMaximumValue;

        public string? SelectedText
        {
            get
            {
                LineRing? Ring = Lines;
                if (Ring == null || SelectionAnchor < 0)
                    return null;

                long First = Math.Min(SelectionAnchor, SelectionEnd) - Ring.FirstLineNumber;
                long Last = Math.Max(SelectionAnchor, SelectionEnd) - Ring.FirstLineNumber;
                if (Last < 0 || First >= Ring.Count)
                    return null;

                return Ring.Text((int)Math.Max(0, First), (int)Math.Min(Ring.Count - 1, Last));
            }
        }

        public string AllText => Lines?.Text(0, Lines.Count - 1) ?? string.Empty;

        public void ScrollToEnd()
        {
            Follow = true;
            LineOffset = ScrollMaximumValue;
        }

        protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs Change)
        {
            base.OnPropertyChanged(Change);

            if (Change.Property == LinesProperty)
            {
                if (Change.OldValue is LineRing Old)
                    Old.Changed -= OnLinesChanged;
                if (Change.NewValue is LineRing New)
                    New.Changed += OnLinesChanged;

                UpdateExtent();
            }
            else if (Change.Property == LineOffsetProperty)
            {
                Follow = LineOffset >= ScrollMaximumValue - 0.5;
            }
            else if (Change.Property == FontFamilyProperty || Change.Property == FontSizeProperty)
            {
                MeasureFont();
                UpdateExtent();
                InvalidateVisual();
            }
        }

        protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs Event)
        {
            base.OnAttachedToVisualTree(Event);
            MeasureFont();
            UpdateExtent();
        }

        protected override Size ArrangeOverride(Size FinalSize)
        {
            Size Result = base.ArrangeOverride(FinalSize);
            UpdateExtent();
            return Result;
        }

        private void OnLinesChanged()
        {
            UpdateExtent();
            if (Follow)
                LineOffset = ScrollMaximumValue;

            InvalidateVisual();
        }

        private void MeasureFont()
        {
            TextLayout Sample = new TextLayout("Mg", new Typeface(FontFamily), FontSize, Brushes.Black);
            LineHeight = Math.Ceiling(Sample.Height);
            CharWidth = Sample.WidthIncludingTrailingWhitespace / 2;
        }

        private void UpdateExtent()
        {
            int Count = Lines?.Count ?? 0;
            double Viewport = Math.Max(1, Math.Floor((Bounds.Height - TopPadding) / LineHeight));
            double Longest = (Lines?.LongestLine ?? 0) * CharWidth + LeftPadding * 2;

            SetAndRaise(ViewportLinesProperty, ref ViewportLinesValue, Viewport);
            SetAndRaise(ScrollMaximumProperty, ref ScrollMaximumValue, Math.Max(0, Count - Viewport));
            SetAndRaise(HorizontalMaximumProperty, ref HorizontalMaximumValue, Math.Max(0, Longest - Bounds.Width));

            if (LineOffset > ScrollMaximumValue)
                LineOffset = ScrollMaximumValue;
            if (HorizontalOffset > HorizontalMaximumValue)
                HorizontalOffset = HorizontalMaximumValue;
        }

        public override void Render(DrawingContext Context)
        {
            LineRing? Ring = Lines;
            if (Ring == null || Ring.Count == 0)
                return;

            int First = (int)Math.Clamp(LineOffset, 0, Ring.Count - 1);
            int Last = Math.Min(Ring.Count, First + (int)Math.Ceiling(Bounds.Height / LineHeight) + 1);
            long SelectionFirst = Math.Min(SelectionAnchor, SelectionEnd);
            long SelectionLast = Math.Max(SelectionAnchor, SelectionEnd);
            Typeface Face = new Typeface(FontFamily);
            double X = LeftPadding - HorizontalOffset;
            double Y = TopPadding;

            for (int i = First; i < Last; i++)
            {
                long Number = Ring.FirstLineNumber + i;
                if (SelectionAnchor >= 0 && Number >= SelectionFirst && Number <= SelectionLast && SelectionBrush != null)
                    Context.FillRectangle(SelectionBrush, new Rect(0, Y, Bounds.Width, LineHeight));

                string Text = Ring[i];
                if (Text.Length != 0)
                {
                    TextLayout Layout = new TextLayout(Text, Face, FontSize, BrushFor(Text));
                    Layout.Draw(Context, new Point(X, Y));
                }

                Y += LineHeight;
            }
        }

        // Brovan prefixes its own lines; the program's output keeps the plain colour.
        private IBrush? BrushFor(string Text)
        {
            if (Text.StartsWith("[-]", StringComparison.Ordinal) || Text.StartsWith("[!!]", StringComparison.Ordinal))
                return BadBrush ?? Foreground;
            if (Text.StartsWith("[+]", StringComparison.Ordinal))
                return GoodBrush ?? Foreground;
            if (Text.StartsWith("[!]", StringComparison.Ordinal))
                return WarnBrush ?? Foreground;
            if (Text.StartsWith("> ", StringComparison.Ordinal) || Text.StartsWith("< ", StringComparison.Ordinal))
                return AccentBrush ?? Foreground;

            return Foreground;
        }

        private long LineNumberAt(double Y)
        {
            LineRing? Ring = Lines;
            int Index = (int)Math.Floor((Y - TopPadding) / LineHeight) + (int)LineOffset;
            if (Ring == null || Index < 0 || Index >= Ring.Count)
                return -1;

            return Ring.FirstLineNumber + Index;
        }

        protected override void OnPointerPressed(PointerPressedEventArgs Event)
        {
            base.OnPointerPressed(Event);
            if (!Event.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
                return;

            Focus();
            long Number = LineNumberAt(Event.GetPosition(this).Y);
            SelectionAnchor = Number;
            SelectionEnd = Number;
            Dragging = Number >= 0;
            if (Dragging)
                Event.Pointer.Capture(this);

            InvalidateVisual();
            Event.Handled = true;
        }

        protected override void OnPointerMoved(PointerEventArgs Event)
        {
            base.OnPointerMoved(Event);
            if (!Dragging)
                return;

            long Number = LineNumberAt(Event.GetPosition(this).Y);
            if (Number >= 0 && Number != SelectionEnd)
            {
                SelectionEnd = Number;
                InvalidateVisual();
            }
        }

        protected override void OnPointerReleased(PointerReleasedEventArgs Event)
        {
            base.OnPointerReleased(Event);
            if (Dragging)
            {
                Dragging = false;
                Event.Pointer.Capture(null);
            }
        }

        protected override void OnPointerWheelChanged(PointerWheelEventArgs Event)
        {
            base.OnPointerWheelChanged(Event);
            if (Event.KeyModifiers.HasFlag(KeyModifiers.Shift))
                HorizontalOffset = Math.Clamp(HorizontalOffset - Event.Delta.Y * 40, 0, HorizontalMaximumValue);
            else
                LineOffset = Math.Clamp(LineOffset - Event.Delta.Y * 3, 0, ScrollMaximumValue);

            Event.Handled = true;
        }

        protected override void OnKeyDown(KeyEventArgs Event)
        {
            base.OnKeyDown(Event);
            if (!Event.KeyModifiers.HasFlag(KeyModifiers.Control))
                return;

            if (Event.Key == Key.C)
            {
                string? Text = SelectedText;
                if (Text != null)
                    _ = TopLevel.GetTopLevel(this)?.Clipboard?.SetTextAsync(Text);

                Event.Handled = true;
            }
            else if (Event.Key == Key.A && Lines != null && Lines.Count != 0)
            {
                SelectionAnchor = Lines.FirstLineNumber;
                SelectionEnd = Lines.FirstLineNumber + Lines.Count - 1;
                InvalidateVisual();
                Event.Handled = true;
            }
        }
    }
}
