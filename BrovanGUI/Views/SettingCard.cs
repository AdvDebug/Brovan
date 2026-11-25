using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using BrovanGUI.ViewModels;

namespace BrovanGUI.Views
{
    public class SettingCard : ContentControl
    {
        public static readonly StyledProperty<string?> HeaderProperty =
            AvaloniaProperty.Register<SettingCard, string?>(nameof(Header));

        public static readonly StyledProperty<string?> DescriptionProperty =
            AvaloniaProperty.Register<SettingCard, string?>(nameof(Description));

        public static readonly StyledProperty<StatusKind> StatusProperty =
            AvaloniaProperty.Register<SettingCard, StatusKind>(nameof(Status));

        static SettingCard()
        {
            StatusProperty.Changed.AddClassHandler<SettingCard>((Card, _) => Card.UpdateStatusClasses());
        }

        public string? Header
        {
            get => GetValue(HeaderProperty);
            set => SetValue(HeaderProperty, value);
        }

        public string? Description
        {
            get => GetValue(DescriptionProperty);
            set => SetValue(DescriptionProperty, value);
        }

        public StatusKind Status
        {
            get => GetValue(StatusProperty);
            set => SetValue(StatusProperty, value);
        }

        private void UpdateStatusClasses()
        {
            PseudoClasses.Set(":good", Status == StatusKind.Good);
            PseudoClasses.Set(":warn", Status == StatusKind.Warn);
            PseudoClasses.Set(":bad", Status == StatusKind.Bad);
        }
    }

    public class StepCard : SettingCard
    {
        public static readonly StyledProperty<string?> NumberProperty =
            AvaloniaProperty.Register<StepCard, string?>(nameof(Number));

        public static readonly StyledProperty<string?> NoteProperty =
            AvaloniaProperty.Register<StepCard, string?>(nameof(Note));

        public static readonly StyledProperty<bool> IsDoneProperty =
            AvaloniaProperty.Register<StepCard, bool>(nameof(IsDone));

        public static readonly StyledProperty<bool> IsProblemProperty =
            AvaloniaProperty.Register<StepCard, bool>(nameof(IsProblem));

        public static readonly StyledProperty<bool> IsCurrentProperty =
            AvaloniaProperty.Register<StepCard, bool>(nameof(IsCurrent));

        public static readonly StyledProperty<Geometry?> IconProperty =
            AvaloniaProperty.Register<StepCard, Geometry?>(nameof(Icon));

        public static readonly StyledProperty<object?> DetailProperty =
            AvaloniaProperty.Register<StepCard, object?>(nameof(Detail));

        static StepCard()
        {
            IsDoneProperty.Changed.AddClassHandler<StepCard>((Card, _) => Card.PseudoClasses.Set(":done", Card.IsDone));
            IsProblemProperty.Changed.AddClassHandler<StepCard>((Card, _) => Card.PseudoClasses.Set(":problem", Card.IsProblem));
            IsCurrentProperty.Changed.AddClassHandler<StepCard>((Card, _) => Card.PseudoClasses.Set(":current", Card.IsCurrent));
            IconProperty.Changed.AddClassHandler<StepCard>((Card, _) => Card.PseudoClasses.Set(":icon", Card.Icon != null));
        }

        public string? Number
        {
            get => GetValue(NumberProperty);
            set => SetValue(NumberProperty, value);
        }

        public string? Note
        {
            get => GetValue(NoteProperty);
            set => SetValue(NoteProperty, value);
        }

        public bool IsDone
        {
            get => GetValue(IsDoneProperty);
            set => SetValue(IsDoneProperty, value);
        }

        public bool IsProblem
        {
            get => GetValue(IsProblemProperty);
            set => SetValue(IsProblemProperty, value);
        }

        public bool IsCurrent
        {
            get => GetValue(IsCurrentProperty);
            set => SetValue(IsCurrentProperty, value);
        }

        public Geometry? Icon
        {
            get => GetValue(IconProperty);
            set => SetValue(IconProperty, value);
        }

        public object? Detail
        {
            get => GetValue(DetailProperty);
            set => SetValue(DetailProperty, value);
        }
    }
}
