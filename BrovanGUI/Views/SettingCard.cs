using Avalonia;
using Avalonia.Controls;
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
}
