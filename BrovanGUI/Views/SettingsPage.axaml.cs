using Avalonia.Controls;
using Avalonia.Interactivity;
using BrovanGUI.ViewModels;

namespace BrovanGUI.Views
{
    public partial class SettingsPage : UserControl
    {
        public SettingsPage()
        {
            InitializeComponent();
            Scroller.ScrollChanged += (_, _) => HeaderBar.Classes.Set("scrolled", Scroller.Offset.Y > 0.5);
        }

        private void ResetClick(object? Sender, RoutedEventArgs Event)
        {
            ResetButton.Flyout?.Hide();
            (DataContext as SettingsViewModel)?.ResetDefaultsCommand.Execute(null);
        }
    }
}
