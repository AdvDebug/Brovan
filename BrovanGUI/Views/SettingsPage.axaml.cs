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
        }

        private void ResetClick(object? Sender, RoutedEventArgs Event)
        {
            ResetButton.Flyout?.Hide();
            (DataContext as SettingsViewModel)?.ResetDefaultsCommand.Execute(null);
        }
    }
}
