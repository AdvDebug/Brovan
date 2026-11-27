using Avalonia.Controls;
using Avalonia.Interactivity;
using BrovanGUI.ViewModels;

namespace BrovanGUI.Views
{
    public partial class ProfilePage : UserControl
    {
        public ProfilePage()
        {
            InitializeComponent();
            Scroller.ScrollChanged += (_, _) => HeaderBar.Classes.Set("scrolled", Scroller.Offset.Y > 0.5);
        }

        private void OpenFolderClick(object? Sender, RoutedEventArgs Event)
        {
            MoreButton.Flyout?.Hide();
            (DataContext as ProfileViewModel)?.OpenFolderCommand.Execute(null);
        }

        private void RemoveClick(object? Sender, RoutedEventArgs Event)
        {
            MoreButton.Flyout?.Hide();
            (DataContext as ProfileViewModel)?.RemoveCommand.Execute(null);
        }
    }
}
