using System.ComponentModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using BrovanGUI.Models;
using BrovanGUI.ViewModels;

namespace BrovanGUI.Views
{
    public partial class MainWindow : Window
    {
        private readonly MainViewModel ViewModel;

        public MainWindow(string? LaunchProfile)
        {
            InitializeComponent();

            if (OperatingSystem.IsWindows())
            {
                ExtendClientAreaToDecorationsHint = true;
                ExtendClientAreaChromeHints = ExtendClientAreaChromeHints.PreferSystemChrome;
                ExtendClientAreaTitleBarHeightHint = 40;
                ContentHost.Margin = new Thickness(0, 40, 0, 0);
            }
            else
            {
                ContentHost.Margin = new Thickness(0, 8, 0, 0);
            }

            ViewModel = new MainViewModel(new Dialogs(this), LaunchProfile);
            DataContext = ViewModel;
            ViewModel.Output.PropertyChanged += OutputPropertyChanged;

            ProfileList.AddHandler(DragDrop.DragOverEvent, DragOver);
            ProfileList.AddHandler(DragDrop.DropEvent, Drop);

            Opened += (_, _) => BrovanHost.EnterEfficiencyMode();
            Closing += (_, _) =>
            {
                ViewModel.StopAll();
                ViewModel.SaveNow();
            };
        }

        private void OutputPropertyChanged(object? Sender, PropertyChangedEventArgs Event)
        {
            if (Event.PropertyName == nameof(OutputViewModel.IsOpen) && ViewModel.Output.IsOpen)
                Dispatcher.UIThread.Post(Log.ScrollToEnd, DispatcherPriority.Background);
        }

        private void RemoveClick(object? Sender, RoutedEventArgs Event)
        {
            RemoveButton.Flyout?.Hide();
            ViewModel.RemoveSelectedCommand.Execute(null);
        }

        private async void CopyOutputClick(object? Sender, RoutedEventArgs Event)
        {
            if (Clipboard != null)
                await Clipboard.SetTextAsync(Log.SelectedText ?? Log.AllText);
        }

        private void InputKeyDown(object? Sender, KeyEventArgs Event)
        {
            if (Event.Key == Key.Enter)
            {
                ViewModel.Output.SubmitInput();
                Event.Handled = true;
            }
        }

        private static void DragOver(object? Sender, DragEventArgs Event)
        {
            Event.DragEffects = Event.Data.Contains(DataFormats.Files) ? DragDropEffects.Copy : DragDropEffects.None;
        }

        private void Drop(object? Sender, DragEventArgs Event)
        {
            IEnumerable<IStorageItem>? Items = Event.Data.GetFiles();
            if (Items == null)
                return;

            foreach (IStorageItem Item in Items)
            {
                string? Path = Item.TryGetLocalPath();
                if (Path != null && File.Exists(Path))
                    ViewModel.AddProfileFromPath(Path);
            }
        }
    }
}
