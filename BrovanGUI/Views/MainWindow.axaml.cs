using System.ComponentModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Platform;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Avalonia.VisualTree;
using BrovanGUI.Models;
using BrovanGUI.ViewModels;

namespace BrovanGUI.Views
{
    public partial class MainWindow : Window
    {
        private const double MinPageHeight = 240;

        private readonly MainViewModel ViewModel;
        private bool CloseConfirmed;
        private double GripStartY;
        private double GripStartHeight;

        public MainWindow(string? LaunchProfile)
        {
            InitializeComponent();

            if (OperatingSystem.IsWindows())
            {
                ExtendClientAreaToDecorationsHint = true;
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

            AddHandler(DragDrop.DragOverEvent, DragOver);
            AddHandler(DragDrop.DropEvent, Drop);
            ProfileList.DoubleTapped += ProfileDoubleTapped;
            ContentHost.SizeChanged += (_, _) => OutputPane.MaxHeight = OutputLimit();

            Opened += (_, _) => BrovanHost.EnterEfficiencyMode();
            Closing += (_, Event) =>
            {
                if (!CloseConfirmed && Event.CloseReason == WindowCloseReason.WindowClosing && ViewModel.HasRunning)
                {
                    Event.Cancel = true;
                    CloseMessage.Text = ViewModel.StopWarning();
                    SetCloseOverlay(true);
                    CancelCloseButton.Focus();
                    return;
                }

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

        private void ProfileDoubleTapped(object? Sender, TappedEventArgs Event)
        {
            if (Event.Source is Visual Source && Source.FindAncestorOfType<ListBoxItem>(true)?.DataContext is ProfileViewModel Profile
                && Profile.LaunchCommand.CanExecute(null))
                Profile.LaunchCommand.Execute(null);
        }

        private void CancelCloseClick(object? Sender, RoutedEventArgs Event)
        {
            SetCloseOverlay(false);
        }

        private void CloseOverlayKeyDown(object? Sender, KeyEventArgs Event)
        {
            if (Event.Key != Key.Escape)
                return;

            SetCloseOverlay(false);
            Event.Handled = true;
        }

        private void SetCloseOverlay(bool Visible)
        {
            CloseOverlay.IsVisible = Visible;
            Sidebar.IsEnabled = !Visible;
            ContentHost.IsEnabled = !Visible;
        }

        private void ConfirmCloseClick(object? Sender, RoutedEventArgs Event)
        {
            CloseConfirmed = true;
            Close();
        }

        private async void CopyOutputClick(object? Sender, RoutedEventArgs Event)
        {
            await CopyAsync(Log.SelectedText ?? Log.AllText);
        }

        private void LogKeyDown(object? Sender, KeyEventArgs Event)
        {
            if (Event.Key != Key.C || !Event.KeyModifiers.HasFlag(KeyModifiers.Control))
                return;

            string? Text = Log.SelectedText;
            if (Text != null)
                _ = CopyAsync(Text);

            Event.Handled = true;
        }

        private async Task CopyAsync(string Text)
        {
            try
            {
                if (Clipboard != null)
                    await Clipboard.SetTextAsync(Text);
            }
            catch (Exception Error)
            {
                ViewModel.ReportProblem("Could not copy the output: " + Error.Message);
            }
        }

        private void InputKeyDown(object? Sender, KeyEventArgs Event)
        {
            if (Event.Key == Key.Enter)
            {
                ViewModel.Output.SubmitInput();
                Event.Handled = true;
            }
        }

        private void GripPressed(object? Sender, PointerPressedEventArgs Event)
        {
            if (!Event.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
                return;

            GripStartY = Event.GetPosition(this).Y;
            GripStartHeight = OutputPane.Bounds.Height;
            Event.Pointer.Capture(OutputGrip);
            Event.Handled = true;
        }

        private void GripMoved(object? Sender, PointerEventArgs Event)
        {
            if (Event.Pointer.Captured != OutputGrip)
                return;

            double Wanted = GripStartHeight - (Event.GetPosition(this).Y - GripStartY);
            ViewModel.Output.Height = Math.Round(Math.Min(Wanted, OutputLimit()));
        }

        private double OutputLimit()
        {
            return Math.Max(OutputViewModel.MinHeight, ContentHost.Bounds.Height - MinPageHeight);
        }

        private void GripReleased(object? Sender, PointerReleasedEventArgs Event)
        {
            Event.Pointer.Capture(null);
        }

        private void GripCaptureLost(object? Sender, PointerCaptureLostEventArgs Event)
        {
            ViewModel.Output.SaveLayout();
        }

        private static void DragOver(object? Sender, DragEventArgs Event)
        {
            Event.DragEffects = Event.DataTransfer.Contains(DataFormat.File) ? DragDropEffects.Copy : DragDropEffects.None;
        }

        private void Drop(object? Sender, DragEventArgs Event)
        {
            IStorageItem[]? Items = Event.DataTransfer.TryGetFiles();
            if (Items == null)
                return;

            if (Event.Source is Visual Source && Source.FindAncestorOfType<TextBox>(true) is TextBox Box)
            {
                string? First = Items.Length != 0 ? Items[0].TryGetLocalPath() : null;
                if (First != null && !Box.IsReadOnly)
                    Box.SetCurrentValue(TextBox.TextProperty, First);

                return;
            }

            foreach (IStorageItem Item in Items)
            {
                string? Path = Item.TryGetLocalPath();
                if (Path != null && File.Exists(Path))
                    ViewModel.AddDroppedFile(Path);
            }
        }
    }
}
