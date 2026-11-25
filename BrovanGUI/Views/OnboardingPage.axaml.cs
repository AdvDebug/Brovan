using Avalonia.Controls;
using Avalonia.Input;

namespace BrovanGUI.Views
{
    public partial class OnboardingPage : UserControl
    {
        public OnboardingPage()
        {
            InitializeComponent();
            DropZone.AddHandler(DragDrop.DragEnterEvent, (_, _) => DropZone.Classes.Set("over", true));
            DropZone.AddHandler(DragDrop.DragLeaveEvent, (_, _) => DropZone.Classes.Set("over", false));
            DropZone.AddHandler(DragDrop.DropEvent, (_, _) => DropZone.Classes.Set("over", false), handledEventsToo: true);
        }
    }
}
