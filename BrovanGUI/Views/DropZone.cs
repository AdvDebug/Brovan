using Avalonia.Controls;
using Avalonia.Input;

namespace BrovanGUI.Views
{
    public class DropZone : Button
    {
        public DropZone()
        {
            DragDrop.SetAllowDrop(this, true);
            AddHandler(DragDrop.DragEnterEvent, (_, _) => Classes.Set("over", true));
            AddHandler(DragDrop.DragLeaveEvent, (_, _) => Classes.Set("over", false));
            AddHandler(DragDrop.DropEvent, (_, _) => Classes.Set("over", false), handledEventsToo: true);
        }

        protected override Type StyleKeyOverride => typeof(Button);
    }
}
