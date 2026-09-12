using Avalonia;

namespace BrovanGUI
{
    internal static class Program
    {
        [STAThread]
        public static void Main(string[] Args)
        {
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(Args);
        }

        public static AppBuilder BuildAvaloniaApp()
        {
            return AppBuilder.Configure<App>()
                .UsePlatformDetect()
                .With(new Win32PlatformOptions { RenderingMode = new[] { Win32RenderingMode.Software } })
                .With(new X11PlatformOptions { RenderingMode = new[] { X11RenderingMode.Software } })
                .WithInterFont()
                .LogToTrace();
        }
    }
}
