using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using BrovanGUI.Views;

namespace BrovanGUI
{
    public partial class App : Application
    {
        public override void Initialize()
        {
            AvaloniaXamlLoader.Load(this);
        }

        public override void OnFrameworkInitializationCompleted()
        {
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime Desktop)
                Desktop.MainWindow = new MainWindow(LaunchProfile(Desktop.Args));

            base.OnFrameworkInitializationCompleted();
        }

        private static string? LaunchProfile(string[]? Args)
        {
            if (Args == null)
                return null;

            for (int i = 0; i < Args.Length; i++)
            {
                if (Args[i] == "--launch" && i + 1 < Args.Length)
                    return Args[i + 1];

                if (Args[i].StartsWith("--launch=", StringComparison.Ordinal))
                    return Args[i].Substring("--launch=".Length);
            }

            return null;
        }
    }
}
