using System.Windows;
using RemoteDesktop.Controller.Services;
using RemoteDesktop.Media;

namespace RemoteDesktop.Controller;

public partial class MainWindow : Window
{
    private readonly ControllerConfigStore _configStore = new();

    public MainWindow()
    {
        InitializeComponent();
        var cfg = _configStore.Load();
        ConfigStatusText.Text = string.IsNullOrWhiteSpace(cfg.BackendBaseUrl)
            ? $"Portable config path: {ControllerConfigStore.GetConfigPath()} (awaiting BackendBaseUrl configuration)"
            : $"Target backend: {cfg.BackendBaseUrl}";

        MediaStatusText.Text = MediaPipelineCapabilities.Current.StatusNote;
    }
}
