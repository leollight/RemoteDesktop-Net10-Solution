using System.Windows;
using RemoteDesktop.Media;

namespace RemoteDesktop.Host.Agent;

public partial class MainWindow : Window
{
    private readonly InteractiveSessionManager _manager = new();
    private readonly CancellationTokenSource _cts = new();

    public MainWindow()
    {
        InitializeComponent();
        var caps = MediaPipelineCapabilities.Current;
        CapabilitiesText.Text =
            $"CaptureImplemented={caps.CaptureImplemented}, AudioImplemented={caps.AudioImplemented}, InputInjectionImplemented={caps.InputInjectionImplemented}, WebRtcMediaEngineImplemented={caps.WebRtcMediaEngineImplemented}";

        _manager.StatusChanged += msg => Dispatcher.Invoke(() => StatusText.Text = msg);
        Loaded += (_, _) => _ = _manager.RunIpcClientLoopAsync(_cts.Token);
        Closed += (_, _) => _cts.Cancel();
    }
}
