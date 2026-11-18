using System.Windows;

namespace BatV2;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        SystemProxy.ResetIfOurs();
        base.OnStartup(e);
    }
}
