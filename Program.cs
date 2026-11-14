namespace ExperimentA;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "--verify-loopback")
        {
            return LoopbackVerification.Run(args[1]);
        }

        ApplicationConfiguration.Initialize();
        using var window = new MainForm();
        string? demoLog = args.Length == 2 && args[0] == "--demo" ? args[1] : null;
        if (demoLog is not null)
        {
            window.Shown += async (_, _) => await window.RunDemoAsync(demoLog);
        }
        Application.Run(window);
        return window.DemoExitCode;
    }
}
