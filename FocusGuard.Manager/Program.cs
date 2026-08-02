using System.Diagnostics;
using System.Security.Principal;

namespace FocusGuard.Manager;

static class Program
{
    public static bool StartMinimized { get; private set; }

    [STAThread]
    static void Main(string[] args)
    {
        StartMinimized = args.Contains("--minimized", StringComparer.OrdinalIgnoreCase);

        // Verifica se está rodando como administrador
        if (!IsAdministrator())
        {
            // Tenta reiniciar como admin, passando os argumentos originais
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = Environment.ProcessPath,
                    Arguments = string.Join(" ", args),
                    UseShellExecute = true,
                    Verb = "runas"
                };
                Process.Start(startInfo);
            }
            catch
            {
                MessageBox.Show(
                    "Este programa precisa ser executado como Administrador para funcionar corretamente.",
                    "FocusGuard",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning
                );
            }
            return;
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}
