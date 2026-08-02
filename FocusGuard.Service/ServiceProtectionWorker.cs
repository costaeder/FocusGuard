using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.ServiceProcess;

namespace FocusGuard.Service;

/// <summary>
/// Worker que protege o servico contra tentativas de parada nao autorizadas.
/// Configura o servico para recuperacao automatica e monitora tentativas de parada.
/// </summary>
public class ServiceProtectionWorker : BackgroundService
{
    private readonly ILogger<ServiceProtectionWorker> _logger;
    private readonly TimeSpan _checkInterval = TimeSpan.FromSeconds(5);
    private const string ServiceName = "FocusGuard Service";
    private bool _protectionConfigured = false;

    public ServiceProtectionWorker(ILogger<ServiceProtectionWorker> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("FocusGuard Service Protection iniciado");

        // Configura protecoes na inicializacao
        ConfigureServiceRecovery();
        ConfigureServiceFailureActions();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                MonitorServiceHealth();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro no monitoramento de protecao do servico");
            }

            await Task.Delay(_checkInterval, stoppingToken);
        }
    }

    /// <summary>
    /// Configura acoes de recuperacao automatica do servico via sc.exe
    /// </summary>
    private void ConfigureServiceRecovery()
    {
        if (_protectionConfigured) return;

        try
        {
            // Configura para reiniciar automaticamente em caso de falha
            // reset=86400 (24h para resetar contador de falhas)
            // actions=restart/5000/restart/10000/restart/30000 (reinicia em 5s, 10s, 30s)
            var result = RunCommand("sc.exe", $"failure \"{ServiceName}\" reset=86400 actions=restart/5000/restart/10000/restart/30000");

            if (result)
            {
                _logger.LogInformation("Recuperacao automatica do servico configurada");
            }

            // Configura para reiniciar tambem em paradas normais (nao apenas falhas)
            // Isso dificulta parar o servico permanentemente
            result = RunCommand("sc.exe", $"failureflag \"{ServiceName}\" 1");

            if (result)
            {
                _logger.LogInformation("Flag de falha em parada configurado");
            }

            _protectionConfigured = true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao configurar recuperacao do servico");
        }
    }

    /// <summary>
    /// Configura permissoes do servico para dificultar parada por usuarios nao-SYSTEM
    /// </summary>
    private void ConfigureServiceFailureActions()
    {
        try
        {
            // Primeiro obtemos o SDDL atual para log/debug
            var currentSddl = GetServiceSddl();
            if (!string.IsNullOrEmpty(currentSddl))
            {
                _logger.LogDebug("SDDL atual do servico: {Sddl}", currentSddl);
            }

            // Por seguranca, nao alteramos SDDL automaticamente pois pode causar problemas
            // A protecao principal e via recuperacao automatica configurada em ConfigureServiceRecovery()
            _logger.LogInformation("Servico protegido - recuperacao automatica ativa");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao configurar permissoes do servico");
        }
    }

    private string? GetServiceSddl()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"sdshow \"{ServiceName}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return null;

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            return output.Trim();
        }
        catch
        {
            return null;
        }
    }

    private void MonitorServiceHealth()
    {
        // Verifica se o servico esta funcionando corretamente
        try
        {
            using var sc = new ServiceController(ServiceName);

            if (sc.Status == ServiceControllerStatus.StopPending)
            {
                _logger.LogWarning("Detectada tentativa de parada do servico!");
            }
            else if (sc.Status == ServiceControllerStatus.Stopped)
            {
                _logger.LogWarning("Servico foi parado! Recuperacao automatica deve reinicia-lo.");
            }
        }
        catch (InvalidOperationException)
        {
            // Servico nao existe ou nao pode ser acessado - normal durante shutdown
        }
    }

    private bool RunCommand(string fileName, string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return false;

            process.WaitForExit(5000);
            return process.ExitCode == 0;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao executar comando: {FileName} {Arguments}", fileName, arguments);
            return false;
        }
    }
}
