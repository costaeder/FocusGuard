using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using FocusGuard.Shared.Models;
using FocusGuard.Shared.Services;

namespace FocusGuard.Service;

public class HostsProtectionWorker : BackgroundService
{
    private readonly ILogger<HostsProtectionWorker> _logger;
    private readonly TimeSpan _checkInterval = TimeSpan.FromSeconds(30);
    private DateTime _lastConfigUpdate = DateTime.MinValue;

    public HostsProtectionWorker(ILogger<HostsProtectionWorker> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var config = AppConfig.Load();
        _logger.LogInformation("FocusGuard Hosts Protection iniciado (DryRun: {DryRun})", config.DryRun);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                SyncHostsFile();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao sincronizar arquivo hosts");
            }

            await Task.Delay(_checkInterval, stoppingToken);
        }
    }

    private void SyncHostsFile()
    {
        var config = AppConfig.Load();
        Action<string> log = msg => _logger.LogInformation(msg);

        // Remove dominios whitelisted que foram bloqueados por engano (falsos positivos de DNS family)
        var removedWhitelisted = config.BlockedSites
            .Where(s => ContentAnalyzerWorker.IsWhitelisted(s))
            .ToList();

        if (removedWhitelisted.Count > 0)
        {
            foreach (var site in removedWhitelisted)
            {
                config.BlockedSites.Remove(site);
                _logger.LogWarning("Removido dominio whitelisted da lista de bloqueados: {Domain}", site);
            }
            config.Save();
        }

        // Só sincroniza se a configuração foi atualizada
        if (config.LastUpdated > _lastConfigUpdate)
        {
            _logger.LogInformation("{Prefix}Configuração atualizada detectada. Sincronizando hosts...",
                config.DryRun ? "[DRY-RUN] " : "");

            if (HostsService.SyncWithConfig(config.BlockedSites, config.DryRun, log))
            {
                _lastConfigUpdate = config.LastUpdated;
                _logger.LogInformation("{Prefix}Arquivo hosts sincronizado com {Count} sites bloqueados",
                    config.DryRun ? "[DRY-RUN] " : "", config.BlockedSites.Count);
            }
            else
            {
                _logger.LogError("Falha ao sincronizar arquivo hosts");
            }
        }

        // Verifica se os sites configurados estão no hosts
        var hostsBlocked = HostsService.GetBlockedSites();
        var configBlocked = config.BlockedSites;

        var missing = configBlocked.Except(hostsBlocked, StringComparer.OrdinalIgnoreCase).ToList();

        if (missing.Count > 0)
        {
            _logger.LogWarning("{Prefix}{Count} sites removidos do hosts detectados. {Action}",
                config.DryRun ? "[DRY-RUN] " : "",
                missing.Count,
                config.DryRun ? "Restauraria..." : "Restaurando...");

            if (HostsService.SyncWithConfig(configBlocked, config.DryRun, log))
            {
                _logger.LogInformation("{Prefix}Sites restaurados no arquivo hosts",
                    config.DryRun ? "[DRY-RUN] " : "");
            }
        }
    }
}
