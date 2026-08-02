using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using System.Diagnostics;
using FocusGuard.Shared.Models;

namespace FocusGuard.Service;

/// <summary>
/// Worker que monitora e bloqueia instalacao de novos navegadores.
/// Detecta instaladores conhecidos e impede sua execucao.
/// </summary>
public class BrowserInstallBlockerWorker : BackgroundService
{
    private readonly ILogger<BrowserInstallBlockerWorker> _logger;
    private readonly TimeSpan _checkInterval = TimeSpan.FromSeconds(3);

    // Lista de processos de instaladores de navegadores conhecidos
    private static readonly HashSet<string> BrowserInstallerProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // Chrome
        "ChromeSetup",
        "ChromeStandaloneSetup",
        "GoogleChromeSetup",
        "chrome_installer",

        // Firefox
        "Firefox Installer",
        "Firefox Setup",
        "FirefoxInstaller",
        "firefox-setup",

        // Edge (downloads adicionais)
        "MicrosoftEdgeSetup",
        "EdgeSetup",

        // Opera
        "OperaSetup",
        "Opera Installer",
        "opera_autoupdate",

        // Brave
        "BraveSetup",
        "BraveBrowserSetup",
        "brave_installer",

        // Tor Browser
        "torbrowser-install",
        "tor-browser-install",

        // Arc
        "ArcInstaller",

        // Outros
        "browser_installer",
        "browsersetup"
    };

    // Padroes de nome de arquivo para detectar instaladores
    private static readonly string[] BrowserInstallerPatterns = new[]
    {
        "chrome", "firefox", "opera", "brave", "tor",
        "browser", "navegador", "edge", "arc"
    };

    // Navegadores permitidos (lista fixa)
    private static readonly string[] AllowedBrowserKeywords = new[]
    {
        "firefox", "edge", "chrome", "vivaldi"
    };

    // Registro de navegadores instalados para detectar novos
    private HashSet<string> _knownBrowsers = new(StringComparer.OrdinalIgnoreCase);

    public BrowserInstallBlockerWorker(ILogger<BrowserInstallBlockerWorker> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("FocusGuard Browser Install Blocker iniciado");
        _logger.LogInformation("Navegadores permitidos: Firefox, Edge, Chrome, Vivaldi");

        // Registra navegadores atuais para detectar novos
        _knownBrowsers = GetInstalledBrowsers();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var config = AppConfig.Load();

                // Verifica se o bloqueio esta ativo
                if (!config.BlockBrowserInstalls)
                {
                    await Task.Delay(_checkInterval, stoppingToken);
                    continue;
                }

                // Apenas bloqueia se DryRun estiver desativado
                if (!config.DryRun)
                {
                    BlockBrowserInstallers();
                    DetectNewBrowserInstallations();
                }
                else
                {
                    MonitorBrowserInstallersOnly();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro no bloqueio de instaladores de navegadores");
            }

            await Task.Delay(_checkInterval, stoppingToken);
        }
    }

    /// <summary>
    /// Bloqueia processos de instaladores de navegadores ativos
    /// </summary>
    private void BlockBrowserInstallers()
    {
        var processes = Process.GetProcesses();

        foreach (var process in processes)
        {
            try
            {
                var processName = process.ProcessName;

                // Verifica se e um instalador conhecido
                if (IsBrowserInstaller(processName))
                {
                    _logger.LogWarning("Bloqueando instalador de navegador: {ProcessName} (PID: {Pid})",
                        processName, process.Id);

                    try
                    {
                        process.Kill(true);
                        _logger.LogInformation("Instalador {ProcessName} bloqueado com sucesso", processName);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Falha ao bloquear instalador {ProcessName}", processName);
                    }
                }

                // Verifica pelo caminho do executavel (mais preciso)
                try
                {
                    var path = process.MainModule?.FileName;
                    if (!string.IsNullOrEmpty(path) && IsBrowserInstallerPath(path))
                    {
                        _logger.LogWarning("Bloqueando instalador detectado por caminho: {Path}", path);

                        try
                        {
                            process.Kill(true);
                            _logger.LogInformation("Instalador bloqueado: {Path}", path);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "Falha ao bloquear: {Path}", path);
                        }
                    }
                }
                catch (System.ComponentModel.Win32Exception)
                {
                    // Acesso negado ao modulo - processo de sistema, ignora
                }
            }
            catch (InvalidOperationException)
            {
                // Processo ja terminou
            }
            finally
            {
                process.Dispose();
            }
        }
    }

    /// <summary>
    /// Apenas monitora e loga (modo DryRun)
    /// </summary>
    private void MonitorBrowserInstallersOnly()
    {
        var processes = Process.GetProcesses();

        foreach (var process in processes)
        {
            try
            {
                var processName = process.ProcessName;

                if (IsBrowserInstaller(processName))
                {
                    _logger.LogWarning("[DRY-RUN] Detectado instalador de navegador: {ProcessName} (PID: {Pid})",
                        processName, process.Id);
                }
            }
            catch (InvalidOperationException)
            {
                // Processo ja terminou
            }
            finally
            {
                process.Dispose();
            }
        }
    }

    /// <summary>
    /// Detecta se novos navegadores foram instalados
    /// </summary>
    private void DetectNewBrowserInstallations()
    {
        var currentBrowsers = GetInstalledBrowsers();
        var newBrowsers = currentBrowsers.Except(_knownBrowsers, StringComparer.OrdinalIgnoreCase).ToList();

        if (newBrowsers.Count > 0)
        {
            foreach (var browser in newBrowsers)
            {
                // Verifica se e um navegador permitido
                if (IsAllowedBrowser(browser))
                {
                    _logger.LogInformation("Navegador permitido detectado: {Browser}", browser);
                    continue;
                }

                _logger.LogWarning("ALERTA: Navegador NAO PERMITIDO detectado: {Browser}", browser);

                // Tenta desinstalar automaticamente
                TryUninstallBrowser(browser);
            }

            // Atualiza lista (mesmo que nao consiga desinstalar, para nao alertar repetidamente)
            _knownBrowsers = currentBrowsers;
        }
    }

    /// <summary>
    /// Verifica se o navegador esta na lista de permitidos (Firefox, Edge, Chrome)
    /// </summary>
    private bool IsAllowedBrowser(string browserName)
    {
        var lowerName = browserName.ToLower();
        return AllowedBrowserKeywords.Any(keyword => lowerName.Contains(keyword));
    }

    private bool IsBrowserInstaller(string processName)
    {
        var lowerName = processName.ToLower();

        // Ignora instaladores de navegadores permitidos (Firefox, Edge, Chrome)
        if (AllowedBrowserKeywords.Any(keyword => lowerName.Contains(keyword)))
            return false;

        // Verifica nome exato
        if (BrowserInstallerProcesses.Contains(processName))
            return true;

        // Verifica padroes
        foreach (var pattern in BrowserInstallerPatterns)
        {
            if (lowerName.Contains(pattern) &&
                (lowerName.Contains("setup") || lowerName.Contains("install") || lowerName.Contains("installer")))
            {
                return true;
            }
        }

        return false;
    }

    private bool IsBrowserInstallerPath(string path)
    {
        var lowerPath = path.ToLower();

        // Ignora instaladores de navegadores permitidos (Firefox, Edge, Chrome)
        if (AllowedBrowserKeywords.Any(keyword => lowerPath.Contains(keyword)))
            return false;

        // Verifica se esta em pasta de downloads ou temp
        var suspiciousFolders = new[] { "downloads", "temp", "tmp", "desktop" };
        var inSuspiciousFolder = suspiciousFolders.Any(f => lowerPath.Contains(f));

        if (!inSuspiciousFolder) return false;

        // Verifica padroes de nome
        var fileName = Path.GetFileNameWithoutExtension(path).ToLower();
        foreach (var pattern in BrowserInstallerPatterns)
        {
            if (fileName.Contains(pattern) &&
                (fileName.Contains("setup") || fileName.Contains("install") || fileName.Contains("installer")))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Obtem lista de navegadores instalados via registro do Windows
    /// </summary>
    private HashSet<string> GetInstalledBrowsers()
    {
        var browsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Chaves de registro onde navegadores se registram
        var registryPaths = new[]
        {
            @"SOFTWARE\Clients\StartMenuInternet",
            @"SOFTWARE\WOW6432Node\Clients\StartMenuInternet"
        };

        foreach (var path in registryPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                if (key != null)
                {
                    foreach (var subKeyName in key.GetSubKeyNames())
                    {
                        browsers.Add(subKeyName);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug("Erro ao ler registro {Path}: {Message}", path, ex.Message);
            }
        }

        // Tambem verifica Apps instalados
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        };

        var browserKeywords = new[] { "chrome", "firefox", "opera", "brave", "vivaldi", "browser" };

        foreach (var path in uninstallPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                if (key != null)
                {
                    foreach (var subKeyName in key.GetSubKeyNames())
                    {
                        using var subKey = key.OpenSubKey(subKeyName);
                        var displayName = subKey?.GetValue("DisplayName")?.ToString() ?? "";

                        if (browserKeywords.Any(k => displayName.ToLower().Contains(k)))
                        {
                            browsers.Add(displayName);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug("Erro ao ler registro {Path}: {Message}", path, ex.Message);
            }
        }

        return browsers;
    }

    /// <summary>
    /// Tenta desinstalar um navegador recem-instalado
    /// </summary>
    private void TryUninstallBrowser(string browserName)
    {
        _logger.LogInformation("Tentando remover navegador: {Browser}", browserName);

        // Busca comando de desinstalacao no registro
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        };

        foreach (var path in uninstallPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                if (key == null) continue;

                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    using var subKey = key.OpenSubKey(subKeyName);
                    var displayName = subKey?.GetValue("DisplayName")?.ToString() ?? "";

                    if (displayName.Equals(browserName, StringComparison.OrdinalIgnoreCase))
                    {
                        var uninstallString = subKey?.GetValue("UninstallString")?.ToString();
                        var quietUninstall = subKey?.GetValue("QuietUninstallString")?.ToString();

                        var cmd = quietUninstall ?? uninstallString;
                        if (!string.IsNullOrEmpty(cmd))
                        {
                            _logger.LogInformation("Executando desinstalacao: {Command}", cmd);

                            try
                            {
                                var psi = new ProcessStartInfo
                                {
                                    FileName = "cmd.exe",
                                    Arguments = $"/c {cmd}",
                                    UseShellExecute = false,
                                    CreateNoWindow = true
                                };

                                Process.Start(psi);
                                _logger.LogInformation("Comando de desinstalacao iniciado para {Browser}", browserName);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogError(ex, "Falha ao executar desinstalacao de {Browser}", browserName);
                            }

                            return;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug("Erro ao buscar desinstalador: {Message}", ex.Message);
            }
        }

        _logger.LogWarning("Nao foi possivel encontrar desinstalador para {Browser}", browserName);
    }
}
