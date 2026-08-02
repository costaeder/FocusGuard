using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using FocusGuard.Shared.Models;
using FocusGuard.Shared.Services;

namespace FocusGuard.Service;

public class DnsMonitorWorker : BackgroundService
{
    private readonly ILogger<DnsMonitorWorker> _logger;
    private readonly TimeSpan _checkInterval = TimeSpan.FromSeconds(30);
    private bool _policyApplied = false;
    private DateTime _lastDnsCorrection = DateTime.MinValue;
    private static readonly TimeSpan DnsCorrectionCooldown = TimeSpan.FromSeconds(30);

    public DnsMonitorWorker(ILogger<DnsMonitorWorker> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var config = AppConfig.Load();
        _logger.LogInformation("FocusGuard DNS Monitor iniciado (DryRun: {DryRun})", config.DryRun);

        // Aplica politica de GPO para bloquear alteracao de DNS
        if (!config.DryRun)
        {
            ApplyDnsPolicy();
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                CheckAndEnforceDns();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao verificar DNS");
            }

            await Task.Delay(_checkInterval, stoppingToken);
        }
    }

    private void CheckAndEnforceDns()
    {
        var config = AppConfig.Load();
        var selectedDns = config.GetSelectedDns();
        var adapters = DnsService.GetActiveNetworkAdapters();

        foreach (var adapter in adapters)
        {
            var (primary, secondary) = DnsService.GetCurrentDns(adapter);

            _logger.LogDebug("Adaptador {Adapter}: DNS atual = {Primary}/{Secondary}", adapter, primary, secondary);

            // DNS deve apontar para o proxy (127.0.0.2), não direto pro provider
            if (primary != DnsService.ProxyDnsAddress)
            {
                // Cooldown para evitar rodar netsh repetidamente (causa flapping de DNS / queda de internet)
                if (DateTime.UtcNow - _lastDnsCorrection < DnsCorrectionCooldown)
                {
                    _logger.LogDebug("DNS incorreto no adaptador {Adapter}, mas cooldown ativo. Aguardando...", adapter);
                    continue;
                }

                _logger.LogWarning(
                    "DNS incorreto no adaptador {Adapter}: {Primary}/{Secondary}. {Action}",
                    adapter, primary, secondary,
                    config.DryRun ? "[DRY-RUN] Corrigiria..." : "Apontando para proxy..."
                );

                var success = DnsService.SetDnsForProxy(adapter, selectedDns, config.DryRun, msg => _logger.LogInformation(msg));
                _lastDnsCorrection = DateTime.UtcNow;

                if (success)
                {
                    _logger.LogInformation(
                        "{Prefix}DNS {Action} no adaptador {Adapter} para {DnsName}",
                        config.DryRun ? "[DRY-RUN] " : "",
                        config.DryRun ? "seria corrigido" : "corrigido",
                        adapter, selectedDns.Name
                    );
                }
                else
                {
                    _logger.LogError("Falha ao corrigir DNS no adaptador {Adapter}", adapter);
                }
            }
        }
    }

    /// <summary>
    /// Aplica politicas de registro (GPO) para impedir alteracao de DNS pelo usuario
    /// </summary>
    private void ApplyDnsPolicy()
    {
        if (_policyApplied) return;

        try
        {
            // Politica 1: Desabilita acesso as propriedades de conexao de rede
            using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows\Network Connections"))
            {
                if (key != null)
                {
                    // Proibe acesso as propriedades da conexao LAN
                    key.SetValue("NC_LanChangeProperties", 0, RegistryValueKind.DWord);
                    // Habilita proibicoes de administrador
                    key.SetValue("NC_EnableAdminProhibits", 1, RegistryValueKind.DWord);
                    // Proibe acesso as propriedades de conexoes de acesso remoto
                    key.SetValue("NC_RasChangeProperties", 0, RegistryValueKind.DWord);
                    // Proibe configuracoes avancadas
                    key.SetValue("NC_AdvancedSettings", 0, RegistryValueKind.DWord);
                    // Proibe adicionar/remover componentes
                    key.SetValue("NC_LanConnect", 0, RegistryValueKind.DWord);
                    _logger.LogInformation("Politica de rede aplicada: propriedades de conexao desabilitadas");
                }
            }

            // Politica 2: Bloqueia acesso ao painel de rede (ncpa.cpl)
            using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"))
            {
                if (key != null)
                {
                    key.SetValue("DisallowCpl", 1, RegistryValueKind.DWord);
                }
            }

            using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl"))
            {
                if (key != null)
                {
                    key.SetValue("1", "ncpa.cpl", RegistryValueKind.String);
                    _logger.LogInformation("Politica aplicada: ncpa.cpl bloqueado");
                }
            }

            // Politica 3: Impede alteracao de DNS via Configuracoes do Windows
            using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows\NetworkProvider"))
            {
                if (key != null)
                {
                    key.SetValue("DisableNetworkSettings", 1, RegistryValueKind.DWord);
                }
            }

            // Politica 4: Bloqueia pagina de configuracoes de rede no Windows Settings
            // Windows 11 usa paginas adicionais como network-wifisettings, network-advancedsettings
            var networkPagesToHide = "hide:network;network-ethernet;network-wifi;network-wifisettings;network-advancedsettings;" +
                "network-status;network-proxy;network-dialup;network-vpn;network-airplanemode;network-mobilehotspot;" +
                "network-directaccess;network-cellular;network-ethernet-settings;network-wifi-settings";

            using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"))
            {
                if (key != null)
                {
                    key.SetValue("SettingsPageVisibility", networkPagesToHide, RegistryValueKind.String);
                    _logger.LogInformation("Politica aplicada: paginas de rede escondidas no Settings");
                }
            }

            // Politica 4b: Bloqueia acesso ao Settings de rede via URI
            using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows\SettingsPageVisibility"))
            {
                if (key != null)
                {
                    key.SetValue("SettingsPageVisibility", networkPagesToHide,
                        RegistryValueKind.String);
                }
            }

            // Politica 5: Desabilita alteracao de DNS no Windows 10/11 Settings
            using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"))
            {
                if (key != null)
                {
                    // Impede alteracao de configuracoes de proxy/rede
                    key.SetValue("ProxySettingsPerUser", 0, RegistryValueKind.DWord);
                }
            }

            // Politica 6: Bloqueia alteracao de TCP/IP via registro
            // Isso impede que o usuario altere DNS mesmo que acesse as configuracoes
            try
            {
                // Define DNS estatico no registro do Windows (backup)
                var selectedDns = AppConfig.Load().GetSelectedDns();
                using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"))
                {
                    if (key != null)
                    {
                        // Lista de servidores DNS permitidos (forcado por politica)
                        key.SetValue("NameServer", $"{DnsService.ProxyDnsAddress},{selectedDns.PrimaryDns}", RegistryValueKind.String);
                        _logger.LogInformation("Politica DNS Client: servidores forcados via GPO");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Nao foi possivel definir DNS via politica");
            }

            // Politica 7: Bloqueia ms-settings URIs de rede
            try
            {
                // Bloqueia execucao de URIs ms-settings de rede
                var blockedUris = new[] { "ms-settings:network", "ms-settings:network-ethernet", "ms-settings:network-wifi", "ms-settings:network-status" };
                using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows\Explorer"))
                {
                    if (key != null)
                    {
                        key.SetValue("DisableSettingsURIHandlers", 1, RegistryValueKind.DWord);
                    }
                }
                _logger.LogInformation("Politica aplicada: URIs de settings bloqueados");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Nao foi possivel bloquear URIs de settings");
            }

            // Limpa NRPT legada (era Politica 8 - removia performance da rede)
            CleanupLegacyNrpt();

            // Politica 7: Desabilita DNS Client UI
            using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"))
            {
                if (key != null)
                {
                    // Desabilita DNS sobre HTTPS no Windows
                    key.SetValue("DoHPolicy", 0, RegistryValueKind.DWord);
                    // Limpa EnableMulticast legado (causava lentidao em rede local)
                    key.DeleteValue("EnableMulticast", false);
                    _logger.LogInformation("Politica DNS Client aplicada");
                }
            }

            // Limpa bloqueios legados de netsh (causavam o servico nao conseguir corrigir DNS)
            CleanupLegacyNetshBlock();

            // Aplica politicas de DoH nos navegadores
            ApplyBrowserDohPolicies();

            _policyApplied = true;
            _logger.LogInformation("Politicas de GPO para bloqueio de DNS aplicadas com sucesso");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao aplicar politicas de GPO");
        }
    }

    /// <summary>
    /// Remove bloqueios legados de netsh.exe (SRP e IFEO) que impediam o proprio servico
    /// de usar netsh para corrigir DNS. A protecao contra alteracao de DNS agora depende
    /// das GPO policies (UI bloqueada) + re-aplicacao automatica a cada 10 segundos.
    /// </summary>
    private void CleanupLegacyNetshBlock()
    {
        try
        {
            // Remove IFEO (Image File Execution Options) para netsh.exe
            try
            {
                using var ifeoKey = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\netsh.exe", true);
                if (ifeoKey != null)
                {
                    ifeoKey.DeleteValue("Debugger", false);
                    if (ifeoKey.ValueCount == 0 && ifeoKey.SubKeyCount == 0)
                    {
                        Registry.LocalMachine.DeleteSubKey(
                            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\netsh.exe", false);
                    }
                    _logger.LogInformation("IFEO legado de netsh.exe removido");
                }
            }
            catch { /* Ignora se nao existir */ }

            // Remove SRP (Software Restriction Policies) para netsh.exe
            try
            {
                using var srpKey = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths", true);
                if (srpKey != null)
                {
                    foreach (var subKeyName in srpKey.GetSubKeyNames())
                    {
                        using var pathKey = srpKey.OpenSubKey(subKeyName);
                        var itemData = pathKey?.GetValue("ItemData")?.ToString() ?? "";
                        var description = pathKey?.GetValue("Description")?.ToString() ?? "";
                        if (itemData.Contains("netsh.exe", StringComparison.OrdinalIgnoreCase) &&
                            description.Contains("FocusGuard", StringComparison.OrdinalIgnoreCase))
                        {
                            srpKey.DeleteSubKeyTree(subKeyName, false);
                            _logger.LogInformation("SRP legado de netsh.exe removido: {Key}", subKeyName);
                        }
                    }
                }
            }
            catch { /* Ignora se nao existir */ }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Erro ao limpar bloqueios legados de netsh");
        }
    }

    /// <summary>
    /// Aplica politicas para desabilitar DNS over HTTPS (DoH) nos navegadores
    /// </summary>
    private void ApplyBrowserDohPolicies()
    {
        try
        {
            // === GOOGLE CHROME ===
            using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Google\Chrome"))
            {
                if (key != null)
                {
                    // DoH
                    key.SetValue("DnsOverHttpsMode", "off", RegistryValueKind.String);
                    key.SetValue("BuiltInDnsClientEnabled", 0, RegistryValueKind.DWord);
                    // Forca Chrome a usar DNS do sistema (hosts file)
                    key.SetValue("AsyncDnsEnabled", 0, RegistryValueKind.DWord);
                    key.SetValue("DnsInterceptionChecksEnabled", 0, RegistryValueKind.DWord);
                    // Modo anonimo
                    key.SetValue("IncognitoModeAvailability", 1, RegistryValueKind.DWord); // 1 = desabilitado
                    // Modo convidado
                    key.SetValue("BrowserGuestModeEnabled", 0, RegistryValueKind.DWord);
                    // Impede apagar historico
                    key.SetValue("AllowDeletingBrowserHistory", 0, RegistryValueKind.DWord);
                    key.SetValue("ClearBrowsingDataOnExit", 0, RegistryValueKind.DWord);
                    _logger.LogInformation("Chrome: DoH, DNS async, modo anonimo e limpeza de historico desabilitados via GPO");
                }
            }

            // Chrome: Bloqueia extensoes de VPN/proxy
            ApplyChromeExtensionBlocklist();

            // === MICROSOFT EDGE ===
            using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Edge"))
            {
                if (key != null)
                {
                    // DoH
                    key.SetValue("DnsOverHttpsMode", "off", RegistryValueKind.String);
                    key.SetValue("BuiltInDnsClientEnabled", 0, RegistryValueKind.DWord);
                    // Forca Edge a usar DNS do sistema (hosts file)
                    key.SetValue("AsyncDnsEnabled", 0, RegistryValueKind.DWord);
                    key.SetValue("DnsInterceptionChecksEnabled", 0, RegistryValueKind.DWord);
                    // Modo InPrivate
                    key.SetValue("InPrivateModeAvailability", 1, RegistryValueKind.DWord); // 1 = desabilitado
                    // Modo convidado
                    key.SetValue("BrowserGuestModeEnabled", 0, RegistryValueKind.DWord);
                    // Impede apagar historico
                    key.SetValue("AllowDeletingBrowserHistory", 0, RegistryValueKind.DWord);
                    key.SetValue("ClearBrowsingDataOnExit", 0, RegistryValueKind.DWord);
                    _logger.LogInformation("Edge: DoH, DNS async, modo InPrivate e limpeza de historico desabilitados via GPO");
                }
            }

            // Edge: Bloqueia extensoes de VPN/proxy
            ApplyEdgeExtensionBlocklist();

            // === MOZILLA FIREFOX ===
            using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Mozilla\Firefox"))
            {
                if (key != null)
                {
                    key.SetValue("DNSOverHTTPS", 0, RegistryValueKind.DWord);
                    // Desabilita navegacao privada
                    key.SetValue("DisablePrivateBrowsing", 1, RegistryValueKind.DWord);
                    // Desabilita botao "Esquecer"
                    key.SetValue("DisableForgetButton", 1, RegistryValueKind.DWord);
                    _logger.LogInformation("Firefox: DoH, modo privado e botao Esquecer desabilitados via GPO");
                }
            }

            // Firefox: Impede limpar historico ao sair
            using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown"))
            {
                if (key != null)
                {
                    key.SetValue("Cache", 0, RegistryValueKind.DWord);
                    key.SetValue("Cookies", 0, RegistryValueKind.DWord);
                    key.SetValue("Downloads", 0, RegistryValueKind.DWord);
                    key.SetValue("FormData", 0, RegistryValueKind.DWord);
                    key.SetValue("History", 0, RegistryValueKind.DWord);
                    key.SetValue("Sessions", 0, RegistryValueKind.DWord);
                    key.SetValue("SiteSettings", 0, RegistryValueKind.DWord);
                    key.SetValue("OfflineApps", 0, RegistryValueKind.DWord);
                    key.SetValue("Locked", 1, RegistryValueKind.DWord);
                }
            }

            using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS"))
            {
                if (key != null)
                {
                    key.SetValue("Enabled", 0, RegistryValueKind.DWord);
                    key.SetValue("Locked", 1, RegistryValueKind.DWord);
                }
            }

            // Firefox: Bloqueia extensoes de VPN/proxy
            ApplyFirefoxExtensionBlocklist();

            // === BRAVE ===
            using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\BraveSoftware\Brave"))
            {
                if (key != null)
                {
                    key.SetValue("DnsOverHttpsMode", "off", RegistryValueKind.String);
                    key.SetValue("BuiltInDnsClientEnabled", 0, RegistryValueKind.DWord);
                    // Forca Brave a usar DNS do sistema (hosts file)
                    key.SetValue("AsyncDnsEnabled", 0, RegistryValueKind.DWord);
                    key.SetValue("DnsInterceptionChecksEnabled", 0, RegistryValueKind.DWord);
                    key.SetValue("IncognitoModeAvailability", 1, RegistryValueKind.DWord);
                    key.SetValue("BrowserGuestModeEnabled", 0, RegistryValueKind.DWord);
                    // Brave: desabilita Tor
                    key.SetValue("TorDisabled", 1, RegistryValueKind.DWord);
                    // Impede apagar historico
                    key.SetValue("AllowDeletingBrowserHistory", 0, RegistryValueKind.DWord);
                    key.SetValue("ClearBrowsingDataOnExit", 0, RegistryValueKind.DWord);
                    _logger.LogInformation("Brave: DoH, DNS async, modo anonimo, Tor e limpeza de historico desabilitados via GPO");
                }
            }

            // === OPERA ===
            using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Opera Software\Opera"))
            {
                if (key != null)
                {
                    key.SetValue("DnsOverHttpsMode", "off", RegistryValueKind.String);
                    key.SetValue("BuiltInDnsClientEnabled", 0, RegistryValueKind.DWord);
                    // Forca Opera a usar DNS do sistema (hosts file)
                    key.SetValue("AsyncDnsEnabled", 0, RegistryValueKind.DWord);
                    key.SetValue("DnsInterceptionChecksEnabled", 0, RegistryValueKind.DWord);
                    key.SetValue("IncognitoModeAvailability", 1, RegistryValueKind.DWord);
                    // Opera: desabilita VPN integrada
                    key.SetValue("OperaVPNEnabled", 0, RegistryValueKind.DWord);
                    // Impede apagar historico
                    key.SetValue("AllowDeletingBrowserHistory", 0, RegistryValueKind.DWord);
                    key.SetValue("ClearBrowsingDataOnExit", 0, RegistryValueKind.DWord);
                    _logger.LogInformation("Opera: DoH, DNS async, modo anonimo, VPN e limpeza de historico desabilitados via GPO");
                }
            }

            // === VIVALDI ===
            using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Vivaldi"))
            {
                if (key != null)
                {
                    key.SetValue("DnsOverHttpsMode", "off", RegistryValueKind.String);
                    key.SetValue("BuiltInDnsClientEnabled", 0, RegistryValueKind.DWord);
                    // Forca Vivaldi a usar DNS do sistema (hosts file)
                    key.SetValue("AsyncDnsEnabled", 0, RegistryValueKind.DWord);
                    key.SetValue("DnsInterceptionChecksEnabled", 0, RegistryValueKind.DWord);
                    key.SetValue("IncognitoModeAvailability", 1, RegistryValueKind.DWord);
                    key.SetValue("BrowserGuestModeEnabled", 0, RegistryValueKind.DWord);
                    // Impede apagar historico
                    key.SetValue("AllowDeletingBrowserHistory", 0, RegistryValueKind.DWord);
                    key.SetValue("ClearBrowsingDataOnExit", 0, RegistryValueKind.DWord);
                    _logger.LogInformation("Vivaldi: DoH, DNS async, modo anonimo e limpeza de historico desabilitados via GPO");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao aplicar politicas de DoH nos navegadores");
        }
    }

    /// <summary>
    /// Bloqueia extensoes de VPN/proxy no Chrome
    /// </summary>
    private void ApplyChromeExtensionBlocklist()
    {
        try
        {
            // IDs de extensoes de VPN/proxy conhecidas para bloquear
            var blockedExtensions = new[]
            {
                // VPNs populares
                "bihmplhobchoageeokmgbdihknkjbknd", // Hola VPN
                "eppiocemhmnlbhjplcgkofciiegomcon", // ZenMate VPN
                "dpplabbmogkhghncfbfdeeokoefdjegm", // Hotspot Shield
                "jhkhlaabnbfpcfpeglkjadkimknjhpjh", // Browsec VPN
                "majdfhpaihoncoakbjgbdhglocklcgno", // Touch VPN
                "ffbkglfijbcbgblgflchnbphjdllaogb", // Windscribe
                "gkojfkhlekighikafcpjkiklfbnlmeio", // Surfshark
                "lnfdopdhdklkglfhbflnfllnkkfoimah", // NordVPN
                "kpiecbcckbofpmkkkdibbllpinceiihk", // Urban VPN
                "biokclnfpnbggpadgcnhgifhkhogkbgg", // SetupVPN
                // Proxies
                "padekgcemlokbadohgkifijomclgjgif", // Proxy SwitchyOmega
                "caehdcpeofiiigpdhbabniblemipncjj", // Hola Proxy
                "knmgclhpddfjcioncjhipdgkognioglc", // Anonymox
            };

            using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist"))
            {
                if (key != null)
                {
                    for (int i = 0; i < blockedExtensions.Length; i++)
                    {
                        key.SetValue((i + 1).ToString(), blockedExtensions[i], RegistryValueKind.String);
                    }
                    _logger.LogInformation("Chrome: {Count} extensoes de VPN/proxy bloqueadas", blockedExtensions.Length);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao bloquear extensoes do Chrome");
        }
    }

    /// <summary>
    /// Bloqueia extensoes de VPN/proxy no Edge
    /// </summary>
    private void ApplyEdgeExtensionBlocklist()
    {
        try
        {
            // Edge usa os mesmos IDs do Chrome para extensoes da Chrome Web Store
            var blockedExtensions = new[]
            {
                "bihmplhobchoageeokmgbdihknkjbknd", // Hola VPN
                "eppiocemhmnlbhjplcgkofciiegomcon", // ZenMate VPN
                "dpplabbmogkhghncfbfdeeokoefdjegm", // Hotspot Shield
                "jhkhlaabnbfpcfpeglkjadkimknjhpjh", // Browsec VPN
                "majdfhpaihoncoakbjgbdhglocklcgno", // Touch VPN
                "ffbkglfijbcbgblgflchnbphjdllaogb", // Windscribe
                "gkojfkhlekighikafcpjkiklfbnlmeio", // Surfshark
                "lnfdopdhdklkglfhbflnfllnkkfoimah", // NordVPN
                "kpiecbcckbofpmkkkdibbllpinceiihk", // Urban VPN
                "biokclnfpnbggpadgcnhgifhkhogkbgg", // SetupVPN
                "padekgcemlokbadohgkifijomclgjgif", // Proxy SwitchyOmega
                "caehdcpeofiiigpdhbabniblemipncjj", // Hola Proxy
                "knmgclhpddfjcioncjhipdgkognioglc", // Anonymox
            };

            using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist"))
            {
                if (key != null)
                {
                    for (int i = 0; i < blockedExtensions.Length; i++)
                    {
                        key.SetValue((i + 1).ToString(), blockedExtensions[i], RegistryValueKind.String);
                    }
                    _logger.LogInformation("Edge: {Count} extensoes de VPN/proxy bloqueadas", blockedExtensions.Length);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao bloquear extensoes do Edge");
        }
    }

    /// <summary>
    /// Bloqueia extensoes de VPN/proxy no Firefox
    /// </summary>
    private void ApplyFirefoxExtensionBlocklist()
    {
        try
        {
            // Firefox usa IDs diferentes (formato addon@domain ou GUID)
            var blockedExtensions = new[]
            {
                "gige@aspect.com", // Hola VPN
                "{73a6fe31-595d-460b-a920-fcc0f8843232}", // ZenMate
                "jid1-ZAdIEUB7XOzOJw@jetpack", // Browsec
                "touch-vpn@nicerapps.dev", // Touch VPN
                "@AnonTab", // AnonTab
                "foxyproxy@eric.h.jung", // FoxyProxy
                "{47bf28c5-7bc8-4ce6-b65c-2d2e80f969b3}", // Windscribe
                "vpn@proton.me", // Proton VPN
                "webextension@nicerapps.dev", // SetupVPN
            };

            using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Mozilla\Firefox\Extensions\Uninstall"))
            {
                if (key != null)
                {
                    for (int i = 0; i < blockedExtensions.Length; i++)
                    {
                        key.SetValue((i + 1).ToString(), blockedExtensions[i], RegistryValueKind.String);
                    }
                }
            }

            // Tambem bloqueia instalacao
            using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Mozilla\Firefox\ExtensionSettings"))
            {
                if (key != null)
                {
                    // Bloqueia todas as extensoes por padrao e permite apenas as da whitelist
                    key.SetValue("*", "{\"blocked_install_message\":\"Extensao bloqueada pelo FocusGuard\",\"installation_mode\":\"blocked\"}", RegistryValueKind.String);
                }
            }

            _logger.LogInformation("Firefox: extensoes de VPN/proxy bloqueadas");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao bloquear extensoes do Firefox");
        }
    }

    /// <summary>
    /// Remove as politicas aplicadas (chamado quando DryRun e ativado)
    /// </summary>
    public void RemoveDnsPolicy()
    {
        try
        {
            using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\Network Connections", true))
            {
                if (key != null)
                {
                    key.DeleteValue("NC_LanChangeProperties", false);
                    key.DeleteValue("NC_EnableAdminProhibits", false);
                }
            }

            Registry.LocalMachine.DeleteSubKeyTree(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl", false);

            using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", true))
            {
                if (key != null)
                {
                    key.DeleteValue("DisallowCpl", false);
                }
            }

            using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\NetworkProvider", true))
            {
                if (key != null)
                {
                    key.DeleteValue("DisableNetworkSettings", false);
                }
            }

            // Limpa NRPT e EnableMulticast legados
            CleanupLegacyNrpt();

            using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", true))
            {
                key?.DeleteValue("EnableMulticast", false);
            }

            _policyApplied = false;
            _logger.LogInformation("Politicas de GPO removidas");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao remover politicas de GPO");
        }
    }

    /// <summary>
    /// Remove a NRPT legada que forcava todo o DNS pelo CleanBrowsing.
    /// Essa politica era redundante com o DNS do adaptador e degradava a performance.
    /// </summary>
    private void CleanupLegacyNrpt()
    {
        try
        {
            Registry.LocalMachine.DeleteSubKeyTree(
                @"SOFTWARE\Policies\Microsoft\Windows NT\DnsClient\DnsPolicyConfig\FocusGuard", false);
            _logger.LogInformation("NRPT legada removida");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Nao foi possivel remover NRPT legada");
        }
    }
}
