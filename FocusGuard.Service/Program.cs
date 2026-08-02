using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;
using FocusGuard.Service;

const string ServiceName = "FocusGuard Service";
const string ServiceDescription = "Servico de protecao de foco e produtividade";

// Verifica argumentos de instalacao
if (args.Length > 0)
{
    var exePath = Process.GetCurrentProcess().MainModule?.FileName ?? "";

    if (args[0].Equals("--install", StringComparison.OrdinalIgnoreCase) ||
        args[0].Equals("/install", StringComparison.OrdinalIgnoreCase))
    {
        return InstallService(exePath);
    }

    if (args[0].Equals("--uninstall", StringComparison.OrdinalIgnoreCase) ||
        args[0].Equals("/uninstall", StringComparison.OrdinalIgnoreCase))
    {
        return UninstallService();
    }
}

// Execucao normal do servico
var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = ServiceName;
});

// Remove EventLog provider (causa crash por falta de System.Threading.AccessControl)
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

// Log em arquivo (ProgramData\FocusGuard\service.log)
var logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FocusGuard");
Directory.CreateDirectory(logDir);
var logFile = Path.Combine(logDir, "service.log");
builder.Logging.AddProvider(new FileLoggerProvider(logFile));

// Singletons compartilhados entre workers
builder.Services.AddSingleton<FocusGuard.Shared.Services.BlockedDomainStore>();
builder.Services.AddSingleton<FocusGuard.Shared.Services.DnsQueryNotifier>();

// DNS Proxy deve iniciar primeiro (os outros dependem dele)
builder.Services.AddHostedService<DnsProxyWorker>();
builder.Services.AddHostedService<DnsMonitorWorker>();
builder.Services.AddHostedService<HostsProtectionWorker>();
builder.Services.AddHostedService<ServiceProtectionWorker>();
builder.Services.AddHostedService<BrowserInstallBlockerWorker>();
builder.Services.AddHostedService<ContentAnalyzerWorker>();
builder.Services.AddHostedService<BlockPageWorker>();

var host = builder.Build();
host.Run();

return 0;

// Funcoes de instalacao
static int InstallService(string exePath)
{
    try
    {
        Console.WriteLine("Instalando FocusGuard Service...");

        // Cria o servico
        var createResult = RunSc($"create \"{ServiceName}\" binPath=\"{exePath}\" start=auto DisplayName=\"{ServiceName}\"");
        if (createResult != 0)
        {
            Console.WriteLine("Erro ao criar servico.");
            return createResult;
        }

        // Define descricao
        RunSc($"description \"{ServiceName}\" \"{ServiceDescription}\"");

        // Inicia o servico
        Console.WriteLine("Iniciando servico...");
        RunSc($"start \"{ServiceName}\"");

        Console.WriteLine("Servico instalado com sucesso!");
        return 0;
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Erro: {ex.Message}");
        return 1;
    }
}

static int UninstallService()
{
    try
    {
        Console.WriteLine("Desinstalando FocusGuard Service...");

        // Para o servico
        Console.WriteLine("Parando servico...");
        RunSc($"stop \"{ServiceName}\"");

        // Aguarda um pouco
        Thread.Sleep(2000);

        // Remove o servico
        Console.WriteLine("Removendo servico...");
        var deleteResult = RunSc($"delete \"{ServiceName}\"");

        if (deleteResult == 0)
        {
            Console.WriteLine("Servico removido com sucesso!");
        }

        return deleteResult;
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Erro: {ex.Message}");
        return 1;
    }
}

static int RunSc(string arguments)
{
    var process = new Process
    {
        StartInfo = new ProcessStartInfo
        {
            FileName = "sc.exe",
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        }
    };

    process.Start();
    process.WaitForExit();

    var output = process.StandardOutput.ReadToEnd();
    var error = process.StandardError.ReadToEnd();

    if (!string.IsNullOrEmpty(output))
        Console.WriteLine(output);
    if (!string.IsNullOrEmpty(error))
        Console.WriteLine(error);

    return process.ExitCode;
}

// Logger simples que escreve em arquivo
sealed class FileLoggerProvider(string filePath) : ILoggerProvider
{
    private readonly object _lock = new();

    public ILogger CreateLogger(string categoryName) => new FileLogger(filePath, categoryName, _lock);
    public void Dispose() { }
}

sealed class FileLogger(string filePath, string category, object lockObj) : ILogger
{
    // Extrai so o nome da classe (sem namespace)
    private readonly string _category = category.Contains('.') ? category[(category.LastIndexOf('.') + 1)..] : category;

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel)) return;

        var level = logLevel switch
        {
            LogLevel.Warning => "WARN",
            LogLevel.Error => "ERRO",
            LogLevel.Critical => "CRIT",
            _ => "INFO"
        };

        var line = $"[{DateTime.Now:HH:mm:ss}] [{level}] [{_category}] {formatter(state, exception)}";
        if (exception != null)
            line += $"\n  {exception.GetType().Name}: {exception.Message}";

        lock (lockObj)
        {
            try
            {
                File.AppendAllText(filePath, line + Environment.NewLine);
            }
            catch { }
        }
    }
}
