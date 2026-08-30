using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace FocusGuard.Shared.Models;

public class AppConfig
{
	private static readonly string ConfigPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FocusGuard", "config.json");

	private const string RegistryPath = "SOFTWARE\\FocusGuard";

	private const string PasswordValueName = "PasswordHash";

	private const string AiApiKeyValueName = "AiApiKey";

	[JsonIgnore]
	public string PasswordHash { get; set; } = string.Empty;

	public int SelectedDnsIndex { get; set; } = 0;

	public List<string> BlockedSites { get; set; } = new List<string>();

	public DateTime LastUpdated { get; set; } = DateTime.UtcNow;

	public bool DryRun { get; set; } = false;

	public bool BlockBrowserInstalls { get; set; } = true;

	public bool ContentAnalysisEnabled { get; set; } = true;

	public int ContentAnalysisThreshold { get; set; } = 15;

	public List<string> WhitelistedSites { get; set; } = new List<string>();

	// Categoria "cota diaria": sites liberados por tempo limitado por dia.
	// Ao atingir DailyLimitMinutes de minutos ativos no dia, o site e bloqueado
	// ate a meia-noite (reseta sozinho). Contador e por site.
	public List<string> LimitedSites { get; set; } = new List<string>();

	public int DailyLimitMinutes { get; set; } = 10;

	public bool UseAiAnalysis { get; set; } = false;

	public string AiModel { get; set; } = "gpt-5.4-nano";

	// Endpoint da API de analise (compativel com OpenAI /chat/completions).
	// Padrao: airouter proprio. Pode ser trocado sem recompilar.
	public string AiEndpoint { get; set; } = "https://airouter.escaladaonline.com.br/v1/chat/completions";

	[JsonIgnore]
	public string AiApiKey { get; set; } = string.Empty;

	public static AppConfig Load()
	{
		AppConfig appConfig = new AppConfig();
		try
		{
			if (File.Exists(ConfigPath))
			{
				string json = File.ReadAllText(ConfigPath);
				appConfig = JsonSerializer.Deserialize<AppConfig>(json) ?? new AppConfig();
			}
		}
		catch
		{
		}
		appConfig.PasswordHash = LoadRegistryValue("PasswordHash");
		appConfig.AiApiKey = LoadRegistryValue("AiApiKey");
		return appConfig;
	}

	public void Save()
	{
		string? directoryName = Path.GetDirectoryName(ConfigPath);
		if (!string.IsNullOrEmpty(directoryName) && !Directory.Exists(directoryName))
		{
			Directory.CreateDirectory(directoryName);
		}
		LastUpdated = DateTime.UtcNow;
		string contents = JsonSerializer.Serialize(this, new JsonSerializerOptions
		{
			WriteIndented = true
		});
		File.WriteAllText(ConfigPath, contents);
	}

	public static string HashPassword(string password)
	{
		byte[] inArray = SHA256.HashData(Encoding.UTF8.GetBytes(password + "FocusGuardSalt2024"));
		return Convert.ToBase64String(inArray);
	}

	public bool ValidatePassword(string password)
	{
		if (string.IsNullOrEmpty(PasswordHash))
		{
			return true;
		}
		return HashPassword(password) == PasswordHash;
	}

	public void SetPassword(string password)
	{
		PasswordHash = HashPassword(password);
		SaveRegistryValue("PasswordHash", PasswordHash);
	}

	public void SetAiApiKey(string apiKey)
	{
		AiApiKey = apiKey;
		SaveRegistryValue("AiApiKey", apiKey);
	}

	public DnsProvider GetSelectedDns()
	{
		if (SelectedDnsIndex >= 0 && SelectedDnsIndex < DnsProvider.AllowedProviders.Length)
		{
			return DnsProvider.AllowedProviders[SelectedDnsIndex];
		}
		return DnsProvider.AllowedProviders[0];
	}

	private static string LoadRegistryValue(string valueName)
	{
		try
		{
			using RegistryKey? registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\FocusGuard");
			return (registryKey?.GetValue(valueName))?.ToString() ?? string.Empty;
		}
		catch
		{
			return string.Empty;
		}
	}

	private static void SaveRegistryValue(string valueName, string data)
	{
		try
		{
			using RegistryKey? registryKey = Registry.LocalMachine.CreateSubKey("SOFTWARE\\FocusGuard");
			registryKey?.SetValue(valueName, data, RegistryValueKind.String);
		}
		catch
		{
		}
	}

	public bool HasPassword()
	{
		return !string.IsNullOrEmpty(PasswordHash);
	}
}
