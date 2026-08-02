using System.Diagnostics;

namespace FocusGuard.Shared.Services;

public static class HostsService
{
	private static readonly string HostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");

	private const string BlockMarkerStart = "# === FOCUSGUARD START ===";

	private const string BlockMarkerEnd = "# === FOCUSGUARD END ===";

	private const string BlockIPv4 = "127.0.0.1";

	private const string BlockIPv6 = "::1";

	private static readonly HashSet<string> KnownBlockIPs = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "127.0.0.1", "::1" };

	private static readonly string[] CommonSubdomains = new string[33]
	{
		"www", "m", "mobile", "app", "pt", "br", "en", "es", "fr", "de",
		"it", "ru", "jp", "cn", "ww1", "ww2", "ww3", "ww4", "ww5", "www1",
		"www2", "www3", "cdn", "static", "media", "img", "images", "video", "videos", "api",
		"stream", "live", "embed"
	};

	private static readonly string[] CommonTlds = new string[71]
	{
		"com", "net", "org", "lat", "xxx", "adult", "porn", "sex", "info", "biz",
		"co", "io", "me", "tv", "cc", "ws", "to", "ru", "cn", "de",
		"fr", "es", "it", "jp", "pt", "br", "com.br", "com.pt", "mx", "ar",
		"cl", "co.uk", "nl", "se", "be", "at", "ch", "pl", "cz", "hu",
		"ro", "xyz", "site", "online", "live", "cam", "club", "top", "icu", "fun",
		"pro", "app", "mobi", "stream", "tube", "link", "click", "world", "space", "uno",
		"today", "gg", "pk", "in", "cx", "sx", "red", "pink", "lol", "wtf",
		"moe"
	};

	private static List<string> ExpandWithSubdomains(IEnumerable<string> sites)
	{
		HashSet<string> hashSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		foreach (string site in sites)
		{
			string text = site.Trim().ToLowerInvariant();
			if (!string.IsNullOrEmpty(text))
			{
				hashSet.Add(text);
				hashSet.Add("www." + text);
			}
		}
		return hashSet.ToList();
	}

	private static string GetDomainNameWithoutTld(string domain)
	{
		if (string.IsNullOrEmpty(domain))
		{
			return domain;
		}
		string[] array = domain.Split('.');
		if (array.Length < 2)
		{
			return domain;
		}
		if (array.Length >= 3 && (array[^2] == "com" || array[^2] == "co" || array[^2] == "org" || array[^2] == "gov" || array[^2] == "edu"))
		{
			return array[^3];
		}
		return array[0];
	}

	private static string GetBaseDomainForExpansion(string domain)
	{
		string[] commonSubdomains = CommonSubdomains;
		foreach (string text in commonSubdomains)
		{
			if (domain.StartsWith(text + "."))
			{
				return domain.Substring(text.Length + 1);
			}
		}
		return domain;
	}

	private static void WriteBlockEntries(List<string> lines, IEnumerable<string> sites)
	{
		lines.Add(string.Empty);
		lines.Add("# === FOCUSGUARD START ===");
		foreach (string item in sites.OrderBy((string s) => s))
		{
			lines.Add("127.0.0.1 " + item);
			lines.Add("::1 " + item);
		}
		lines.Add("# === FOCUSGUARD END ===");
	}

	private static bool UnlockHostsFile(Action<string>? log = null)
	{
		try
		{
			RunCommand("takeown", "/F \"" + HostsPath + "\"", log);
			RunCommand("attrib", "-R \"" + HostsPath + "\"", log);
			RunCommand("icacls", "\"" + HostsPath + "\" /remove:d *S-1-5-32-545", log);
			RunCommand("icacls", "\"" + HostsPath + "\" /remove:d *S-1-1-0", log);
			RunCommand("icacls", "\"" + HostsPath + "\" /grant *S-1-5-32-544:F", log);
			string userName = Environment.UserName;
			RunCommand("icacls", $"\"{HostsPath}\" /grant \"{userName}\":F", log);
			log?.Invoke("Arquivo hosts desbloqueado");
			return true;
		}
		catch (Exception ex)
		{
			log?.Invoke("Erro ao desbloquear hosts: " + ex.Message);
			return false;
		}
	}

	private static bool LockHostsFile(Action<string>? log = null)
	{
		try
		{
			RunCommand("icacls", "\"" + HostsPath + "\" /reset", log);
			RunCommand("icacls", "\"" + HostsPath + "\" /grant:r *S-1-5-32-545:(R)", log);
			RunCommand("icacls", "\"" + HostsPath + "\" /grant:r *S-1-1-0:(R)", log);
			RunCommand("attrib", "+R \"" + HostsPath + "\"", log);
			log?.Invoke("Arquivo hosts bloqueado");
			return true;
		}
		catch (Exception ex)
		{
			log?.Invoke("Erro ao bloquear hosts: " + ex.Message);
			return false;
		}
	}

	private static void FlushDnsCache(Action<string>? log = null)
	{
		try
		{
			RunCommand("ipconfig", "/flushdns", log);
			RunCommand("net", "stop dnscache", log);
			RunCommand("net", "start dnscache", log);
			log?.Invoke("Cache DNS limpo com sucesso");
		}
		catch (Exception ex)
		{
			log?.Invoke("Aviso: Erro ao limpar cache DNS: " + ex.Message);
		}
	}

	private static bool RunCommand(string fileName, string arguments, Action<string>? log = null)
	{
		try
		{
			Process process = new Process
			{
				StartInfo = new ProcessStartInfo
				{
					FileName = fileName,
					Arguments = arguments,
					UseShellExecute = false,
					CreateNoWindow = true,
					RedirectStandardOutput = true,
					RedirectStandardError = true
				}
			};
			process.Start();
			string text = process.StandardOutput.ReadToEnd();
			string text2 = process.StandardError.ReadToEnd();
			process.WaitForExit(10000);
			if (process.ExitCode != 0)
			{
				log?.Invoke("CMD falhou: " + fileName + " " + arguments);
				if (!string.IsNullOrWhiteSpace(text2))
				{
					log?.Invoke("  Erro: " + text2.Trim());
				}
			}
			return process.ExitCode == 0;
		}
		catch (Exception ex)
		{
			log?.Invoke("Exceção em " + fileName + ": " + ex.Message);
			return false;
		}
	}

	private static bool ExecuteWithUnlock(Action action, Action<string>? log = null)
	{
		try
		{
			if (!UnlockHostsFile(log))
			{
				return false;
			}
			action();
			LockHostsFile(log);
			return true;
		}
		catch (Exception ex)
		{
			log?.Invoke("Erro: " + ex.Message);
			LockHostsFile(log);
			return false;
		}
	}

	public static List<string> GetBlockedSites()
	{
		HashSet<string> hashSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		try
		{
			if (!File.Exists(HostsPath))
			{
				return hashSet.ToList();
			}
			string[] array = File.ReadAllLines(HostsPath);
			bool flag = false;
			string[] array2 = array;
			foreach (string text in array2)
			{
				if (text.Trim() == "# === FOCUSGUARD START ===")
				{
					flag = true;
				}
				else if (text.Trim() == "# === FOCUSGUARD END ===")
				{
					flag = false;
				}
				else if (flag && !string.IsNullOrWhiteSpace(text) && !text.TrimStart().StartsWith('#'))
				{
					string[] array3 = text.Split(new char[2] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
					if (array3.Length >= 2 && KnownBlockIPs.Contains(array3[0]))
					{
						hashSet.Add(array3[1]);
					}
				}
			}
		}
		catch
		{
		}
		return hashSet.ToList();
	}

	public static bool AddBlockedSites(IEnumerable<string> sites, bool dryRun = false, Action<string>? log = null)
	{
		Action<string>? log2 = log;
		try
		{
			List<string> source = ExpandWithSubdomains(sites);
			List<string> existingSites = GetBlockedSites();
			List<string> newSites = source.Where((string s) => !existingSites.Contains(s, StringComparer.OrdinalIgnoreCase)).ToList();
			if (newSites.Count == 0)
			{
				return true;
			}
			if (dryRun)
			{
				log2?.Invoke($"[DRY-RUN] Adicionaria {newSites.Count} sites ao hosts:");
				foreach (string item in newSites.Take(5))
				{
					log2?.Invoke("[DRY-RUN]   - " + item);
				}
				if (newSites.Count > 5)
				{
					log2?.Invoke($"[DRY-RUN]   ... e mais {newSites.Count - 5} sites");
				}
				return true;
			}
			return ExecuteWithUnlock(delegate
			{
				List<string> list = (File.Exists(HostsPath) ? File.ReadAllLines(HostsPath).ToList() : new List<string>());
				int num = list.FindIndex((string l) => l.Trim() == "# === FOCUSGUARD START ===");
				int num2 = list.FindIndex((string l) => l.Trim() == "# === FOCUSGUARD END ===");
				if (num >= 0 && num2 >= 0 && num2 > num)
				{
					list.RemoveRange(num, num2 - num + 1);
				}
				List<string> sites2 = existingSites.Concat(newSites).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
				WriteBlockEntries(list, sites2);
				File.WriteAllLines(HostsPath, list);
				FlushDnsCache(log2);
				log2?.Invoke($"Adicionado(s) {newSites.Count} site(s) ao hosts");
			}, log2);
		}
		catch (Exception ex)
		{
			log2?.Invoke("Erro ao adicionar sites: " + ex.Message);
			return false;
		}
	}

	public static bool RemoveBlockedSite(string site, bool dryRun = false, Action<string>? log = null)
	{
		string site2 = site;
		Action<string>? log2 = log;
		try
		{
			if (dryRun)
			{
				log2?.Invoke("[DRY-RUN] Removeria site do hosts: " + site2);
				return true;
			}
			List<string> sites = GetBlockedSites();
			sites.RemoveAll((string s) => s.Equals(site2, StringComparison.OrdinalIgnoreCase));
			return ExecuteWithUnlock(delegate
			{
				List<string> list = File.ReadAllLines(HostsPath).ToList();
				int num = list.FindIndex((string l) => l.Trim() == "# === FOCUSGUARD START ===");
				int num2 = list.FindIndex((string l) => l.Trim() == "# === FOCUSGUARD END ===");
				if (num >= 0 && num2 >= 0 && num2 > num)
				{
					list.RemoveRange(num, num2 - num + 1);
				}
				if (sites.Count > 0)
				{
					WriteBlockEntries(list, sites);
				}
				File.WriteAllLines(HostsPath, list);
				FlushDnsCache(log2);
				log2?.Invoke("Site removido do hosts: " + site2);
			}, log2);
		}
		catch (Exception ex)
		{
			log2?.Invoke("Erro ao remover site: " + ex.Message);
			return false;
		}
	}

	public static bool SyncWithConfig(List<string> configSites, bool dryRun = false, Action<string>? log = null)
	{
		Action<string>? log2 = log;
		List<string> configSites2 = configSites;
		try
		{
			List<string> expandedSites = ExpandWithSubdomains(configSites2);
			if (dryRun)
			{
				List<string> blockedSites = GetBlockedSites();
				List<string> list = expandedSites.Except(blockedSites, StringComparer.OrdinalIgnoreCase).ToList();
				List<string> list2 = blockedSites.Except(expandedSites, StringComparer.OrdinalIgnoreCase).ToList();
				log2?.Invoke("[DRY-RUN] Sincronizaria hosts com config:");
				log2?.Invoke($"[DRY-RUN]   Sites na config: {configSites2.Count} ({expandedSites.Count} com subdomínios)");
				log2?.Invoke($"[DRY-RUN]   Sites no hosts: {blockedSites.Count}");
				if (list.Count > 0)
				{
					log2?.Invoke($"[DRY-RUN]   A adicionar: {list.Count}");
				}
				if (list2.Count > 0)
				{
					log2?.Invoke($"[DRY-RUN]   A remover: {list2.Count}");
				}
				return true;
			}
			return ExecuteWithUnlock(delegate
			{
				List<string> list3 = (File.Exists(HostsPath) ? File.ReadAllLines(HostsPath).ToList() : new List<string>());
				int num = list3.FindIndex((string l) => l.Trim() == "# === FOCUSGUARD START ===");
				int num2 = list3.FindIndex((string l) => l.Trim() == "# === FOCUSGUARD END ===");
				if (num >= 0 && num2 >= 0 && num2 > num)
				{
					list3.RemoveRange(num, num2 - num + 1);
				}
				if (expandedSites.Count > 0)
				{
					WriteBlockEntries(list3, expandedSites);
				}
				File.WriteAllLines(HostsPath, list3);
				FlushDnsCache(log2);
				log2?.Invoke($"Hosts sincronizado: {configSites2.Count} sites base ({expandedSites.Count} com subdomínios)");
			}, log2);
		}
		catch (Exception ex)
		{
			log2?.Invoke("Erro ao sincronizar: " + ex.Message);
			return false;
		}
	}
}
