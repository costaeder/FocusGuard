using System.Text.Json;

namespace FocusGuard.Shared.Models;

public class AnalysisCache
{
	private static readonly string CachePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FocusGuard", "analysis_cache.json");

	private static readonly object _lock = new object();

	private Dictionary<string, AnalyzedSite> _cache = new Dictionary<string, AnalyzedSite>();

	private DateTime _lastLoad = DateTime.MinValue;

	public int Count => _cache.Count;

	public void Load()
	{
		lock (_lock)
		{
			try
			{
				if (File.Exists(CachePath))
				{
					string json = File.ReadAllText(CachePath);
					List<AnalyzedSite> source = JsonSerializer.Deserialize<List<AnalyzedSite>>(json) ?? new List<AnalyzedSite>();
					_cache = source.ToDictionary((AnalyzedSite s) => s.Domain.ToLowerInvariant(), (AnalyzedSite s) => s);
				}
				_lastLoad = DateTime.UtcNow;
			}
			catch
			{
				_cache = new Dictionary<string, AnalyzedSite>();
			}
		}
	}

	public void Save()
	{
		lock (_lock)
		{
			try
			{
				string? directoryName = Path.GetDirectoryName(CachePath);
				if (!string.IsNullOrEmpty(directoryName) && !Directory.Exists(directoryName))
				{
					Directory.CreateDirectory(directoryName);
				}
				List<AnalyzedSite> value = _cache.Values.ToList();
				string contents = JsonSerializer.Serialize(value, new JsonSerializerOptions
				{
					WriteIndented = true
				});
				File.WriteAllText(CachePath, contents);
			}
			catch
			{
			}
		}
	}

	public AnalyzedSite? Get(string domain)
	{
		lock (_lock)
		{
			string key = domain.ToLowerInvariant();
			if (_cache.TryGetValue(key, out AnalyzedSite? value) && (DateTime.UtcNow - value.AnalyzedAt).TotalDays < 7.0)
			{
				return value;
			}
			return null;
		}
	}

	public void Set(AnalyzedSite site)
	{
		lock (_lock)
		{
			string key = site.Domain.ToLowerInvariant();
			_cache[key] = site;
		}
	}

	public bool Contains(string domain)
	{
		return Get(domain) != null;
	}

	public List<AnalyzedSite> GetBlockedSites()
	{
		lock (_lock)
		{
			return _cache.Values.Where((AnalyzedSite s) => s.IsBlocked).ToList();
		}
	}

	public List<AnalyzedSite> GetSitesPendingBlock(int threshold)
	{
		lock (_lock)
		{
			return _cache.Values.Where((AnalyzedSite s) => !s.IsBlocked && !s.AnalysisFailed && s.Score >= threshold).ToList();
		}
	}

	public void Cleanup()
	{
		lock (_lock)
		{
			DateTime cutoff = DateTime.UtcNow.AddDays(-30.0);
			List<string> list = (from kv in _cache
				where kv.Value.AnalyzedAt < cutoff
				select kv.Key).ToList();
			foreach (string item in list)
			{
				_cache.Remove(item);
			}
		}
	}
}
