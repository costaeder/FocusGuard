using System.Collections.Concurrent;
using FocusGuard.Shared.Models;

namespace FocusGuard.Shared.Services;

public class BlockedDomainStore
{
	private readonly ConcurrentDictionary<string, byte> _blocked = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);

	public int Count => _blocked.Count;

	public bool IsBlocked(string domain)
	{
		if (string.IsNullOrEmpty(domain))
		{
			return false;
		}
		domain = domain.TrimEnd('.').ToLowerInvariant();
		string text = domain;
		while (!string.IsNullOrEmpty(text))
		{
			if (_blocked.ContainsKey(text))
			{
				return true;
			}
			int num = text.IndexOf('.');
			if (num < 0)
			{
				break;
			}
			text = text.Substring(num + 1);
		}
		return false;
	}

	public void Add(string domain)
	{
		domain = domain.TrimEnd('.').ToLowerInvariant();
		_blocked.TryAdd(domain, 0);
	}

	public void Remove(string domain)
	{
		domain = domain.TrimEnd('.').ToLowerInvariant();
		_blocked.TryRemove(domain, out var _);
	}

	public HashSet<string> GetAll()
	{
		return new HashSet<string>(_blocked.Keys, StringComparer.OrdinalIgnoreCase);
	}

	public void Reload(Func<string, bool>? isWhitelisted = null)
	{
		AppConfig appConfig = AppConfig.Load();
		HashSet<string> hashSet = new HashSet<string>(appConfig.BlockedSites.Select((string s) => s.TrimEnd('.').ToLowerInvariant()), StringComparer.OrdinalIgnoreCase);
		foreach (string item in _blocked.Keys.ToList())
		{
			if (!hashSet.Contains(item))
			{
				_blocked.TryRemove(item, out var _);
			}
		}
		foreach (string item2 in hashSet)
		{
			if (isWhitelisted == null || !isWhitelisted(item2))
			{
				_blocked.TryAdd(item2, 0);
			}
		}
	}
}
