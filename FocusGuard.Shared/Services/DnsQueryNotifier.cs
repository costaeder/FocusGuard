using System.Collections.Concurrent;

namespace FocusGuard.Shared.Services;

public class DnsQueryNotifier
{
	private readonly ConcurrentQueue<string> _queue = new ConcurrentQueue<string>();

	private int _count;

	private const int MaxQueueSize = 5000;

	public void Enqueue(string domain)
	{
		if (Interlocked.Increment(ref _count) > 5000)
		{
			_queue.TryDequeue(out string? _);
			Interlocked.Decrement(ref _count);
		}
		_queue.Enqueue(domain.ToLowerInvariant());
	}

	public HashSet<string> DrainAll()
	{
		HashSet<string> hashSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		string? result;
		while (_queue.TryDequeue(out result))
		{
			Interlocked.Decrement(ref _count);
			hashSet.Add(result);
		}
		return hashSet;
	}
}
