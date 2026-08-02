using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using FocusGuard.Shared.Models;

namespace FocusGuard.Shared.Services;

public static class DnsService
{
	private static readonly HashSet<string> KnownBlockIPs = new HashSet<string>
	{
		"0.0.0.0", "127.0.0.1", "::1", "185.228.168.10", "185.228.168.11", "146.112.61.104", "146.112.61.105", "146.112.61.106", "146.112.61.107", "146.112.61.108",
		"::ffff:0:0"
	};

	private static readonly ConcurrentBag<UdpClient> _dnsClientPool = new ConcurrentBag<UdpClient>();

	private static int _dnsPoolCount;

	private const int MaxDnsPoolSize = 4;

	private static readonly string[] ExcludedAdapterPrefixes = new string[10] { "vSwitch", "Radmin", "Tailscale", "VMware", "VirtualBox", "Hyper-V", "WSL", "Docker", "Ponte de Rede", "Conexao Local" };

	private static readonly string[] ExcludedVEthernetKeywords = new string[5] { "Default Switch", "NATSwitch", "NAT", "WSL", "DockerNAT" };

	public const string ProxyDnsAddress = "127.0.0.2";

	public static async Task<(bool IsBlocked, string? BlockedBy)> IsDomainBlockedByFamilyDnsAsync(string domain, Action<string>? log = null)
	{
		DnsProvider[] allowedProviders = DnsProvider.AllowedProviders;
		foreach (DnsProvider provider in allowedProviders)
		{
			try
			{
				List<IPAddress> ips = await ResolveDomainAsync(domain, provider.PrimaryDns);
				if (ips.Count == 0)
				{
					continue;
				}
				foreach (IPAddress ip in ips)
				{
					if (KnownBlockIPs.Contains(ip.ToString()))
					{
						log?.Invoke($"DNS {provider.Name} bloqueou {domain} (retornou {ip})");
						return (IsBlocked: true, BlockedBy: provider.Name);
					}
				}
			}
			catch (Exception ex)
			{
				log?.Invoke($"Erro ao consultar {provider.Name} para {domain}: {ex.Message}");
			}
		}
		return (IsBlocked: false, BlockedBy: null);
	}

	public static async Task<List<IPAddress>> ResolveDomainAsync(string domain, string dnsServer, int timeoutMs = 3000)
	{
		List<IPAddress> results = new List<IPAddress>();
		if (!_dnsClientPool.TryTake(out UdpClient? udp))
		{
			udp = new UdpClient
			{
				Client = { ReceiveTimeout = timeoutMs }
			};
		}
		else
		{
			Interlocked.Decrement(ref _dnsPoolCount);
		}
		try
		{
			ushort queryId = (ushort)Random.Shared.Next(0, 65535);
			byte[] query = BuildDnsQuery(queryId, domain);
			IPEndPoint endpoint = new IPEndPoint(IPAddress.Parse(dnsServer), 53);
			await udp.SendAsync(query, endpoint);
			using CancellationTokenSource cts = new CancellationTokenSource(timeoutMs);
			results = ParseDnsResponse((await udp.ReceiveAsync(cts.Token)).Buffer);
			if (Interlocked.Increment(ref _dnsPoolCount) <= 4)
			{
				_dnsClientPool.Add(udp);
			}
			else
			{
				Interlocked.Decrement(ref _dnsPoolCount);
				udp.Dispose();
			}
		}
		catch (SocketException)
		{
			try
			{
				udp.Dispose();
			}
			catch
			{
			}
		}
		catch
		{
			if (Interlocked.Increment(ref _dnsPoolCount) <= 4)
			{
				_dnsClientPool.Add(udp);
			}
			else
			{
				Interlocked.Decrement(ref _dnsPoolCount);
				udp.Dispose();
			}
		}
		return results;
	}

	private static byte[] BuildDnsQuery(ushort id, string domain)
	{
		using MemoryStream memoryStream = new MemoryStream();
		using BinaryWriter binaryWriter = new BinaryWriter(memoryStream);
		binaryWriter.Write(IPAddress.HostToNetworkOrder((short)id));
		binaryWriter.Write(IPAddress.HostToNetworkOrder((short)256));
		binaryWriter.Write(IPAddress.HostToNetworkOrder((short)1));
		binaryWriter.Write(IPAddress.HostToNetworkOrder((short)0));
		binaryWriter.Write(IPAddress.HostToNetworkOrder((short)0));
		binaryWriter.Write(IPAddress.HostToNetworkOrder((short)0));
		string[] array = domain.Split('.');
		foreach (string text in array)
		{
			binaryWriter.Write((byte)text.Length);
			binaryWriter.Write(Encoding.ASCII.GetBytes(text));
		}
		binaryWriter.Write((byte)0);
		binaryWriter.Write(IPAddress.HostToNetworkOrder((short)1));
		binaryWriter.Write(IPAddress.HostToNetworkOrder((short)1));
		return memoryStream.ToArray();
	}

	private static List<IPAddress> ParseDnsResponse(byte[] response)
	{
		List<IPAddress> list = new List<IPAddress>();
		if (response.Length < 12)
		{
			return list;
		}
		int num = response[3] & 0xF;
		int num2 = (response[6] << 8) | response[7];
		if (num != 0 || num2 == 0)
		{
			return list;
		}
		int offset = 12;
		offset = SkipDnsName(response, offset);
		if (offset < 0 || offset + 4 > response.Length)
		{
			return list;
		}
		offset += 4;
		for (int i = 0; i < num2; i++)
		{
			if (offset >= response.Length)
			{
				break;
			}
			offset = SkipDnsName(response, offset);
			if (offset < 0 || offset + 10 > response.Length)
			{
				break;
			}
			int num3 = (response[offset] << 8) | response[offset + 1];
			offset += 2;
			offset += 2;
			offset += 4;
			int num4 = (response[offset] << 8) | response[offset + 1];
			offset += 2;
			if (num3 == 1 && num4 == 4 && offset + 4 <= response.Length)
			{
				IPAddress item = new IPAddress(response.AsSpan(offset, 4));
				list.Add(item);
			}
			offset += num4;
		}
		return list;
	}

	private static int SkipDnsName(byte[] data, int offset)
	{
		if (offset >= data.Length)
		{
			return -1;
		}
		while (offset < data.Length)
		{
			byte b = data[offset];
			if (b == 0)
			{
				return offset + 1;
			}
			if ((b & 0xC0) == 192)
			{
				return offset + 2;
			}
			offset += b + 1;
		}
		return -1;
	}

	public static (string? Primary, string? Secondary) GetCurrentDns(string adapterName)
	{
		string adapterName2 = adapterName;
		try
		{
			NetworkInterface? networkInterface = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault((NetworkInterface n) => n.Name == adapterName2 && n.OperationalStatus == OperationalStatus.Up);
			if (networkInterface == null)
			{
				return (Primary: null, Secondary: null);
			}
			IPInterfaceProperties iPProperties = networkInterface.GetIPProperties();
			IPAddress[] array = iPProperties.DnsAddresses.ToArray();
			return (Primary: (array.Length != 0) ? array[0].ToString() : null, Secondary: (array.Length > 1) ? array[1].ToString() : null);
		}
		catch
		{
			return (Primary: null, Secondary: null);
		}
	}

	public static List<string> GetActiveNetworkAdapters()
	{
		return (from n in NetworkInterface.GetAllNetworkInterfaces()
			where n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback && !IsExcludedAdapter(n.Name)
			select n.Name).ToList();
	}

	private static bool IsExcludedAdapter(string name)
	{
		string name2 = name;
		if (ExcludedAdapterPrefixes.Any((string prefix) => name2.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
		{
			return true;
		}
		if (name2.StartsWith("vEthernet", StringComparison.OrdinalIgnoreCase))
		{
			return ExcludedVEthernetKeywords.Any((string kw) => name2.Contains(kw, StringComparison.OrdinalIgnoreCase));
		}
		return false;
	}

	public static bool SetDns(string adapterName, DnsProvider provider, bool dryRun = false, Action<string>? log = null)
	{
		try
		{
			string text = $"interface ip set dns name=\"{adapterName}\" static {provider.PrimaryDns} primary";
			string text2 = $"interface ip add dns name=\"{adapterName}\" {provider.SecondaryDns} index=2";
			string text3 = "interface ipv6 set dnsservers name=\"" + adapterName + "\" source=dhcp";
			if (dryRun)
			{
				log?.Invoke("[DRY-RUN] Executaria: netsh " + text);
				log?.Invoke("[DRY-RUN] Executaria: netsh " + text2);
				log?.Invoke("[DRY-RUN] Executaria: netsh " + text3);
				return true;
			}
			if (!RunNetshCommand(text))
			{
				return false;
			}
			RunNetshCommand(text2);
			RunNetshCommand(text3);
			return true;
		}
		catch
		{
			return false;
		}
	}

	public static bool IsDnsAllowed(string? primaryDns, string? secondaryDns)
	{
		if (string.IsNullOrEmpty(primaryDns))
		{
			return false;
		}
		if (primaryDns == "127.0.0.2")
		{
			return true;
		}
		DnsProvider[] allowedProviders = DnsProvider.AllowedProviders;
		foreach (DnsProvider dnsProvider in allowedProviders)
		{
			if (dnsProvider.PrimaryDns == primaryDns || dnsProvider.PrimaryDnsV6 == primaryDns)
			{
				return true;
			}
		}
		return false;
	}

	public static bool SetDnsForProxy(string adapterName, DnsProvider fallbackProvider, bool dryRun = false, Action<string>? log = null)
	{
		try
		{
			string text = $"interface ip set dns name=\"{adapterName}\" static {"127.0.0.2"} primary";
			string arguments = $"interface ip add dns name=\"{adapterName}\" {fallbackProvider.PrimaryDns} index=2";
			string arguments2 = "interface ipv6 set dnsservers name=\"" + adapterName + "\" source=dhcp";
			if (dryRun)
			{
				log?.Invoke("[DRY-RUN] Executaria: netsh " + text);
				return true;
			}
			if (!RunNetshCommand(text))
			{
				return false;
			}
			RunNetshCommand(arguments);
			RunNetshCommand(arguments2);
			return true;
		}
		catch
		{
			return false;
		}
	}

	private static bool RunNetshCommand(string arguments)
	{
		try
		{
			Process process = new Process
			{
				StartInfo = new ProcessStartInfo
				{
					FileName = "netsh",
					Arguments = arguments,
					UseShellExecute = false,
					CreateNoWindow = true,
					RedirectStandardOutput = true,
					RedirectStandardError = true
				}
			};
			process.Start();
			process.WaitForExit(5000);
			return process.ExitCode == 0;
		}
		catch
		{
			return false;
		}
	}
}
