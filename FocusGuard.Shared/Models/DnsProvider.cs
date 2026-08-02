namespace FocusGuard.Shared.Models;

public class DnsProvider
{
	public static readonly DnsProvider[] AllowedProviders = new DnsProvider[3]
	{
		new DnsProvider
		{
			Name = "CleanBrowsing Family",
			PrimaryDns = "185.228.168.168",
			SecondaryDns = "185.228.169.168",
			PrimaryDnsV6 = "2a0d:2a00:1::",
			SecondaryDnsV6 = "2a0d:2a00:2::",
			Description = "Bloqueia adulto, proxy e malware"
		},
		new DnsProvider
		{
			Name = "OpenDNS FamilyShield",
			PrimaryDns = "208.67.222.123",
			SecondaryDns = "208.67.220.123",
			PrimaryDnsV6 = "2620:119:35::35",
			SecondaryDnsV6 = "2620:119:53::53",
			Description = "Filtro família da Cisco"
		},
		new DnsProvider
		{
			Name = "Cloudflare Families",
			PrimaryDns = "1.1.1.3",
			SecondaryDns = "1.0.0.3",
			PrimaryDnsV6 = "2606:4700:4700::1113",
			SecondaryDnsV6 = "2606:4700:4700::1003",
			Description = "Bloqueia malware e adulto"
		}
	};

	public required string Name { get; init; }

	public required string PrimaryDns { get; init; }

	public required string SecondaryDns { get; init; }

	public string? PrimaryDnsV6 { get; init; }

	public string? SecondaryDnsV6 { get; init; }

	public string? Description { get; init; }
}
