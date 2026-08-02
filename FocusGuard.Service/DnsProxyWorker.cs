using System.Buffers;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using FocusGuard.Shared.Models;
using FocusGuard.Shared.Services;

namespace FocusGuard.Service;

/// <summary>
/// DNS proxy que escuta em 127.0.0.2:53.
/// Dominios bloqueados -> 127.0.0.1. Demais -> forward para DNS family upstream.
/// </summary>
public class DnsProxyWorker : BackgroundService
{
    private readonly ILogger<DnsProxyWorker> _logger;
    private readonly BlockedDomainStore _blockedStore;
    private readonly DnsQueryNotifier _queryNotifier;

    private static readonly IPAddress ProxyAddress = IPAddress.Parse("127.0.0.2");
    private const int DnsPort = 53;

    // Cache de respostas upstream (domain+type -> resposta)
    private readonly ConcurrentDictionary<string, CachedResponse> _responseCache = new();
    private const int MaxCacheEntries = 10000;

    // Limite de queries concorrentes para nao estressar o kernel (previne BSOD)
    private readonly SemaphoreSlim _concurrencyLimiter = new(50, 50);

    // Pool de UdpClients reutilizaveis para upstream (evita socket churn)
    private readonly ConcurrentBag<UdpClient> _upstreamPool = [];
    private const int MaxPoolSize = 8;
    private int _poolCount;

    public DnsProxyWorker(
        ILogger<DnsProxyWorker> logger,
        BlockedDomainStore blockedStore,
        DnsQueryNotifier queryNotifier)
    {
        _logger = logger;
        _blockedStore = blockedStore;
        _queryNotifier = queryNotifier;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _blockedStore.Reload(ContentAnalyzerWorker.IsWhitelisted);
        _logger.LogInformation("DNS Proxy iniciando em {Address}:{Port} ({Count} dominios bloqueados)",
            ProxyAddress, DnsPort, _blockedStore.Count);

        var config = AppConfig.Load();
        var upstream = config.GetSelectedDns();
        _logger.LogInformation("DNS upstream: {Name} ({Primary}/{Secondary})", upstream.Name, upstream.PrimaryDns, upstream.SecondaryDns);

        using var udpServer = new UdpClient(new IPEndPoint(ProxyAddress, DnsPort));

        // Reload config periodicamente
        var reloadTask = ReloadConfigLoop(stoppingToken);
        var cleanupTask = CacheCleanupLoop(stoppingToken);

        _logger.LogInformation("DNS Proxy ativo e escutando");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var result = await udpServer.ReceiveAsync(stoppingToken);

                // Limita concorrencia para nao estressar o kernel
                if (_concurrencyLimiter.CurrentCount == 0)
                {
                    _logger.LogWarning("[DNS] Limite de concorrencia atingido, descartando query");
                    continue;
                }

                _ = ProcessQueryWithLimitAsync(udpServer, result.Buffer, result.RemoteEndPoint, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (SocketException)
            {
                // ICMP Port Unreachable / connection reset - normal em UDP, ignora
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao receber query DNS");
            }
        }

        await Task.WhenAll(reloadTask, cleanupTask);
        DrainPool();

        // Restaura DNS dos adaptadores para o provider upstream (sem proxy)
        // para que a internet continue funcionando com o servico parado
        RestoreDnsToUpstream();
    }

    /// <summary>
    /// Quando o servico para, o DNS precisa sair de 127.0.0.2 (proxy local)
    /// e voltar para o DNS family direto, senao a internet morre.
    /// </summary>
    private void RestoreDnsToUpstream()
    {
        try
        {
            var config = AppConfig.Load();
            var upstream = config.GetSelectedDns();
            var adapters = DnsService.GetActiveNetworkAdapters();

            foreach (var adapter in adapters)
            {
                var (primary, _) = DnsService.GetCurrentDns(adapter);
                if (primary == DnsService.ProxyDnsAddress)
                {
                    _logger.LogInformation("Restaurando DNS do adaptador {Adapter} para {Dns}", adapter, upstream.Name);
                    DnsService.SetDns(adapter, upstream, dryRun: false, msg => _logger.LogInformation(msg));
                }
            }

            _logger.LogInformation("DNS restaurado para {Dns} em todos os adaptadores", upstream.Name);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao restaurar DNS ao parar servico");
        }
    }

    private async Task ProcessQueryWithLimitAsync(UdpClient server, byte[] data, IPEndPoint remoteEp, CancellationToken ct)
    {
        await _concurrencyLimiter.WaitAsync(ct);
        try
        {
            await ProcessQueryAsync(server, data, remoteEp, ct);
        }
        finally
        {
            _concurrencyLimiter.Release();
        }
    }

    private UdpClient RentUpstreamClient()
    {
        if (_upstreamPool.TryTake(out var client))
        {
            Interlocked.Decrement(ref _poolCount);
            return client;
        }
        var c = new UdpClient();
        c.Client.ReceiveTimeout = 3000;
        return c;
    }

    private void ReturnUpstreamClient(UdpClient client)
    {
        if (Interlocked.Increment(ref _poolCount) <= MaxPoolSize)
        {
            _upstreamPool.Add(client);
        }
        else
        {
            Interlocked.Decrement(ref _poolCount);
            client.Dispose();
        }
    }

    private void DiscardUpstreamClient(UdpClient client)
    {
        try { client.Dispose(); } catch { }
    }

    private void DrainPool()
    {
        while (_upstreamPool.TryTake(out var client))
        {
            Interlocked.Decrement(ref _poolCount);
            try { client.Dispose(); } catch { }
        }
    }

    private async Task ProcessQueryAsync(UdpClient server, byte[] data, IPEndPoint remoteEp, CancellationToken ct)
    {
        try
        {
            if (data.Length < 12) return;

            var (domain, queryType) = ParseQuestion(data);
            if (string.IsNullOrEmpty(domain)) return;

            domain = domain.TrimEnd('.').ToLowerInvariant();

            // Notifica o ContentAnalyzerWorker
            var baseDomain = GetBaseDomain(domain);
            if (!string.IsNullOrEmpty(baseDomain))
                _queryNotifier.Enqueue(baseDomain);

            byte[] response;

            if (_blockedStore.IsBlocked(domain) && !ContentAnalyzerWorker.IsWhitelisted(domain))
            {
                _logger.LogInformation("[DNS] BLOQUEADO: {Domain} (tipo={Type})", domain, queryType);
                response = BuildBlockedResponse(data, queryType);
            }
            else
            {
                // Check cache
                var cacheKey = $"{domain}:{queryType}";
                if (_responseCache.TryGetValue(cacheKey, out var cached) && cached.Expiry > DateTime.UtcNow)
                {
                    // Reescreve o transaction ID
                    response = (byte[])cached.Data.Clone();
                    response[0] = data[0];
                    response[1] = data[1];
                }
                else
                {
                    response = await ForwardToUpstreamAsync(data, ct);
                    if (response.Length > 0 && _responseCache.Count < MaxCacheEntries)
                    {
                        var ttl = ExtractMinTtl(response);
                        _responseCache[cacheKey] = new CachedResponse
                        {
                            Data = response,
                            Expiry = DateTime.UtcNow.AddSeconds(Math.Max(ttl, 30))
                        };
                    }
                }
            }

            if (response.Length > 0)
                await server.SendAsync(response, remoteEp, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Erro ao processar query DNS");
        }
    }

    private async Task<byte[]> ForwardToUpstreamAsync(byte[] query, CancellationToken ct)
    {
        var config = AppConfig.Load();
        var upstream = config.GetSelectedDns();

        // Tenta primario
        var result = await ForwardToServerAsync(query, upstream.PrimaryDns, ct);
        if (result.Length > 0) return result;

        // Fallback para secundario
        return await ForwardToServerAsync(query, upstream.SecondaryDns, ct);
    }

    private async Task<byte[]> ForwardToServerAsync(byte[] query, string server, CancellationToken ct)
    {
        var client = RentUpstreamClient();
        try
        {
            var endpoint = new IPEndPoint(IPAddress.Parse(server), 53);
            await client.SendAsync(query, endpoint, ct);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(3000);

            // Loop para descartar respostas stale (transaction ID diferente)
            var queryTxId = (ushort)((query[0] << 8) | query[1]);
            for (int attempt = 0; attempt < 3; attempt++)
            {
                var response = await client.ReceiveAsync(cts.Token);
                if (response.Buffer.Length >= 2)
                {
                    var respTxId = (ushort)((response.Buffer[0] << 8) | response.Buffer[1]);
                    if (respTxId == queryTxId)
                    {
                        ReturnUpstreamClient(client);
                        return response.Buffer;
                    }
                    _logger.LogDebug("[DNS] Descartando resposta stale (txid={Stale:X4}, esperado={Expected:X4})",
                        respTxId, queryTxId);
                }
            }

            // Nao conseguiu resposta valida apos retries
            DiscardUpstreamClient(client);
            return [];
        }
        catch (SocketException)
        {
            DiscardUpstreamClient(client);
            return [];
        }
        catch
        {
            // Timeout ou cancelamento — socket pode ter resposta pendente, descarta
            DiscardUpstreamClient(client);
            return [];
        }
    }

    /// <summary>
    /// Constroi resposta DNS para dominio bloqueado.
    /// A record -> 127.0.0.1, AAAA record -> ::1
    /// </summary>
    private static byte[] BuildBlockedResponse(byte[] query, ushort queryType)
    {
        using var ms = new MemoryStream();

        // Copia header do query
        ms.Write(query, 0, 2); // Transaction ID

        // Flags: response, authoritative, recursion available
        ms.WriteByte(0x85); // QR=1, Opcode=0, AA=1, TC=0, RD=1
        ms.WriteByte(0x80); // RA=1, RCODE=0

        // Questions: 1
        ms.WriteByte(0x00); ms.WriteByte(0x01);

        // Answers: 1 (se A ou AAAA, senao 0)
        bool hasAnswer = queryType is 1 or 28;
        ms.WriteByte(0x00); ms.WriteByte(hasAnswer ? (byte)0x01 : (byte)0x00);

        // Authority: 0, Additional: 0
        ms.WriteByte(0x00); ms.WriteByte(0x00);
        ms.WriteByte(0x00); ms.WriteByte(0x00);

        // Copia question section do query original
        var questionStart = 12;
        var questionEnd = SkipQuestion(query, questionStart);
        ms.Write(query, questionStart, questionEnd - questionStart);

        if (hasAnswer)
        {
            // Answer: pointer to question name (compression)
            ms.WriteByte(0xC0); ms.WriteByte(0x0C);

            // Type
            ms.WriteByte((byte)(queryType >> 8)); ms.WriteByte((byte)(queryType & 0xFF));

            // Class IN
            ms.WriteByte(0x00); ms.WriteByte(0x01);

            // TTL: 60 seconds
            ms.WriteByte(0x00); ms.WriteByte(0x00); ms.WriteByte(0x00); ms.WriteByte(0x3C);

            if (queryType == 1) // A record -> 127.0.0.1
            {
                ms.WriteByte(0x00); ms.WriteByte(0x04); // RDLength
                ms.WriteByte(127); ms.WriteByte(0); ms.WriteByte(0); ms.WriteByte(1);
            }
            else if (queryType == 28) // AAAA record -> ::1
            {
                ms.WriteByte(0x00); ms.WriteByte(0x10); // RDLength = 16
                for (int i = 0; i < 15; i++) ms.WriteByte(0x00);
                ms.WriteByte(0x01);
            }
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Parse do nome de dominio e tipo de query
    /// </summary>
    private static (string Domain, ushort Type) ParseQuestion(byte[] data)
    {
        if (data.Length < 12) return ("", 0);

        int offset = 12; // Skip header
        var sb = new StringBuilder();

        while (offset < data.Length)
        {
            byte len = data[offset++];
            if (len == 0) break;

            if ((len & 0xC0) == 0xC0)
            {
                offset++; // Skip pointer
                break;
            }

            if (sb.Length > 0) sb.Append('.');
            if (offset + len > data.Length) return ("", 0);
            sb.Append(Encoding.ASCII.GetString(data, offset, len));
            offset += len;
        }

        if (offset + 4 > data.Length) return (sb.ToString(), 0);

        ushort qtype = (ushort)((data[offset] << 8) | data[offset + 1]);
        return (sb.ToString(), qtype);
    }

    private static int SkipQuestion(byte[] data, int offset)
    {
        while (offset < data.Length)
        {
            byte len = data[offset];
            if (len == 0) { offset++; break; }
            if ((len & 0xC0) == 0xC0) { offset += 2; break; }
            offset += len + 1;
        }
        offset += 4; // Type + Class
        return offset;
    }

    private static int ExtractMinTtl(byte[] response)
    {
        if (response.Length < 12) return 60;

        int answerCount = (response[6] << 8) | response[7];
        int offset = 12;

        // Skip question
        offset = SkipQuestion(response, offset);

        int minTtl = 3600;
        for (int i = 0; i < answerCount && offset < response.Length; i++)
        {
            // Skip name
            while (offset < response.Length)
            {
                byte b = response[offset];
                if (b == 0) { offset++; break; }
                if ((b & 0xC0) == 0xC0) { offset += 2; break; }
                offset += b + 1;
            }

            if (offset + 10 > response.Length) break;

            offset += 2; // Type
            offset += 2; // Class
            int ttl = (response[offset] << 24) | (response[offset + 1] << 16) |
                      (response[offset + 2] << 8) | response[offset + 3];
            offset += 4;
            if (ttl < minTtl && ttl > 0) minTtl = ttl;

            int rdLen = (response[offset] << 8) | response[offset + 1];
            offset += 2 + rdLen;
        }

        return minTtl;
    }

    private static string GetBaseDomain(string domain)
    {
        var parts = domain.Split('.');
        if (parts.Length <= 2) return domain;

        if (parts.Length >= 3 &&
            parts[^2] is "com" or "co" or "org" or "gov" or "edu")
            return string.Join(".", parts[^3..]);

        return string.Join(".", parts[^2..]);
    }

    private async Task ReloadConfigLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(15), ct);
                var before = _blockedStore.Count;
                _blockedStore.Reload(ContentAnalyzerWorker.IsWhitelisted);
                var after = _blockedStore.Count;
                if (after != before)
                    _logger.LogInformation("[DNS] Dominios bloqueados atualizados: {Count}", after);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { _logger.LogDebug(ex, "Erro no reload config"); }
        }
    }

    private async Task CacheCleanupLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(5), ct);
                var now = DateTime.UtcNow;
                var expired = _responseCache.Where(kv => kv.Value.Expiry < now).Select(kv => kv.Key).ToList();
                foreach (var key in expired)
                    _responseCache.TryRemove(key, out _);
            }
            catch (OperationCanceledException) { break; }
            catch { }
        }
    }

    private class CachedResponse
    {
        public required byte[] Data { get; init; }
        public required DateTime Expiry { get; init; }
    }
}
