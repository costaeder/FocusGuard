using System.Text.Json;

namespace FocusGuard.Shared.Services;

/// <summary>
/// Rastreia "minutos ativos" por dominio no dia corrente (horario local) para
/// impor cota diaria de uso. Um minuto conta quando ha >= 1 consulta DNS nele
/// (varias consultas no mesmo minuto contam como 1). Persistido em
/// ProgramData\FocusGuard\usage.json e resetado automaticamente a cada dia.
/// Thread-safe (o DNS proxy chama isto de forma concorrente).
/// </summary>
public class UsageTracker
{
    private static readonly string UsagePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "FocusGuard", "usage.json");

    private readonly object _lock = new();
    private string _date = Today();
    private readonly Dictionary<string, int> _minutes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, long> _lastBucket = new(StringComparer.OrdinalIgnoreCase);

    public UsageTracker() => Load();

    private static string Today() => DateTime.Now.ToString("yyyy-MM-dd");
    private static long CurrentBucket() => DateTime.Now.Ticks / TimeSpan.TicksPerMinute;

    /// <summary>
    /// Registra atividade para o dominio. Conta +1 minuto apenas se for um
    /// minuto (bucket) novo para aquele dominio.
    /// </summary>
    /// <returns>true se este acesso iniciou um minuto novo (foi contado).</returns>
    public bool RecordActivity(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return false;
        lock (_lock)
        {
            RollDayIfNeeded();
            var bucket = CurrentBucket();
            if (_lastBucket.TryGetValue(domain, out var last) && last == bucket)
                return false; // este minuto ja foi contado para este dominio
            _lastBucket[domain] = bucket;
            _minutes[domain] = _minutes.GetValueOrDefault(domain) + 1;
            Save();
            return true;
        }
    }

    /// <summary>Minutos ativos ja usados pelo dominio hoje.</summary>
    public int GetUsedMinutes(string domain)
    {
        lock (_lock)
        {
            RollDayIfNeeded();
            return _minutes.GetValueOrDefault(domain);
        }
    }

    /// <summary>true se o dominio ja atingiu/passou o limite diario.</summary>
    public bool IsOverLimit(string domain, int limitMinutes)
        => GetUsedMinutes(domain) >= limitMinutes;

    private void RollDayIfNeeded()
    {
        var today = Today();
        if (today == _date) return;
        _date = today;
        _minutes.Clear();
        _lastBucket.Clear();
        Save();
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(UsagePath)) return;
            var data = JsonSerializer.Deserialize<UsageData>(File.ReadAllText(UsagePath));
            if (data?.Minutes == null) return;
            // So aproveita se for do mesmo dia; senao comeca zerado.
            if (data.Date == Today())
            {
                _date = data.Date;
                foreach (var kv in data.Minutes)
                    _minutes[kv.Key] = kv.Value;
            }
        }
        catch { }
    }

    private void Save()
    {
        try
        {
            var dir = Path.GetDirectoryName(UsagePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            var data = new UsageData { Date = _date, Minutes = new(_minutes) };
            File.WriteAllText(UsagePath, JsonSerializer.Serialize(data,
                new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { }
    }

    private class UsageData
    {
        public string Date { get; set; } = "";
        public Dictionary<string, int> Minutes { get; set; } = new();
    }
}
