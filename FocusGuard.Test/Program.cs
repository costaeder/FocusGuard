// FocusGuard.Test - projeto de teste manual.
//
// NOTA: o conteudo original deste arquivo foi PERDIDO na corrupcao de disco
// (arquivos zerados ao copiar de outro drive). O original referenciava a antiga
// classe ContentAnalyzerService (analise por download de HTML + keywords), que
// foi substituida pela AiContentAnalyzerService (classificacao por IA).
//
// Este stub mantem a solucao compilavel. Reimplemente os testes conforme
// necessario usando a API atual em FocusGuard.Shared.Services.

using FocusGuard.Shared.Services;

Console.WriteLine("=== FocusGuard.Test ===");
Console.WriteLine("Placeholder. O teste original foi perdido na corrupcao de disco.");
Console.WriteLine();

// Exemplo de teste offline: checagem de dominio ja bloqueado no arquivo hosts.
var blocked = HostsService.GetBlockedSites();
Console.WriteLine($"Sites atualmente no hosts (FocusGuard): {blocked.Count}");
foreach (var d in blocked.Take(10))
    Console.WriteLine($"  - {d}");
