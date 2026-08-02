#r "FocusGuard.Shared/bin/Debug/net9.0/FocusGuard.Shared.dll"

using FocusGuard.Shared.Services;

Console.WriteLine("=== Teste do Analisador de Conteudo ===\n");

// Dominios para testar
var testDomains = new[]
{
    "github.com",           // Seguro
    "stackoverflow.com",    // Seguro
    "xvideos.com",          // Adulto (deve bloquear)
    "pornhub.com",          // Adulto (deve bloquear)
    "bet365.com",           // Apostas (deve bloquear)
    "blaze.com",            // Apostas (deve bloquear)
};

foreach (var domain in testDomains)
{
    Console.WriteLine($"--- Analisando: {domain} ---");

    // Analise rapida (so pelo nome do dominio)
    var quick = ContentAnalyzerService.QuickDomainAnalysis(domain);
    Console.WriteLine($"  Analise rapida - Score: {quick.Score}");
    if (quick.MatchedKeywords.Count > 0)
        Console.WriteLine($"  Palavras no dominio: {string.Join(", ", quick.MatchedKeywords)}");

    // Analise completa (baixa HTML)
    var result = await ContentAnalyzerService.AnalyzeDomainAsync(domain, threshold: 15);
    Console.WriteLine($"  Analise completa - Score: {result.Score}, Categoria: {result.Category}");
    Console.WriteLine($"  Titulo: {result.Title}");
    Console.WriteLine($"  Bloqueado: {(result.IsBlocked ? "SIM" : "NAO")}");
    if (result.MatchedKeywords.Count > 0)
        Console.WriteLine($"  Palavras encontradas: {string.Join(", ", result.MatchedKeywords.Take(10))}");

    Console.WriteLine();
}
