namespace FocusGuard.Shared.Models;

public class AnalyzedSite
{
	public string Domain { get; set; } = string.Empty;

	public DateTime AnalyzedAt { get; set; } = DateTime.UtcNow;

	public bool IsBlocked { get; set; }

	public int Score { get; set; }

	/// <summary>Numero de vezes que o site foi detectado como categoria ruim (reincidencia).</summary>
	public int Hits { get; set; }

	/// <summary>Se ja foi emitido um aviso ao usuario antes do bloqueio (bloqueio progressivo).</summary>
	public bool Warned { get; set; }

	public string Category { get; set; } = string.Empty;

	public List<string> MatchedKeywords { get; set; } = new List<string>();

	public string Title { get; set; } = string.Empty;

	public bool AnalysisFailed { get; set; }

	public string FailureReason { get; set; } = string.Empty;
}
