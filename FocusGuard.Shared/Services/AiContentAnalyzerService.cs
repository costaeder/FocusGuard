using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using FocusGuard.Shared.Models;

namespace FocusGuard.Shared.Services;

public class AiClassification
{
	[JsonPropertyName("domain")]
	public string Domain { get; set; } = string.Empty;

	[JsonPropertyName("category")]
	public string Category { get; set; } = "safe";
}

public static class AiContentAnalyzerService
{
	private static readonly HttpClient _httpClient = new HttpClient
	{
		Timeout = TimeSpan.FromSeconds(30L)
	};

	private const string OpenAiEndpoint = "https://api.openai.com/v1/chat/completions";

	private const string SystemPrompt = "You are a content safety classifier for a parental control / focus tool.\n" +
		"You will receive a list of internet domains. For each domain, classify it into exactly one category:\n" +
		"- \"adult\": pornography, escort, cam sites, explicit sexual content\n" +
		"- \"gambling\": online casinos, sports betting, lottery, slot machines\n" +
		"- \"proxy\": web proxies, VPN services, anonymizers and \"unblock\"/\"bypass\" sites whose purpose is to access blocked content (e.g. croxyproxy, proxysite, hidemyass, hide.me, kproxy)\n" +
		"- \"distraction\": social media feeds, meme sites, time-wasting content, piracy/torrent sites\n" +
		"- \"safe\": legitimate websites (news, education, work tools, e-commerce, etc.)\n\n" +
		"IMPORTANT:\n" +
		"- Be aggressive with adult, gambling and proxy detection. When in doubt between adult/safe, choose adult.\n" +
		"- Be VERY aggressive with proxy detection: any site whose purpose is to proxy, unblock, anonymize or tunnel traffic is \"proxy\". Names containing \"proxy\", \"unblock\", \"vpn\", \"hide\", \"croxy\", \"anonym\", \"bypass\" should be \"proxy\".\n" +
		"- Only classify as \"safe\" if you are confident it is a legitimate, non-harmful site.\n" +
		"- If you don't recognize a domain, classify based on name patterns (e.g. domains containing \"porn\", \"xxx\", \"bet\", \"casino\" should be blocked).\n" +
		"- Return ONLY valid JSON, no markdown, no explanation.\n\n" +
		"Return a JSON array with this exact format:\n" +
		"[{\"domain\": \"example.com\", \"category\": \"safe\"}, {\"domain\": \"pornhub.com\", \"category\": \"adult\"}, {\"domain\": \"croxyproxy.com\", \"category\": \"proxy\"}]";

	public static async Task<List<AiClassification>> AnalyzeBatchAsync(List<string> domains, string apiKey, string model = "gpt-5.4-nano", Action<string>? log = null)
	{
		if (domains.Count == 0)
		{
			return new List<AiClassification>();
		}
		if (string.IsNullOrEmpty(apiKey))
		{
			log?.Invoke("AI Analysis: API key nao configurada");
			return new List<AiClassification>();
		}
		try
		{
			string domainList = string.Join("\n", domains.Select((string d, int i) => $"{i + 1}. {d}"));
			string userPrompt = "Classify these domains:\n" + domainList;
			log?.Invoke($"AI Analysis: enviando {domains.Count} dominios para {model}...");
			// Modelos GPT-5 (ex.: gpt-5.4-nano) usam 'max_completion_tokens' (nao 'max_tokens')
			// e aceitam apenas a temperatura padrao, por isso 'temperature' e omitida.
			// O limite e generoso para acomodar tokens de raciocinio + a saida JSON.
			var requestBody = new
			{
				model,
				messages = new object[2]
				{
					new { role = "system", content = SystemPrompt },
					new { role = "user", content = userPrompt }
				},
				max_completion_tokens = 2000
			};
			string json = JsonSerializer.Serialize(requestBody);
			log?.Invoke("AI Request: POST " + OpenAiEndpoint);
			log?.Invoke($"AI Request: modelo={model}, dominios=[{string.Join(", ", domains)}]");
			HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, OpenAiEndpoint)
			{
				Content = new StringContent(json, Encoding.UTF8, "application/json")
			};
			request.Headers.Add("Authorization", "Bearer " + apiKey);
			log?.Invoke("AI Request: key=" + apiKey.Substring(0, Math.Min(8, apiKey.Length)) + "...(oculta)");
			Stopwatch sw = Stopwatch.StartNew();
			HttpResponseMessage response = await _httpClient.SendAsync(request);
			sw.Stop();
			string responseBody = await response.Content.ReadAsStringAsync();
			log?.Invoke($"AI Response: HTTP {response.StatusCode} em {sw.ElapsedMilliseconds}ms");
			if (!response.IsSuccessStatusCode)
			{
				log?.Invoke("AI Response ERRO: " + responseBody);
				return new List<AiClassification>();
			}
			log?.Invoke("AI Response body: " + ((responseBody.Length > 500) ? (responseBody.Substring(0, 500) + "...") : responseBody));
			string? content = JsonSerializer.Deserialize<OpenAiResponse>(responseBody)?.Choices?.FirstOrDefault()?.Message?.Content;
			if (string.IsNullOrEmpty(content))
			{
				log?.Invoke("AI Analysis: resposta vazia da API");
				return new List<AiClassification>();
			}
			content = content.Trim();
			if (content.StartsWith("```"))
			{
				int firstNewline = content.IndexOf('\n');
				if (firstNewline >= 0)
				{
					content = content.Substring(firstNewline + 1);
				}
				if (content.EndsWith("```"))
				{
					content = content.Substring(0, content.Length - 3);
				}
				content = content.Trim();
			}
			List<AiClassification>? classifications = JsonSerializer.Deserialize<List<AiClassification>>(content, new JsonSerializerOptions
			{
				PropertyNameCaseInsensitive = true
			});
			if (classifications == null)
			{
				log?.Invoke("AI Analysis: falha ao deserializar resposta");
				return new List<AiClassification>();
			}
			log?.Invoke($"AI Analysis: {classifications.Count} dominios classificados");
			foreach (AiClassification c in classifications)
			{
				log?.Invoke("  " + c.Domain + " -> " + c.Category);
			}
			return classifications;
		}
		catch (TaskCanceledException)
		{
			log?.Invoke("AI Analysis: timeout na requisicao");
			return new List<AiClassification>();
		}
		catch (Exception ex)
		{
			log?.Invoke("AI Analysis: erro - " + ex.Message);
			return new List<AiClassification>();
		}
	}

	public static AnalyzedSite ToAnalyzedSite(AiClassification classification)
	{
		string category = classification.Category?.ToLowerInvariant() ?? "safe";
		bool isBad = category is "adult" or "gambling" or "distraction" or "proxy";
		return new AnalyzedSite
		{
			Domain = classification.Domain.ToLowerInvariant(),
			AnalyzedAt = DateTime.UtcNow,
			Score = (isBad ? 80 : 0),
			Category = category,
			MatchedKeywords = new List<string> { "ai:" + category },
			IsBlocked = false
		};
	}

	private class OpenAiResponse
	{
		[JsonPropertyName("choices")]
		public List<OpenAiChoice>? Choices { get; set; }
	}

	private class OpenAiChoice
	{
		[JsonPropertyName("message")]
		public OpenAiMessage? Message { get; set; }
	}

	private class OpenAiMessage
	{
		[JsonPropertyName("content")]
		public string? Content { get; set; }
	}
}
