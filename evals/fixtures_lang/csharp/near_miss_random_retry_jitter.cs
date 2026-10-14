// Near miss: System.Random only spreads retry delays so clients do not retry
// in lockstep. Nothing secret or security-relevant is derived from it.
using System.Net;

namespace Billing.Clients;

public sealed class RetryingHttpClient
{
    private readonly HttpClient _http;
    private readonly Random _jitter = new Random();

    public RetryingHttpClient(HttpClient http)
    {
        _http = http;
    }

    public async Task<HttpResponseMessage> GetAsync(string url, CancellationToken ct)
    {
        for (var attempt = 1; ; attempt++)
        {
            var response = await _http.GetAsync(url, ct);
            if (response.StatusCode != HttpStatusCode.ServiceUnavailable || attempt == 5)
            {
                return response;
            }
            var delayMs = (int)Math.Pow(2, attempt) * 100;
            delayMs += _jitter.Next(0, 100);
            await Task.Delay(delayMs, ct);
        }
    }
}
