using System.Net;
using System.Text;

namespace Tamp.Ingest.V1.Tests;

/// <summary>
/// Test-only <see cref="HttpMessageHandler"/> that captures every outgoing request and
/// returns a configurable response. Use one instance per test (no shared state).
/// </summary>
internal sealed class CapturingHandler : HttpMessageHandler
{
    public List<CapturedRequest> Sent { get; } = new();

    /// <summary>Default response: 204 No Content. Override for endpoints that return a body.</summary>
    public Func<HttpRequestMessage, HttpResponseMessage> Responder { get; set; }
        = _ => new HttpResponseMessage(HttpStatusCode.NoContent);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var contentType = request.Content?.Headers.ContentType?.MediaType;
        var authHeader = request.Headers.Authorization?.ToString();
        Sent.Add(new CapturedRequest(request.Method, request.RequestUri!, body, contentType, authHeader));
        return Responder(request);
    }
}

internal sealed record CapturedRequest(HttpMethod Method, Uri Uri, string? Body, string? ContentType, string? Authorization)
{
    public string Path => Uri.AbsolutePath;
    public string Query => Uri.Query;
}
