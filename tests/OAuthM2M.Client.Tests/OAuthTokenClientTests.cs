using System.Net;
using System.Net.Http;
using System.Text;
using System.Web;
using Microsoft.Extensions.Logging.Abstractions;
using OAuthM2M.Client.Security;
using OAuthM2M.Client.Tokens;

namespace OAuthM2M.Client.Tests;

public sealed class OAuthTokenClientTests
{
    private sealed record Call(HttpMethod Method, Uri? Uri, string? ContentType, string Body);

    private sealed class StubHandler(Func<HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<Call> Calls { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
            Calls.Add(new Call(request.Method, request.RequestUri, request.Content?.Headers.ContentType?.MediaType, body));
            return respond();
        }
    }

    private sealed class ThrowingHandler(Exception exception) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw exception;
    }

    private sealed class FakeAssertionFactory : IClientAssertionFactory
    {
        public int Calls { get; private set; }

        public string Create() => $"signed.jwt.{++Calls}";
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string json) =>
        new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static OAuthTokenClient CreateClient(HttpMessageHandler handler, OAuthClientOptions options, IClientAssertionFactory factory) =>
        new(new HttpClient(handler), factory, TestKeys.Wrap(options), NullLogger<OAuthTokenClient>.Instance);

    private static OAuthClientOptions JwtOptions() => TestKeys.JwtOptions("/unused.pem");

    private static OAuthClientOptions MtlsOptions() => new()
    {
        AuthMethod = ClientAuthMethod.TlsClientAuth,
        TokenEndpoint = TestKeys.TokenEndpoint,
        ClientId = "my-service",
        ClientCertificatePath = "/unused.pfx"
    };

    private const string OkJson = """{"access_token":"abc.def.ghi","expires_in":300,"token_type":"Bearer"}""";

    [Fact]
    public async Task PrivateKeyJwt_sends_expected_form_and_parses_response()
    {
        var handler = new StubHandler(() => Json(HttpStatusCode.OK, OkJson));
        var factory = new FakeAssertionFactory();
        var client = CreateClient(handler, JwtOptions(), factory);

        var token = await client.RequestTokenAsync();

        var call = Assert.Single(handler.Calls);
        Assert.Equal(HttpMethod.Post, call.Method);
        Assert.Equal(TestKeys.TokenEndpoint, call.Uri!.ToString());
        Assert.Equal("application/x-www-form-urlencoded", call.ContentType);

        var form = HttpUtility.ParseQueryString(call.Body);
        Assert.Equal("client_credentials", form["grant_type"]);
        Assert.Equal("my-service", form["client_id"]);
        Assert.Equal("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", form["client_assertion_type"]);
        Assert.Equal("signed.jwt.1", form["client_assertion"]);
        Assert.Null(form["client_secret"]);

        Assert.Equal("abc.def.ghi", token.AccessToken);
        Assert.Equal(300, token.ExpiresIn);
        Assert.Equal("Bearer", token.TokenType);
    }

    [Fact]
    public async Task Mtls_mode_sends_no_assertion_and_does_not_touch_the_key()
    {
        var handler = new StubHandler(() => Json(HttpStatusCode.OK, OkJson));
        var factory = new FakeAssertionFactory();
        var client = CreateClient(handler, MtlsOptions(), factory);

        await client.RequestTokenAsync();

        var form = HttpUtility.ParseQueryString(Assert.Single(handler.Calls).Body);
        Assert.Equal("client_credentials", form["grant_type"]);
        Assert.Equal("my-service", form["client_id"]);
        Assert.Null(form["client_assertion"]);
        Assert.Null(form["client_assertion_type"]);
        Assert.Null(form["client_secret"]);
        Assert.Equal(0, factory.Calls);
    }

    [Fact]
    public async Task Scope_is_sent_when_configured()
    {
        var handler = new StubHandler(() => Json(HttpStatusCode.OK, OkJson));
        var options = JwtOptions();
        options.Scope = "api.read api.write";
        var client = CreateClient(handler, options, new FakeAssertionFactory());

        await client.RequestTokenAsync();

        var form = HttpUtility.ParseQueryString(Assert.Single(handler.Calls).Body);
        Assert.Equal("api.read api.write", form["scope"]);
    }

    [Fact]
    public async Task Fresh_assertion_is_created_for_every_request()
    {
        var handler = new StubHandler(() => Json(HttpStatusCode.OK, OkJson));
        var factory = new FakeAssertionFactory();
        var client = CreateClient(handler, JwtOptions(), factory);

        await client.RequestTokenAsync();
        await client.RequestTokenAsync();

        Assert.Equal(2, factory.Calls);
        Assert.NotEqual(
            HttpUtility.ParseQueryString(handler.Calls[0].Body)["client_assertion"],
            HttpUtility.ParseQueryString(handler.Calls[1].Body)["client_assertion"]);
    }

    [Fact]
    public async Task Error_response_throws_with_status_and_oauth_error()
    {
        var handler = new StubHandler(() => Json(
            HttpStatusCode.Unauthorized,
            """{"error":"invalid_client","error_description":"Invalid client or Invalid client credentials"}"""));
        var client = CreateClient(handler, JwtOptions(), new FakeAssertionFactory());

        var ex = await Assert.ThrowsAsync<TokenRequestException>(() => client.RequestTokenAsync());

        Assert.Equal(401, ex.StatusCode);
        Assert.Equal("invalid_client", ex.Error);
        Assert.Contains("Invalid client", ex.Message);
    }

    [Fact]
    public async Task Non_json_error_body_is_still_reported()
    {
        var handler = new StubHandler(() => new HttpResponseMessage(HttpStatusCode.BadGateway)
        {
            Content = new StringContent("<html>bad gateway</html>")
        });
        var client = CreateClient(handler, JwtOptions(), new FakeAssertionFactory());

        var ex = await Assert.ThrowsAsync<TokenRequestException>(() => client.RequestTokenAsync());

        Assert.Equal(502, ex.StatusCode);
        Assert.Null(ex.Error);
        Assert.Contains("bad gateway", ex.Message);
    }

    [Fact]
    public async Task Invalid_json_on_success_throws()
    {
        var handler = new StubHandler(() => Json(HttpStatusCode.OK, "not json"));
        var client = CreateClient(handler, JwtOptions(), new FakeAssertionFactory());

        await Assert.ThrowsAsync<TokenRequestException>(() => client.RequestTokenAsync());
    }

    [Fact]
    public async Task Missing_access_token_throws()
    {
        var handler = new StubHandler(() => Json(HttpStatusCode.OK, """{"expires_in":300}"""));
        var client = CreateClient(handler, JwtOptions(), new FakeAssertionFactory());

        var ex = await Assert.ThrowsAsync<TokenRequestException>(() => client.RequestTokenAsync());

        Assert.Contains("access_token", ex.Message);
    }

    [Fact]
    public async Task Network_error_is_wrapped()
    {
        var client = CreateClient(
            new ThrowingHandler(new HttpRequestException("connection refused")),
            JwtOptions(),
            new FakeAssertionFactory());

        var ex = await Assert.ThrowsAsync<TokenRequestException>(() => client.RequestTokenAsync());

        Assert.IsType<HttpRequestException>(ex.InnerException);
    }

    [Fact]
    public async Task Timeout_is_reported_as_token_request_failure()
    {
        var client = CreateClient(
            new ThrowingHandler(new TaskCanceledException("timeout")),
            JwtOptions(),
            new FakeAssertionFactory());

        var ex = await Assert.ThrowsAsync<TokenRequestException>(() => client.RequestTokenAsync());

        Assert.Contains("Таймаут", ex.Message);
    }

    [Fact]
    public async Task Caller_cancellation_is_not_wrapped()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var client = CreateClient(
            new ThrowingHandler(new OperationCanceledException(cts.Token)),
            JwtOptions(),
            new FakeAssertionFactory());

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.RequestTokenAsync(cts.Token));
    }
}
