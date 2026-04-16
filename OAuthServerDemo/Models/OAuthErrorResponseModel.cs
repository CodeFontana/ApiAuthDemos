using System.Text.Json.Serialization;

namespace OAuthServerDemo.Models;

public sealed class OAuthErrorResponseModel
{
    [JsonPropertyName("error")]
    public required string Error { get; set; }

    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; set; }
}
