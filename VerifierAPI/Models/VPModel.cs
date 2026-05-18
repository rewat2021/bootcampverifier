using Newtonsoft.Json;
using System.Text.Json.Serialization;
using static VerifierAPI.Controllers.VerifierController;

namespace VerifierAPI.Models
{
    public class VPModel
    {
    }

    public class JwtModel
    {
        public string Header { get; set; }
        public string Payload { get; set; }
        public string Signature { get; set; }
    }

    public class Root
    {
        [JsonProperty("sub")]
        public string Sub { get; set; }

        [JsonProperty("nbf")]
        public long Nbf { get; set; }

        [JsonProperty("iat")]
        public long Iat { get; set; }

        [JsonProperty("jti")]
        public string Jti { get; set; }

        [JsonProperty("iss")]
        public string Iss { get; set; }

        [JsonProperty("nonce")]
        public string Nonce { get; set; }

        [JsonProperty("aud")]
        public string Aud { get; set; }

        [JsonProperty("vp")]
        public VerifiablePresentation Vp { get; set; }
    }

    public class VerifiablePresentation
    {
        [JsonProperty("@context")]
        public List<string> Context { get; set; }

        [JsonProperty("type")]
        public List<string> Type { get; set; }

        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("holder")]
        public string Holder { get; set; }

        [JsonProperty("verifiableCredential")]
        public List<string> VerifiableCredential { get; set; }
    }

    public class PresentationOffer
    {
        public string client_id { get; set; }
        public string client_id_scheme { get; set; }
        public string response_uri { get; set; }
        public string response_type { get; set; }

        public object? dcql_query { get; set; }

        public string nonce { get; set; }
        public string response_mode { get; set; }
        public string state { get; set; }
        public string client_metadata { get; set; }
        //public string presentation_submission { get; set; }
        //public string presentation_definition_uri { get; set; }
    }

    public class GenerateVpQrResponse
    {
        public string AuthorizationRequestUri { get; set; } = string.Empty;
        public string QrText { get; set; } = string.Empty;
        public string? QrImageBase64 { get; set; }
        public string State { get; set; } = string.Empty;
        public string Nonce { get; set; } = string.Empty;
    }

    public enum DocumentType
    {
        Transcript,
        IDCard,
        DriverLicense,
        Bootcamp
    }

    public class GenerateVpQrRequest
    {
        public DocumentType DocumentType { get; set; }
    }

    public class PresentVPAuthorizationRequest
    {
        public string response_type { get; set; }
        public string? client_id { get; set; }
        public string? response_mode { get; set; }
        public string? state { get; set; }
        public string? code { get; set; }
        public string? presentation_definition_uri { get; set; }
        public string? presentation_submission { get; set; }
        public string? client_id_scheme { get; set; }
        public string? client_metadata { get; set; }
        public string? nonce { get; set; }
        public string response_uri { get; set; }
        public string? id_token { get; set; }
        public string? iss { get; set; }
        public string? presentation_definition { get; set; }
        public string? scope { get; set; }

    }

    public class PresentVPAuthorizationResponse
    {
        public string vp_token { get; set; }
        public string presentation_submission { get; set; }
        public string? state { get; set; }
        public string? code { get; set; }
        public string? id_token { get; set; }
        public string? iss { get; set; }
    }
    public class PresentVPAuthorizationIdTokenResponse
    {
        public string code { get; set; }
        public string state { get; set; }
    }

    public class PresentVPTokenExchangeRequest
    {
        public string grant_type { get; set; }
        public string code { get; set; }
        public string client_id { get; set; }
        public string? presentation_definition { get; set; }
        public string? presentation_definition_uri { get; set; }
    }

    public class PresentVPTokenExchangeResponse
    {
        public string vp_token { get; set; }
        public string presentation_submission { get; set; }
        public string grant_type { get; set; }
        public string code { get; set; }
        public string redirect_uri { get; set; }
        public string client_id { get; set; }
    }


    public class PresentationDefinition
    {
        public string id { get; set; }

        [JsonProperty("input_descriptors")]
        public List<InputDescriptor> InputDescriptors { get; set; }
    }

    public class InputDescriptor
    {
        public string id { get; set; }

        [JsonProperty("format")]
        public Format Format { get; set; }

        [JsonProperty("constraints")]
        public Constraints Constraints { get; set; }
    }

    public class Format
    {
        [JsonProperty("jwt_vc_json")]
        public JwtVcJson JwtVcJson { get; set; }
    }

    public class JwtVcJson
    {
        [JsonProperty("alg")]
        public List<string> Alg { get; set; }
    }

    public class Constraints
    {
        [JsonProperty("fields")]
        public List<Field> Fields { get; set; }
    }

    public class FieldFilter
    {
        [JsonProperty("type")]
        public string Type { get; set; }

        [JsonProperty("pattern")]
        public string Pattern { get; set; }
    }

    public class Field
    {
        [JsonProperty("path")]
        public List<string> Path { get; set; }

        [JsonProperty("filter")]
        public Filter Filter { get; set; }
    }

    public class Filter
    {
        [JsonPropertyName("type")]
        public string Type { get; set; }

        [JsonPropertyName("pattern")]
        public string Pattern { get; set; }
    }

    public class VpRequestSession
    {
        public string stateId { set; get; }
        public string nonce { get; set; }
    }
}
