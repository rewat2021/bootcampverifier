using System;
using System.Collections.Generic;

namespace VerifierAPI.Databases;

public partial class Dbverifierlog
{
    public int Id { get; set; }

    public string TeamId { get; set; } = null!;

    public string? PresentationId { get; set; }

    public string? HolderDid { get; set; }

    public string? IssuerDid { get; set; }

    public string? CredentialType { get; set; }

    public string Status { get; set; } = null!;

    public bool? Verified { get; set; }

    public string? ErrorCode { get; set; }

    public string? ErrorMessage { get; set; }

    public string? VpToken { get; set; }

    public string? Claims { get; set; }

    public string? PresentationSubmission { get; set; }

    public DateTime? CreatedAt { get; set; }
}
