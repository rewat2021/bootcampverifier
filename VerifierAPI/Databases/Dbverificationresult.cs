using System;
using System.Collections.Generic;

namespace VerifierAPI.Databases;

public partial class Dbverificationresult
{
    public string Id { get; set; } = null!;

    public string SessionId { get; set; } = null!;

    public ulong IsValid { get; set; }

    public string? HolderDid { get; set; }

    public string? CredentialFormat { get; set; }

    public ulong? NonceBound { get; set; }

    public ulong? AudienceBound { get; set; }

    public ulong? SignatureValid { get; set; }

    public ulong? NotRevoked { get; set; }

    public ulong? NotExpired { get; set; }

    public string? ClaimsJson { get; set; }

    public string? ErrorMessage { get; set; }

    public DateTime VerifiedAt { get; set; }

    public virtual Dbverifiersession Session { get; set; } = null!;
}
