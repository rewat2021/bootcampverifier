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

    // FEATURE (audit trail, 2026-08-15): this table already existed as unused
    // scaffolding (mapped in VerifierDbContext, real columns in the DB, but no
    // code ever wrote to it) — reused as the verification audit log instead of
    // adding a new table. These two columns are new; see
    // db/migrations/002_add_verifier_log_client_info.sql for the ALTER TABLE
    // that must be run against any existing database.
    public string? ClientIp { get; set; }

    public string? UserAgent { get; set; }
}
