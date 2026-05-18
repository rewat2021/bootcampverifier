using System;
using System.Collections.Generic;

namespace VerifierAPI.Databases;

public partial class Dbverifiersession
{
    public string Id { get; set; } = null!;

    public string DocTypeId { get; set; } = null!;

    public string State { get; set; } = null!;

    public string? ClientId { get; set; }

    public string? Nonce { get; set; }

    public string? Status { get; set; }

    public DateTime CreatedAt { get; set; }

    public DateTime ExpiresAt { get; set; }

    public DateTime? CompletedAt { get; set; }

    public virtual ICollection<Dbverificationresult> Dbverificationresults { get; set; } = new List<Dbverificationresult>();

    public virtual ICollection<Dbverifierresponse> Dbverifierresponses { get; set; } = new List<Dbverifierresponse>();
}
