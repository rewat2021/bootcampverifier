using System;
using System.Collections.Generic;

namespace VerifierAPI.Databases;

public partial class Dbverifierresponse
{
    public int Id { get; set; }

    public string SessionId { get; set; } = null!;

    public string VpToken { get; set; } = null!;

    public string? VcPayload { get; set; }

    public string? PresentationSubmission { get; set; }

    public string? ResponseCode { get; set; }

    public DateTime ReceivedAt { get; set; }

    public virtual Dbverifiersession Session { get; set; } = null!;
}
