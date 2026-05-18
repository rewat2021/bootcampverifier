using System;
using System.Collections.Generic;

namespace VerifierAPI.Databases;

public partial class Dbdocumenttype
{
    public Guid Id { get; set; }

    public string TypeId { get; set; } = null!;

    public string DocType { get; set; } = null!;

    public string Format { get; set; } = null!;

    public string VcType { get; set; } = null!;

    public string AlgValues { get; set; } = null!;

    public string? Endpoint { get; set; }

    public bool? IsActive { get; set; }

    public DateTime CreatedAt { get; set; }

    public DateTime UpdatedAt { get; set; }
}
