using System;
using System.Collections.Generic;

namespace VerifierAPI.Databases;

public partial class Usednonce
{
    public string Nonce { get; set; } = null!;

    public DateTime UsedAt { get; set; }

    public DateTime ExpiredAt { get; set; }
}
