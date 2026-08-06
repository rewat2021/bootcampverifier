using System.ComponentModel.DataAnnotations;

namespace VerifierAPI.Models
{
    public class AuthenUser
    {
        [Required(ErrorMessage = "กรุณากรอก Username")]
        public string username { get; set; } = string.Empty;

        [Required(ErrorMessage = "กรุณากรอก Password")]
        public string password { get; set; } = string.Empty;
    }

    public class Register
	{
        public string UnitId { get; set; }
        public string Contact { get; set; }
        public string RegName { get; set; }
        public ulong IsIssuer { get; set; }
        public ulong IsHolder { get; set; }
        public ulong IsVerifier { get; set; }
        public ulong IsAdmin { get; set; }

    }
}
