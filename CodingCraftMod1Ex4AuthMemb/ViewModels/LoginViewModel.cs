using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace CodingCraftMod1Ex4Auth.ViewModels
{
    public class LoginViewModel
    {
        [Required]
        [DisplayName("Usuário")]
        public string UserName { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [DisplayName("Senha")]
        public string Password { get; set; }

        [DisplayName("Lembrar-me")]
        public bool RememberMe { get; set; }
    }
}