using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace CodingCraftMod1Ex4Auth.ViewModels
{
    public class RegisterViewModel
    {
        [Required]
        [EmailAddress]
        [DisplayName("Usuário")]
        public string UserName { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "O campo {0} deve ter no mínimo {2} caracteres.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [DisplayName("Senha")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [DisplayName("Confirmar Senha")]
        [Compare("Password", ErrorMessage = "A senha e a confirmação da senha não são iguais.")]
        public string ConfirmPassword { get; set; }
    }
}