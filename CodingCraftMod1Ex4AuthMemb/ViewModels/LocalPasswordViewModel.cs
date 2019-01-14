using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace CodingCraftMod1Ex4Auth.ViewModels
{
    public class LocalPasswordViewModel
    {
        [Required]
        [DataType(DataType.Password)]
        [DisplayName("CurrentPassword")]
        public string OldPassword { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "O campo {0} deve ter no mínimo {2} caracteres.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [DisplayName("NewPassword")]
        public string NewPassword { get; set; }

        [DataType(DataType.Password)]
        [DisplayName("ConfirmNewPassword")]
        [Compare("NewPassword", ErrorMessage = "Senha e confirmação não coincidem.")]
        public string ConfirmPassword { get; set; }
    }
}