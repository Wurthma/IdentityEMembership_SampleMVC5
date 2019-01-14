using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace CodingCraftMod1Ex4Auth.Models
{
    public class Membership
    {
        [Key]
        public Guid MembershipId { get; set; }
        public Guid CustomUserId { get; set; }

        [DisplayName("Token de Confirmação")]
        public String ConfirmationToken { get; set; }
        [DisplayName("Confirmado?")]
        [DefaultValue(false)]
        public Boolean IsConfirmed { get; set; }
        [DisplayName("Última Falha de Senha")]
        public DateTime? LastPasswordFailureDate { get; set; }
        [DisplayName("Falhas de Senha desde Último Sucesso")]
        [DefaultValue(0)]
        public int PasswordFailuresSinceLastSuccess { get; set; }
        [DisplayName("Senha")]
        public String Password { get; set; }
        [DisplayName("Data da Última Alteração de Senha")]
        public DateTime? PasswordChangedDate { get; set; }
        [DisplayName("Token de Verificação de Senha")]
        public String PasswordVerificationToken { get; set; }
        [DisplayName("Data de Expiração do Token de Verificação de Senha")]
        public DateTime? PasswordVerificationTokenExpirationDate { get; set; }

        [DisplayName("Usuário")]
        public virtual CustomUser CustomUser { get; set; }

        [DisplayName("Última Modificação")]
        public DateTime LastModified { get; set; }
        [DisplayName("Data de Criação")]
        public DateTime CreatedOn { get; set; }
    }
}