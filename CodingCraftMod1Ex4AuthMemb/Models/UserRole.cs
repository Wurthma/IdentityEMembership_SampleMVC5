using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace CodingCraftMod1Ex4Auth.Models
{
    public class UserRole
    {
        [Key]
        public Guid UserRoleId { get; set; }
        public Guid CustomUserId { get; set; }
        public Guid RoleId { get; set; }

        [DisplayName("Usuário")]
        public virtual CustomUser CustomUser { get; set; }
        [DisplayName("Grupo")]
        public virtual Role Role { get; set; }

        [DisplayName("Última Modificação")]
        public DateTime LastModified { get; set; }
        [DisplayName("Data de Criação")]
        public DateTime CreatedOn { get; set; }
    }
}