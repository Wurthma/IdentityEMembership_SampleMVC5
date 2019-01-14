using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace CodingCraftMod1Ex4Auth.Models
{
    public class CustomUser
    {
        [Key]
        public Guid CustomUserId { get; set; }

        [DisplayName("Nome de Usuário")]
        public String Name { get; set; }
        [DisplayName("Nome")]
        public String FirstName { get; set; }
        [DisplayName("Sobrenome")]
        public String LastName { get; set; }
        [DisplayName("Suspenso?")]
        [DefaultValue(false)]
        public Boolean Suspended { get; set; }

        public virtual ICollection<Membership> Memberships { get; set; }
        [DisplayName("Grupos do Usuário")]
        public virtual ICollection<UserRole> UserRoles { get; set; }

        [DisplayName("Última Modificação")]
        public DateTime LastModified { get; set; }
        [DisplayName("Data de Criação")]
        public DateTime CreatedOn { get; set; }
    }
}