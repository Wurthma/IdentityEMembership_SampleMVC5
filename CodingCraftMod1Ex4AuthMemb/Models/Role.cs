using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace CodingCraftMod1Ex4Auth.Models
{
    public class Role
    {
        [Key]
        public Guid RoleId { get; set; }

        [DisplayName("Nome")]
        [MaxLength(512)]
        public String Name { get; set; }

        [DisplayName("Usuários do Grupo")]
        public virtual ICollection<UserRole> UserRoles { get; set; }

        [DisplayName("Última Modificação")]
        public DateTime LastModified { get; set; }
        [DisplayName("Data de Criação")]
        public DateTime CreatedOn { get; set; }
    }
}