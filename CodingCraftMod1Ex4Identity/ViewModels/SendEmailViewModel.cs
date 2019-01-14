using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace CodingCraftMod1Ex4Identity.ViewModels
{
    public class SendEmailViewModel
    {
        public string Origem { get; set; }
        public string Destino { get; set; }
        public string Assunto { get; set; }
        public string Mensagem { get; set; }
        public string Usuario { get; set; }
        public string Senha { get; set; }
        public string SmptHost { get; set; }
        public int SmptPort { get; set; }
    }
}