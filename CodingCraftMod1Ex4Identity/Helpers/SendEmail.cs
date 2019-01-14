using CodingCraftMod1Ex4Identity.ViewModels;
using SendGrid.Helpers.Mail;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Net.Mime;
using System.Web;
using System.Web.Configuration;

namespace CodingCraftMod1Ex4Identity.Helpers
{
    public class SendEmail
    {
        public void Enviar(SendEmailViewModel email, bool html = false)
        {
            MailMessage mailMsg = new MailMessage();

            // To
            mailMsg.To.Add(new MailAddress(email.Destino));

            // From
            mailMsg.From = new MailAddress(email.Origem, WebConfigurationManager.AppSettings["ApplicationName"]);

            // Subject and multipart/alternative Body
            mailMsg.Subject = email.Assunto;
            if (!html)
            {
                mailMsg.AlternateViews.Add(AlternateView.CreateAlternateViewFromString(email.Mensagem, null, MediaTypeNames.Text.Plain));
            }
            else
            {
                mailMsg.AlternateViews.Add(AlternateView.CreateAlternateViewFromString(email.Mensagem, null, MediaTypeNames.Text.Html));
            }

            // Init SmtpClient and send
            SmtpClient smtpClient = new SmtpClient(email.SmptHost, email.SmptPort);
            NetworkCredential credentials = new NetworkCredential(email.Usuario, email.Senha);
            smtpClient.Credentials = credentials;

            smtpClient.Send(mailMsg);
        }
    }
}