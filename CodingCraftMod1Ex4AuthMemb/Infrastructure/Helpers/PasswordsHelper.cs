using System;
using System.Configuration.Provider;
using System.Security.Cryptography;
using System.Text;
using System.Web.Configuration;
using System.Web.Security;

namespace CodingCraftMod1Ex4Auth.Infrastructure.Helpers
{
    public static class PasswordsHelper
    {
        /// <summary>
        /// Encode password.
        /// </summary>
        /// <param name="password">Password.</param>
        /// <returns>Encoded password.</returns>
        public static string EncodePassword(string password, MembershipPasswordFormat passwordFormat)
        {
            MachineKeySection machineKey;
            string encodedPassword = password;

            System.Configuration.Configuration cfg = WebConfigurationManager.OpenWebConfiguration(System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
            machineKey = cfg.GetSection("system.web/machineKey") as MachineKeySection;

            if (machineKey.ValidationKey.Contains("AutoGenerate"))
            {
                if (passwordFormat != MembershipPasswordFormat.Clear)
                {
                    throw new ProviderException("Hashed or Encrypted passwords are not supported with auto-generated keys.");
                }
            }

            switch (passwordFormat)
            {
                case MembershipPasswordFormat.Clear:
                    break;
                case MembershipPasswordFormat.Encrypted:
                    // Problema: como EncryptPassword poderia ser usado aqui, se EncryptPassword pertence a MembershipProvider?
                    // byte[] encryptedPass = EncryptPassword(Encoding.Unicode.GetBytes(password));
                    // encodedPassword = Convert.ToBase64String(encryptedPass);
                    break;
                case MembershipPasswordFormat.Hashed:
                    HMACSHA1 hash = new HMACSHA1();
                    hash.Key = HexToByte(machineKey.ValidationKey);
                    encodedPassword =
                      Convert.ToBase64String(hash.ComputeHash(Encoding.Unicode.GetBytes(password)));
                    break;
                default:
                    throw new ProviderException("Unsupported password format.");
            }

            return encodedPassword;
        }

        /// <summary>
        /// UnEncode password.
        /// </summary>
        /// <param name="encodedPassword">Password.</param>
        /// <returns>Unencoded password.</returns>
        public static string UnEncodePassword(string encodedPassword, MembershipPasswordFormat passwordFormat)
        {
            string password = encodedPassword;

            switch (passwordFormat)
            {
                case MembershipPasswordFormat.Clear:
                    break;
                case MembershipPasswordFormat.Encrypted:
                    //password =
                    //  Encoding.Unicode.GetString(DecryptPassword(Convert.FromBase64String(password)));
                    break;
                case MembershipPasswordFormat.Hashed:
                    //HMACSHA1 hash = new HMACSHA1();
                    //hash.Key = HexToByte(machineKey.ValidationKey);
                    //password = Convert.ToBase64String(hash.ComputeHash(Encoding.Unicode.GetBytes(password)));

                    throw new ProviderException("Not implemented password format (HMACSHA1).");
                default:
                    throw new ProviderException("Unsupported password format.");
            }

            return password;
        }

        /// <summary>
        /// Converts a hexadecimal string to a byte array. Used to convert encryption key values from the configuration
        /// </summary>
        /// <param name="hexString"></param>
        /// <returns></returns>
        /// <remarks></remarks>
        public static byte[] HexToByte(string hexString)
        {
            byte[] returnBytes = new byte[hexString.Length / 2];
            for (int i = 0; i < returnBytes.Length; i++)
                returnBytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            return returnBytes;
        }
    }
}