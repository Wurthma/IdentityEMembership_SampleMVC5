using CodingCraftMod1Ex4Auth.Infrastructure.CustomMembership;
using CodingCraftMod1Ex4Auth.Infrastructure.Helpers;
using CodingCraftMod1Ex4Auth.Models;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Configuration.Provider;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web.Configuration;
using System.Web.Security;
using WebMatrix.WebData;

namespace CodingCraftMod1Ex4Auth.Infrastructure.Membership
{
    public class CustomMembershipProvider : ExtendedMembershipProvider
    {

        #region Class Variables
        private string connectionString;
        private string applicationName;
        private bool enablePasswordReset;
        private bool enablePasswordRetrieval;
        private bool requiresQuestionAndAnswer;
        private bool requiresUniqueEmail;
        private int maxInvalidPasswordAttempts;
        private int passwordAttemptWindow;
        private MembershipPasswordFormat passwordFormat;
        private int minRequiredNonAlphanumericCharacters;
        private int minRequiredPasswordLength;
        private string passwordStrengthRegularExpression;
        private MachineKeySection machineKey; //Used when determining encryption key values.

        #endregion

        public override string ApplicationName
        {
            get { return applicationName; }
            set { applicationName = value; }
        }

        public override bool EnablePasswordReset
        {
            get { return enablePasswordReset; }
        }

        public override bool EnablePasswordRetrieval
        {
            get { return enablePasswordRetrieval; }
        }

        public override bool RequiresQuestionAndAnswer
        {
            get { return requiresQuestionAndAnswer; }
        }

        public override bool RequiresUniqueEmail
        {
            get { return requiresUniqueEmail; }
        }

        public override int MaxInvalidPasswordAttempts
        {
            get { return maxInvalidPasswordAttempts; }
        }

        public override int PasswordAttemptWindow
        {
            get { return passwordAttemptWindow; }
        }

        public override MembershipPasswordFormat PasswordFormat
        {
            get { return passwordFormat; }
        }

        public override int MinRequiredNonAlphanumericCharacters
        {
            get { return minRequiredNonAlphanumericCharacters; }
        }

        public override int MinRequiredPasswordLength
        {
            get { return minRequiredPasswordLength; }
        }

        public override string PasswordStrengthRegularExpression
        {
            get { return passwordStrengthRegularExpression; }
        }

        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
            {
                string configPath = "~/web.config";
                Configuration NexConfig = WebConfigurationManager.OpenWebConfiguration(configPath);
                MembershipSection section = (MembershipSection)NexConfig.GetSection("system.web/membership");
                ProviderSettingsCollection settings = section.Providers;
                NameValueCollection membershipParams = settings[section.DefaultProvider].Parameters;
                config = membershipParams;
            }

            if (name == null || name.Length == 0)
            {
                name = "CustomMembershipProvider";
            }

            if (String.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "Custom Membership Provider");
            }

            //Initialize the abstract base class.
            base.Initialize(name, config);

            applicationName = GetConfigValue(config["applicationName"], System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
            maxInvalidPasswordAttempts = Convert.ToInt32(GetConfigValue(config["maxInvalidPasswordAttempts"], "5"));
            passwordAttemptWindow = Convert.ToInt32(GetConfigValue(config["passwordAttemptWindow"], "10"));
            minRequiredNonAlphanumericCharacters = Convert.ToInt32(GetConfigValue(config["minRequiredAlphaNumericCharacters"], "1"));
            minRequiredPasswordLength = Convert.ToInt32(GetConfigValue(config["minRequiredPasswordLength"], "7"));
            passwordStrengthRegularExpression = Convert.ToString(GetConfigValue(config["passwordStrengthRegularExpression"], String.Empty));
            enablePasswordReset = Convert.ToBoolean(GetConfigValue(config["enablePasswordReset"], "true"));
            enablePasswordRetrieval = Convert.ToBoolean(GetConfigValue(config["enablePasswordRetrieval"], "true"));
            requiresQuestionAndAnswer = Convert.ToBoolean(GetConfigValue(config["requiresQuestionAndAnswer"], "false"));
            requiresUniqueEmail = Convert.ToBoolean(GetConfigValue(config["requiresUniqueEmail"], "true"));

            string temp_format = config["passwordFormat"];
            if (temp_format == null)
            {
                temp_format = "Hashed";
            }

            switch (temp_format)
            {
                case "Hashed":
                    passwordFormat = MembershipPasswordFormat.Hashed;
                    break;
                case "Encrypted":
                    passwordFormat = MembershipPasswordFormat.Encrypted;
                    break;
                case "Clear":
                    passwordFormat = MembershipPasswordFormat.Clear;
                    break;
                default:
                    throw new ProviderException("Password format not supported.");
            }

            ConnectionStringSettings ConnectionStringSettings = ConfigurationManager.ConnectionStrings[config["connectionStringName"]];

            if ((ConnectionStringSettings == null) || (ConnectionStringSettings.ConnectionString.Trim() == String.Empty))
            {
                throw new ProviderException("Connection string cannot be blank.");
            }

            connectionString = ConnectionStringSettings.ConnectionString;

            //Get encryption and decryption key information from the configuration.
            System.Configuration.Configuration cfg = WebConfigurationManager.OpenWebConfiguration(System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
            machineKey = cfg.GetSection("system.web/machineKey") as MachineKeySection;

            if (machineKey.ValidationKey.Contains("AutoGenerate"))
            {
                if (PasswordFormat != MembershipPasswordFormat.Clear)
                {
                    throw new ProviderException("Hashed or Encrypted passwords are not supported with auto-generated keys.");
                }
            }
        }

        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            using (var context = new CodingCraftMod1Ex4AuthMembershipContext())
            {
                //Criptografa o password antes de fazer a comparação
                string hashedPassword = PasswordsHelper.EncodePassword(oldPassword, MembershipPasswordFormat.Hashed);
                var membershipUser = context.Memberships.Where(u => u.CustomUser.Name == username).SingleOrDefault();
                if (CheckPassword(hashedPassword, membershipUser.Password))
                {
                    membershipUser.Password = PasswordsHelper.EncodePassword(newPassword, MembershipPasswordFormat.Hashed);
                    context.SaveChanges();
                    return true;
                }
                return false;
            }
        }

        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            throw new NotImplementedException();
        }

        public override bool ConfirmAccount(string accountConfirmationToken)
        {
            throw new NotImplementedException();
        }

        public override bool ConfirmAccount(string userName, string accountConfirmationToken)
        {
            throw new NotImplementedException();
        }

        public override string CreateAccount(string userName, string password, bool requireConfirmationToken)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Createa MembershipUser.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="email"></param>
        /// <param name="passwordQuestion"></param>
        /// <param name="passwordAnswer"></param>
        /// <param name="isApproved"></param>
        /// <param name="providerUserKey"></param>
        /// <param name="status"></param>
        /// <returns></returns>
        public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
        {
            ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(username, password, true);

            OnValidatingPassword(args);

            if (args.Cancel)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            if ((RequiresUniqueEmail && (GetUserNameByEmail(email) != String.Empty)))
            {
                status = MembershipCreateStatus.DuplicateEmail;
                return null;
            }

            MembershipUser membershipUser = GetUser(username, false);

            if (membershipUser == null)
            {
                try
                {
                    using (var context = new CodingCraftMod1Ex4AuthMembershipContext())
                    {
                        CustomUser user = new CustomUser();
                        user.Name = username;
                        context.CustomUsers.Add(user);
                        context.SaveChanges();

                        var membership = new Models.Membership();
                        membership.CustomUser = user;
                        membership.Password = EncodePassword(password);

                        context.Memberships.Add(membership);
                        context.SaveChanges();

                        status = MembershipCreateStatus.Success;

                        return GetUser(username, false);
                    }

                }
                catch
                {
                    status = MembershipCreateStatus.ProviderError;
                }
            }
            else
            {
                status = MembershipCreateStatus.DuplicateUserName;
            }

            return null;
        }


        public override string CreateUserAndAccount(string userName, string password, bool requireConfirmation, IDictionary<string, object> values)
        {
            ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(userName, password, true);

            OnValidatingPassword(args);

            if (args.Cancel)
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.InvalidPassword);
            }

            CustomMembershipUser CustomMembershipUser = GetUser(userName);

            if (CustomMembershipUser == null)
            {
                using (var context = new CodingCraftMod1Ex4AuthMembershipContext())
                {
                    CustomUser user = new CustomUser();
                    user.CustomUserId = Guid.NewGuid();
                    user.Name = userName;
                    user.CreatedOn = user.LastModified = DateTime.Now;
                    context.CustomUsers.Add(user);
                    context.SaveChanges();

                    var membership = new Models.Membership();

                    membership.MembershipId = Guid.NewGuid();
                    membership.CustomUser = user;
                    membership.LastModified = membership.CreatedOn = DateTime.Now;
                    membership.Password = PasswordsHelper.EncodePassword(password, MembershipPasswordFormat.Hashed);
                    context.Memberships.Add(membership);
                    context.SaveChanges();

                    var userRoles = new UserRole();

                    userRoles.UserRoleId = Guid.NewGuid();
                    userRoles.CustomUserId = user.CustomUserId;
                    userRoles.RoleId = context.Roles.Where(r => r.Name == "Padrao").SingleOrDefault().RoleId;
                    userRoles.LastModified = DateTime.Now;
                    userRoles.CreatedOn = DateTime.Now;
                    context.UserRoles.Add(userRoles);
                    context.SaveChanges();

                    return MembershipCreateStatus.Success.ToString();
                }
            }
            else
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.DuplicateUserName);
            }
        }

        public override bool DeleteAccount(string userName)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Delete user
        /// </summary>
        /// <param name="username"></param>
        /// <param name="deleteAllRelatedData"></param>
        /// <returns></returns>
        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            bool ret = false;

            using (var context = new CodingCraftMod1Ex4AuthMembershipContext())
            {
                try
                {
                    CustomUser user = context.CustomUsers.Where(u => u.Name == username).SingleOrDefault();

                    if (user != null)
                    {
                        context.CustomUsers.Remove(user);
                        context.SaveChanges();

                        ret = true;
                    }
                }
                catch
                {
                    ret = false;
                }
            }

            return ret;
        }

        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotImplementedException();
        }

        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotImplementedException();
        }

        public override string GeneratePasswordResetToken(string userName, int tokenExpirationInMinutesFromNow)
        {
            throw new NotImplementedException();
        }

        public override ICollection<OAuthAccountData> GetAccountsForUser(string userName)
        {
            throw new NotImplementedException();
        }

        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotImplementedException();
        }

        public override DateTime GetCreateDate(string userName)
        {
            throw new NotImplementedException();
        }

        public override DateTime GetLastPasswordFailureDate(string userName)
        {
            throw new NotImplementedException();
        }

        public override int GetNumberOfUsersOnline()
        {
            throw new NotImplementedException();
        }

        public override string GetPassword(string username, string answer)
        {
            using (var context = new CodingCraftMod1Ex4AuthMembershipContext())
            {
                try
                {
                    var pass = context.Memberships.Where(m => m.CustomUser.Name == username).SingleOrDefault().Password;

                    if (!string.IsNullOrWhiteSpace(pass))
                        return UnEncodePassword(pass);
                }
                catch (Exception)
                {
                    throw;
                }
            }
            return null;
        }

        public override DateTime GetPasswordChangedDate(string userName)
        {
            throw new NotImplementedException();
        }

        public override int GetPasswordFailuresSinceLastSuccess(string userName)
        {
            throw new NotImplementedException();
        }

        public CustomMembershipUser GetUser(string username)
        {
            CustomMembershipUser CustomMembershipUser = null;
            using (var context = new CodingCraftMod1Ex4AuthMembershipContext())
            {
                try
                {
                    CustomUser user = context.CustomUsers.Where(u => u.Name == username).SingleOrDefault();

                    if (user != null)
                    {
                        CustomMembershipUser = new CustomMembershipUser(
                            this.Name,
                            user.Name,
                            user.CustomUserId,
                            user.Name,
                            "",
                            "",
                            true,
                            false,
                            user.CreatedOn,
                            DateTime.Now,
                            DateTime.Now,
                            default(DateTime),
                            default(DateTime),
                            user.Name);
                    }
                }
                catch { }
            }

            return CustomMembershipUser;
        }

        /// <summary>
        /// Get MembershipUser.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="userIsOnline"></param>
        /// <returns></returns>
        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            MembershipUser membershipUser = null;
            using (var context = new CodingCraftMod1Ex4AuthMembershipContext())
            {
                try
                {
                    CustomUser user = context.CustomUsers.Where(u => u.Name == username).SingleOrDefault();

                    if (user != null)
                    {
                        membershipUser = new MembershipUser(this.Name,
                            user.Name,
                            user.CustomUserId,
                            user.Name,
                            "",
                            "",
                            true,
                            false,
                            user.CreatedOn,
                            DateTime.Now,
                            DateTime.Now,
                            default(DateTime),
                            default(DateTime));
                    }
                }
                catch { }
            }

            return membershipUser;
        }

        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            throw new NotImplementedException();
        }

        public override int GetUserIdFromPasswordResetToken(string token)
        {
            throw new NotImplementedException();
        }

        public override string GetUserNameByEmail(string email)
        {
            throw new NotImplementedException();
        }

        public override bool IsConfirmed(string userName)
        {
            throw new NotImplementedException();
        }

        public override string ResetPassword(string username, string answer)
        {
            throw new NotImplementedException();
        }

        public override bool ResetPasswordWithToken(string token, string newPassword)
        {
            throw new NotImplementedException();
        }

        public override bool UnlockUser(string userName)
        {
            throw new NotImplementedException();
        }

        public override void UpdateUser(MembershipUser user)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Validate user.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public override bool ValidateUser(string username, string password)
        {
            bool isValid = false;

            using (var context = new CodingCraftMod1Ex4AuthMembershipContext())
            {
                try
                {
                    CustomUser user = context.CustomUsers.Where(u => u.Name == username).SingleOrDefault();

                    if (user != null)
                    {
                        string storedPassword = user.Memberships.First().Password;
                        if (CheckPassword(password, storedPassword))
                        {
                            isValid = true;
                        }
                    }
                }
                catch
                {
                    isValid = false;
                }
            }
            return isValid;
        }

        /// <summary>
        /// Get config value.
        /// </summary>
        /// <param name="configValue"></param>
        /// <param name="defaultValue"></param>
        /// <returns></returns>
        private string GetConfigValue(string configValue, string defaultValue)
        {
            if (String.IsNullOrEmpty(configValue))
            {
                return defaultValue;
            }

            return configValue;
        }

        /// <summary>
        /// Encode password.
        /// </summary>
        /// <param name="password">Password.</param>
        /// <returns>Encoded password.</returns>
        private string EncodePassword(string password)
        {
            string encodedPassword = password;

            switch (PasswordFormat)
            {
                case MembershipPasswordFormat.Clear:
                    break;
                case MembershipPasswordFormat.Encrypted:
                    byte[] encryptedPass = EncryptPassword(Encoding.Unicode.GetBytes(password));
                    encodedPassword = Convert.ToBase64String(encryptedPass);
                    break;
                case MembershipPasswordFormat.Hashed:
                    HMACSHA1 hash = new HMACSHA1();
                    hash.Key = PasswordsHelper.HexToByte(machineKey.ValidationKey);
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
        private string UnEncodePassword(string encodedPassword)
        {
            string password = encodedPassword;

            switch (PasswordFormat)
            {
                case MembershipPasswordFormat.Clear:
                    break;
                case MembershipPasswordFormat.Encrypted:
                    password =
                      Encoding.Unicode.GetString(DecryptPassword(Convert.FromBase64String(password)));
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
        /// Check the password format based upon the MembershipPasswordFormat.
        /// </summary>
        /// <param name="password">Password</param>
        /// <param name="dbpassword"></param>
        /// <returns></returns>
        /// <remarks></remarks>
        private bool CheckPassword(string password, string dbpassword)
        {
            string pass1 = password;
            string pass2 = dbpassword;

            switch (PasswordFormat)
            {
                case MembershipPasswordFormat.Encrypted:
                    pass2 = UnEncodePassword(dbpassword);
                    break;
                case MembershipPasswordFormat.Hashed:
                    pass1 = EncodePassword(password);
                    break;
                default:
                    break;
            }

            if (pass1 == pass2)
            {
                return true;
            }

            return false;
        }
    }
}