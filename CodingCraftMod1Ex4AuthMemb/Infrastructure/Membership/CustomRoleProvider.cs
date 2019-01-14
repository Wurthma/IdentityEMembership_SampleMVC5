using System;
using System.Collections.Specialized;
using System.Web.Security;
using CodingCraftMod1Ex4Auth.Models;
using System.Linq;
using System.Collections.Generic;

namespace CodingCraftMod1Ex4Auth.Infrastructure.CustomMembership
{
    public class CustomRoleProvider : RoleProvider
    {
        private string applicationName;

        public override string ApplicationName
        {
            get { return applicationName; }
            set { applicationName = value; }
        }

        /// <summary>
        /// Initialize.
        /// </summary>
        /// <param name="usernames"></param>
        /// <param name="roleNames"></param>
        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
            {
                throw new ArgumentNullException("config");
            }

            if (name == null || name.Length == 0)
            {
                name = "CustomRoleProvider";
            }

            if (String.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "Custom Role Provider");
            }

            //Initialize the abstract base class.
            base.Initialize(name, config);

            applicationName = GetConfigValue(config["applicationName"], System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
        }

        /// <summary>
        /// Add users to roles.
        /// </summary>
        /// <param name="usernames"></param>
        /// <param name="roleNames"></param>
        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            try
            {
                using (var context = new CodingCraftMod1Ex4AuthMembershipContext())
                {
                    foreach (string username in usernames)
                    {
                        // find each user in users table
                        CustomUser user = context.CustomUsers.Where(u => u.Name == username).FirstOrDefault();

                        if (user != null)
                        {
                            // find all roles that are contained in the roleNames
                            var AllDbRoles = context.Roles.ToList();

                            List<Role> UserRoles = new List<Role>();

                            foreach (var roleName in roleNames)
                            {
                                var role = context.Roles.SingleOrDefault(r => r.Name == roleName);

                                if (role == default(Role))
                                {
                                    throw new Exception("Role does not exist.");
                                }

                                UserRoles.Add(role);
                            }


                            if (UserRoles.Count > 0)
                            {
                                foreach (var role in UserRoles)
                                {
                                    if (!context.UserRoles.Where(ur => ur.CustomUserId == user.CustomUserId && ur.RoleId == role.RoleId).Any())
                                    {
                                        var userRole = new UserRole();
                                        userRole.UserRoleId = Guid.NewGuid();
                                        userRole.CustomUser = user;
                                        userRole.Role = role;
                                        context.UserRoles.Add(userRole);
                                        context.SaveChanges();
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        /// <summary>
        /// Create new role.
        /// </summary>
        /// <param name="roleName"></param>
        public override void CreateRole(string roleName)
        {
            try
            {
                if (!RoleExists(roleName))
                {
                    using (var context = new CodingCraftMod1Ex4AuthMembershipContext())
                    {
                        Role role = new Role();
                        role.RoleId = Guid.NewGuid();
                        role.Name = roleName;
                        context.Roles.Add(role);
                        context.SaveChanges();
                    }
                }
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        /// <summary>
        /// Delete role.
        /// </summary>
        /// <param name="roleName"></param>
        /// <param name="throwOnPopulatedRole"></param>
        /// <returns>true if role is successfully deleted</returns>
        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            using (var context = new CodingCraftMod1Ex4AuthMembershipContext())
            {
                try
                {
                    Role role = context.Roles.Where(r => r.Name == roleName).SingleOrDefault();

                    if (role != null)
                    {
                        context.Roles.Remove(role);
                        context.SaveChanges();
                        return true;
                    }
                }
                catch
                {
                    return false;
                }
            }

            return false;
        }

        /// <summary>
        /// Find users in role.
        /// </summary>
        /// <param name="roleName"></param>
        /// <param name="usernameToMatch"></param>
        /// <returns></returns>
        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            List<string> users = new List<string>();

            using (var context = new CodingCraftMod1Ex4AuthMembershipContext())
            {
                try
                {
                    var usersInRole = context.UserRoles.Where(ur => ur.Role.Name == roleName && ur.CustomUser.Name == usernameToMatch).ToList();

                    if (usersInRole != null)
                    {
                        foreach (var userInRole in usersInRole)
                        {
                            users.Add(userInRole.CustomUser.Name);
                        }
                    }
                }
                catch { }
            }

            return users.ToArray();
        }

        /// <summary>
        /// Get all roles.
        /// </summary>
        /// <returns></returns>
        public override string[] GetAllRoles()
        {
            List<string> roles = new List<string>();

            using (var context = new CodingCraftMod1Ex4AuthMembershipContext())
            {
                try
                {
                    var dbRoles = context.Roles.ToList();

                    foreach (var role in dbRoles)
                    {
                        roles.Add(role.Name);
                    }
                }
                catch { }
            }

            return roles.ToArray();
        }

        /// <summary>
        /// Get all roles for a specific user.
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        public override string[] GetRolesForUser(string username)
        {
            List<string> roles = new List<string>();

            using (var context = new CodingCraftMod1Ex4AuthMembershipContext())
            {
                try
                {
                    var dbRoles = context.UserRoles.Where(r => r.CustomUser.Name == username).ToList();

                    foreach (var role in dbRoles)
                    {
                        roles.Add(role.Role.Name);
                    }
                }
                catch { }
            }

            return roles.ToArray();
        }

        /// <summary>
        /// Get all users that belong to a role.
        /// </summary>
        /// <param name="roleName"></param>
        /// <returns></returns>
        public override string[] GetUsersInRole(string roleName)
        {
            List<string> users = new List<string>();

            using (var context = new CodingCraftMod1Ex4AuthMembershipContext())
            {
                try
                {
                    var usersInRole = context.UserRoles.Where(ur => ur.Role.Name == roleName).ToList();

                    if (usersInRole != null)
                    {
                        foreach (var userInRole in usersInRole)
                        {
                            users.Add(userInRole.CustomUser.Name);
                        }
                    }
                }
                catch { }
            }

            return users.ToArray();
        }

        /// <summary>
        /// Checks if user belongs to a given role.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="roleName"></param>
        /// <returns></returns>
        public override bool IsUserInRole(string username, string roleName)
        {
            using (var context = new CodingCraftMod1Ex4AuthMembershipContext())
            {
                try
                {
                    var usersInRole = context.UserRoles.SingleOrDefault(ur => ur.CustomUser.Name == username && ur.Role.Name == roleName);

                    if (usersInRole != default(UserRole))
                    {
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    throw ex;
                }
            }

            return false;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="usernames"></param>
        /// <param name="roleNames"></param>
        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            try
            {
                using (var context = new CodingCraftMod1Ex4AuthMembershipContext())
                {
                    foreach (string username in usernames)
                    {
                        // find each user in users table
                        CustomUser user = context.CustomUsers.Where(u => u.Name == username).SingleOrDefault();

                        if (user != null)
                        {
                            // find all roles that are contained in the roleNames
                            var AllDbRoles = context.Roles.ToList();

                            List<Role> RemoveRoles = new List<Role>();

                            foreach (var role in AllDbRoles)
                            {
                                foreach (string roleName in roleNames)
                                {
                                    if (role.Name == roleName)
                                    {
                                        RemoveRoles.Add(role);
                                        continue;
                                    }
                                }
                            }

                            if (RemoveRoles.Count > 0)
                            {
                                foreach (var role in RemoveRoles)
                                {
                                    UserRole userRole = context.UserRoles
                                                            .Where(ur => ur.CustomUserId == user.CustomUserId && ur.RoleId == role.RoleId)
                                                            .SingleOrDefault();

                                    if (userRole != null)
                                    {
                                        context.UserRoles.Remove(userRole);
                                        context.SaveChanges();
                                    }
                                }
                            }
                        }
                    }
                }
            }

            catch (Exception e)
            {
                throw e;
            }
        }

        /// <summary>
        /// Check if role exists.
        /// </summary>
        /// <param name="configValue"></param>
        /// <param name="defaultValue"></param>
        /// <returns></returns>
        public override bool RoleExists(string roleName)
        {
            using (var context = new CodingCraftMod1Ex4AuthMembershipContext())
            {
                // check if role exits
                return context.Roles.Any(r => r.Name == roleName);
            }
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
    }
}