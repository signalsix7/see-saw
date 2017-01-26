using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SSO
{

    public class MyUser
    {
        public string Subject { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }

        public List<Claim> Claims { get; set; }
    }

    public class MyUserManager
    {
        public Task<MyUser> FindBySubjectAsync(string subject)
        {
            //This is where you would do a database call in real world scenario

            //var context = new ApplicationContext();
            //var user = context.MyUsers.SingleOrDefaultAsync(x => x.Username == username)
            var user = GetUsers().SingleOrDefault(x => x.Subject == subject);

            return Task.FromResult(user);
        }

        public Task<bool> CheckPasswordAsync(MyUser user, string password)
        {
            //This is where you call a hashing method to verify password
            //var isPasswordMatch = MyPasswordHasher.VerifyHashedPassword(user.PasswordHash, password);

            if (user.Password == password)
                return Task.FromResult(true);

            return Task.FromResult(false);
        }

        private List<MyUser> GetUsers()
        {
            return new List<MyUser>
            {
                new MyUser
                {
                    Subject = "1",
                    UserName = "alice",
                    Password = "password",

                    Claims = new List<Claim>
                    {
                        new Claim(JwtClaimTypes.Name, "Alice"),
                        new Claim(JwtClaimTypes.Email, "alice@company.com"),
                        new Claim("flex_roles", "peadmin pnowadmin cashier"),
                        new Claim("digital_roles", "")
                    }

                },
                new MyUser
                {
                    Subject = "2",
                    UserName = "bob",
                    Password = "password",

                    Claims = new List<Claim>
                    {
                        new Claim(JwtClaimTypes.Name, "Bob"),
                        new Claim(JwtClaimTypes.Email, "bob@company.com"),
                        new Claim("flex_roles", "cashier"),
                        new Claim("digital_roles", "maintenance")
                    }
                }
            };
            //var users = new List<MyUser>();

            //users.Add(new MyUser { UserName = "alice", Password = "Bunny11!" });
            //users.Add(new MyUser { UserName = "bob", Password = "Bunny11!" });
            //users.Add(new MyUser { UserName = "eve", Password = "Bunny11!" });

            //return users;
        }

        public Task<List<Claim>> GetClaimsAsync(MyUser user)
        {
            //Database call to get calims if needed
            var claims = new List<Claim>();
            claims.AddRange(user.Claims);// (new Claim("accountnumber", "12345"));

            return Task.FromResult(claims);
        }

    }

    //public class ResourceOwnerPasswordValidator : IResourceOwnerPasswordValidator
    //{
    //    private MyUserManager _myUserManager { get; set; }
    //    public ResourceOwnerPasswordValidator()
    //    {
    //        _myUserManager = new MyUserManager();
    //    }

    //    //public async Task<CustomGrantValidationResult> ValidateAsync(string userName, string password, ValidatedTokenRequest request)
    //    //{
    //    //    var user = await _myUserManager.FindByNameAsync(userName);
    //    //    if (user != null && await _myUserManager.CheckPasswordAsync(user, password))
    //    //    {
    //    //        return new CustomGrantValidationResult(user.UserName, "password");
    //    //    }
    //    //    return new CustomGrantValidationResult("Invalid username or password");
    //    //}

    //    //public async Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
    //    //{

    //    //    var user = await _myUserManager.FindByNameAsync(context.UserName);
    //    //    if (user != null && await _myUserManager.CheckPasswordAsync(user, context.Password))
    //    //    {
    //    //        return new GrantValidationResult(subject: "818727", authenticationMethod: "custom");
    //    //    }
    //    //    return new GrantValidationResult(TokenRequestErrors.InvalidGrant, "invalid custom credential");

    //    //}
    //}



    public class ProfileService : IProfileService
    {
        MyUserManager _myUserManager;
        public ProfileService()
        {
            _myUserManager = new MyUserManager();
        }

        public async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var sub = context.Subject.FindFirst("sub")?.Value;
            if (sub != null)
            {
                var user = await _myUserManager.FindBySubjectAsync(sub);
                var cp = await getClaims(user);

                var claims = cp.Claims;
                //if (//context.AllClaimsRequested == false ||
                //    (context.RequestedClaimTypes != null && context.RequestedClaimTypes.Any()))
                //{
                //    claims = claims.Where(x => context.RequestedClaimTypes.Contains(x.Type)).ToArray().AsEnumerable();
                //}

                context.IssuedClaims = claims.ToList();
            }
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            return Task.FromResult(0);
        }

        private async Task<ClaimsPrincipal> getClaims(MyUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var id = new ClaimsIdentity();
            id.AddClaim(new Claim(JwtClaimTypes.PreferredUserName, user.UserName));

            id.AddClaims(await _myUserManager.GetClaimsAsync(user));

            return new ClaimsPrincipal(id);
        }

    }

    public class Config
    {
        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new List<ApiResource>
            {
                new ApiResource("api1", "My API")
            };
        }

        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            var customProfile = new IdentityResource(
            name: "custom.profile",
            displayName: "Custom profile",
            claimTypes: new[] { "name", "email", "flex_roles", "digital_roles" });



            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email(),
                 customProfile

            };
        }


        public static IEnumerable<Client> GetClients()
        {
            return new List<Client>
            {
                new Client
                {
                    ClientId = "client",

                    // no interactive user, use the clientid/secret for authentication
                    AllowedGrantTypes = GrantTypes.ClientCredentials,

                    // secret for authentication
                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    },

                    // scopes that client has access to
                    AllowedScopes = { "api1" }
                },

                new Client
                {
                    ClientId = "ro.client",
                    AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,

                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    },
                    AllowedScopes = { "api1" }
                },
                // OpenID Connect implicit flow client (MVC)
                new Client
                {
                    ClientId = "beanweasel",
                    ClientName = "Project Bean Weasel",
                    AllowedGrantTypes = GrantTypes.HybridAndClientCredentials,
                    RequireConsent = false,
                    
                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    },

                    // where to redirect to after login
                    RedirectUris = { "http://localhost:5002/signin-oidc",  "http://localhost:5004/signin-oidc" },

                    // where to redirect to after logout
                    PostLogoutRedirectUris = { "http://localhost:5002/signout-callback-oidc", "http://localhost:5004/signout-callback-oidc" },

                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "api1"
                    },

                    AllowOfflineAccess = true
                }

            };
        }

        //public static List<InMemoryUser> GetUsers()
        //{
        //    return new List<InMemoryUser>
        //    {
        //        new InMemoryUser
        //        {
        //            Subject = "1",
        //            Username = "alice",
        //            Password = "password",

        //            Claims = new []
        //            {
        //                new Claim(JwtClaimTypes.Name, "Alice"),
        //                new Claim(JwtClaimTypes.Email, "alice@company.com"),
        //                new Claim("flex_roles", "Admin")
        //            }

        //        },
        //        new InMemoryUser
        //        {
        //            Subject = "2",
        //            Username = "bob",
        //            Password = "password",

        //             Claims = new []
        //            {
        //                new Claim(JwtClaimTypes.Name, "Bob"),
        //                new Claim(JwtClaimTypes.Email, "bob@company.com"),
        //                new Claim("flex_roles", "FLEX_Admin")
        //            }
        //        }
        //    };
        //}


    }
}
