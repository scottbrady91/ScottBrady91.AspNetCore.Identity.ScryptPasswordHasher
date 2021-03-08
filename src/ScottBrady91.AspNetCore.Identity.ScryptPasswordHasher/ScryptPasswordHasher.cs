using System;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Scrypt;

namespace ScottBrady91.AspNetCore.Identity
{
    /// <summary>
    /// ASP.NET Core Identity password hasher using the scrypt password hashing algorithm.
    /// </summary>
    /// <typeparam name="TUser">your ASP.NET Core Identity user type (e.g. IdentityUser). User is not used by this implementation</typeparam>
    public class ScryptPasswordHasher<TUser> : IPasswordHasher<TUser> where TUser : class
    {
        private readonly ScryptPasswordHasherOptions options;

        /// <summary>
        /// Creates a new ScryptPasswordHasher.
        /// </summary>
        /// <param name="optionsAccessor">optional ScryptPasswordHasherOptions</param>
        public ScryptPasswordHasher(IOptions<ScryptPasswordHasherOptions> optionsAccessor = null)
        {
            options = optionsAccessor?.Value ?? new ScryptPasswordHasherOptions();
        }

        /// <summary>
        /// Hashes a password using scrypt.
        /// </summary>
        /// <param name="user">not used for this implementation</param>
        /// <param name="password">plaintext password</param>
        /// <returns>hashed password</returns>
        /// <exception cref="ArgumentNullException">missing plaintext password</exception>
        public virtual string HashPassword(TUser user, string password)
        {
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));

            var encoder = new ScryptEncoder(options.IterationCount, options.BlockSize, options.ThreadCount);
            return encoder.Encode(password);
        }

        /// <summary>
        /// Verifies a plaintext password against a stored hash.
        /// </summary>
        /// <param name="user">not used for this implementation</param>
        /// <param name="hashedPassword">the stored, hashed password</param>
        /// <param name="providedPassword">the plaintext password to verify against the stored hash</param>
        /// <returns>If the password matches the stored password</returns>
        /// <exception cref="ArgumentNullException">missing plaintext password or hashed password</exception>

        public virtual PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
        {
            if (string.IsNullOrWhiteSpace(hashedPassword)) throw new ArgumentNullException(nameof(hashedPassword));
            if (string.IsNullOrWhiteSpace(providedPassword)) throw new ArgumentNullException(nameof(providedPassword));

            var encoder = new ScryptEncoder();
            var isValid = encoder.Compare(providedPassword, hashedPassword);

            return isValid ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;
        }
    }
}