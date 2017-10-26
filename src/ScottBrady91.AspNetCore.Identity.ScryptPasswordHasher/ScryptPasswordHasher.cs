using System;
using Microsoft.AspNetCore.Identity;
using Scrypt;

namespace ScottBrady91.AspNetCore.Identity
{
    public class ScryptPasswordHasher<TUser> : IPasswordHasher<TUser> where TUser : class
    {
        public string HashPassword(TUser user, string password)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));

            var encoder = new ScryptEncoder();
            return encoder.Encode(password);
        }

        public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
        {
            if (hashedPassword == null) throw new ArgumentNullException(nameof(hashedPassword));
            if (providedPassword == null) throw new ArgumentNullException(nameof(providedPassword));

            var encoder = new ScryptEncoder();
            var isValid = encoder.Compare(providedPassword, hashedPassword);

            return isValid ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;
        }
    }
}