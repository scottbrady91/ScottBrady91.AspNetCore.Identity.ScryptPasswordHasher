using System;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Scrypt;
using Xunit;

namespace ScottBrady91.AspNetCore.Identity.ScryptPasswordHasher.Tests
{
    public class ScryptPasswordHasherTests
    {
        [Fact]
        public void HashPassword_WithDefaultSettings_ExpectVerifiableHash()
        {
            var password = Guid.NewGuid().ToString();

            var hasher = new ScryptPasswordHasher<string>();
            var hashedPassword = hasher.HashPassword("", password);

            var encoder = new ScryptEncoder();
            encoder.Compare(password, hashedPassword).Should().BeTrue();
        }
        
        [Fact]
        public void VerifyHashedPassword_WithDefaultSettings_ExpectSuccess()
        {
            var password = Guid.NewGuid().ToString();
            var encoder = new ScryptEncoder();
            var hashedPassword = encoder.Encode(password);

            var hasher = new ScryptPasswordHasher<string>();

            hasher.VerifyHashedPassword("", hashedPassword, password).Should().Be(PasswordVerificationResult.Success);
        }
        
        [Fact]
        public void VerifyHashedPassword_WhenSuppliedPasswordDoesNotMatch_ExpectFailure()
        {
            var password = Guid.NewGuid().ToString();
            var encoder = new ScryptEncoder();
            var hashedPassword = encoder.Encode(Guid.NewGuid().ToString());

            var hasher = new ScryptPasswordHasher<string>();

            hasher.VerifyHashedPassword("", hashedPassword, password).Should().Be(PasswordVerificationResult.Failed);
        }
    }
}