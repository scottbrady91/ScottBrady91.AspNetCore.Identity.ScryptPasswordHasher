using System;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Scrypt;
using Xunit;

namespace ScottBrady91.AspNetCore.Identity.ScryptPasswordHasher.Tests
{
    public class ScryptPasswordHasherTests
    {
        private ScryptPasswordHasherOptions options = new ScryptPasswordHasherOptions();

        private ScryptPasswordHasher<string> CreateSut() =>
            new ScryptPasswordHasher<string>(
                options != null ? new OptionsWrapper<ScryptPasswordHasherOptions>(options) : null);
        
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public void HashPassword_WhenPasswordIsNullOrWhitespace_ExpectArgumentNullException(string password)
        {
            var sut = CreateSut();
            Assert.Throws<ArgumentNullException>(() => sut.HashPassword(null, password));
        }
        
        [Fact]
        public void HashPassword_WithDefaultSettings_ExpectVerifiableHash()
        {
            var password = Guid.NewGuid().ToString();

            var sut = CreateSut();
            var hashedPassword = sut.HashPassword("", password);

            var encoder = new ScryptEncoder();
            encoder.Compare(password, hashedPassword).Should().BeTrue();
        }

        [Fact]
        public void HashPassword_WhenCalledMultipleTimesWithSamePlaintext_ExpectDifferentHash()
        {
            var password = Guid.NewGuid().ToString();

            var sut = CreateSut();
            var hashedPassword1 = sut.HashPassword("", password);
            var hashedPassword2 = sut.HashPassword("", password);

            hashedPassword1.Should().NotBe(hashedPassword2);
        }

        [Fact]
        public void HashPassword_WithCustomSettings_ExpectVerifiableHash()
        {
            var random = new Random();
            var iterationCount = (int)Math.Pow(2.00, random.Next(15, 20));
            var blockSize = random.Next(9, 12);
            const int threadCount = 2;

            var password = Guid.NewGuid().ToString();

            options.IterationCount = iterationCount;
            options.BlockSize = blockSize;
            options.ThreadCount = threadCount;
            var sut = CreateSut();
            
            var hashedPassword = sut.HashPassword("", password);

            var encoder = new ScryptEncoder();
            encoder.Compare(password, hashedPassword).Should().BeTrue();
        }
        
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public void VerifyHashedPassword_WhenHashedPasswordIsNullOrWhitespace_ExpectArgumentNullException(string hashedPassword)
        {
            var sut = CreateSut();
            Assert.Throws<ArgumentNullException>(() => sut.VerifyHashedPassword(null, hashedPassword, Guid.NewGuid().ToString()));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public void VerifyHashedPassword_WhenPasswordIsNullOrWhitespace_ExpectArgumentNullException(string password)
        {
            var sut = CreateSut();
            Assert.Throws<ArgumentNullException>(() => sut.VerifyHashedPassword(null, Guid.NewGuid().ToString(), password));
        }

        [Fact]
        public void VerifyHashedPassword_WithDefaultSettings_ExpectSuccess()
        {
            var password = Guid.NewGuid().ToString();
            var encoder = new ScryptEncoder();
            var hashedPassword = encoder.Encode(password);

            var sut = CreateSut();

            sut.VerifyHashedPassword("", hashedPassword, password).Should().Be(PasswordVerificationResult.Success);
        }
        
        [Fact]
        public void VerifyHashedPassword_WithCustomSettings_ExpectSuccess()
        {
            var random = new Random();
            var iterationCount = (int)Math.Pow(2.00, random.Next(15, 20));
            var blockSize = random.Next(9, 12);
            const int threadCount = 2;

            var password = Guid.NewGuid().ToString();
            var encoder = new ScryptEncoder(iterationCount, blockSize, threadCount);
            var hashedPassword = encoder.Encode(password);

            var sut = CreateSut();

            sut.VerifyHashedPassword("", hashedPassword, password).Should().Be(PasswordVerificationResult.Success);
        }

        [Fact]
        public void VerifyHashedPassword_WhenSuppliedPasswordDoesNotMatch_ExpectFailure()
        {
            var password = Guid.NewGuid().ToString();
            var encoder = new ScryptEncoder();
            var hashedPassword = encoder.Encode(Guid.NewGuid().ToString());

            var sut = CreateSut();

            sut.VerifyHashedPassword("", hashedPassword, password).Should().Be(PasswordVerificationResult.Failed);
        }
    }
}