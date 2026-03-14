// Tests/TestInputValidation.cs
using NUnit.Framework;
using BCrypt.Net;

[TestFixture]
public class TestInputValidation
{
    [Test]
    public void TestValidUsername()
    {
        string result = InputValidation.SanitizeUsername("valid_user123");
        Assert.That(result, Is.EqualTo("valid_user123"));
    }

    [Test]
    public void TestUsernameWithSpecialChars()
    {
        string result = InputValidation.SanitizeUsername("user<script>alert('xss')</script>");
        Assert.That(result, Is.EqualTo("userscriptalertxssscript"));
    }

    [Test]
    public void TestEmptyUsername()
    {
        Assert.Throws<ArgumentException>(() => InputValidation.SanitizeUsername(""));
    }

    [Test]
    public void TestValidEmail()
    {
        string result = InputValidation.SanitizeEmail("user@example.com");
        Assert.That(result, Is.EqualTo("user@example.com"));
    }

    [Test]
    public void TestEmailWithXSS()
    {
        string result = InputValidation.SanitizeEmail("user<script>alert('xss')</script>@example.com");
        Assert.That(result, Is.EqualTo("user&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;@example.com"));
    }

    [Test]
    public void TestInvalidEmail()
    {
        Assert.Throws<ArgumentException>(() => InputValidation.SanitizeEmail("invalid-email"));
    }

    [Test]
    public void TestSQLInjectionAttempt()
    {
        string maliciousUsername = "'; DROP TABLE Users; --";
        string sanitized = InputValidation.SanitizeUsername(maliciousUsername);
        Assert.That(sanitized, Is.EqualTo("DROP TABLE Users --"));
    }

    [Test]
    public void TestXSSInEmail()
    {
        string maliciousEmail = "user<img>@example.com";
        string sanitized = InputValidation.SanitizeEmail(maliciousEmail);
        Assert.That(sanitized, Is.EqualTo("user&lt;img&gt;@example.com"));
    }

    [Test]
    public void TestValidRole()
    {
        string result = InputValidation.SanitizeRole("admin");
        Assert.That(result, Is.EqualTo("admin"));
    }

    [Test]
    public void TestInvalidRole()
    {
        Assert.Throws<ArgumentException>(() => InputValidation.SanitizeRole("hacker"));
    }

    [Test]
    public void TestValidPassword()
    {
        string result = InputValidation.SanitizePassword("password123");
        Assert.That(result, Is.EqualTo("password123"));
    }

    [Test]
    public void TestShortPassword()
    {
        Assert.Throws<ArgumentException>(() => InputValidation.SanitizePassword("123"));
    }

    [Test]
    public void TestPasswordHashing()
    {
        string password = "password123";
        string hash = BCrypt.Net.BCrypt.HashPassword(password);
        bool verified = BCrypt.Net.BCrypt.Verify(password, hash);
        Assert.That(verified, Is.True);
    }

    [Test]
    public void TestInvalidPassword()
    {
        string password = "password123";
        string hash = BCrypt.Net.BCrypt.HashPassword(password);
        bool verified = BCrypt.Net.BCrypt.Verify("wrongpassword", hash);
        Assert.That(verified, Is.False);
    }
}