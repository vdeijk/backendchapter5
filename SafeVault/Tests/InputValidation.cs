using System.Text.RegularExpressions;
using System.Text.Encodings.Web;

public static class InputValidation
{
    public static string SanitizeUsername(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            throw new ArgumentException("Username cannot be empty.");

        // Remove potentially harmful characters, allow alphanumeric, spaces, underscores, hyphens
        string sanitized = Regex.Replace(username, @"[^a-zA-Z0-9 _-]", "");
        // Trim and limit length
        sanitized = sanitized.Trim();
        if (sanitized.Length > 100)
            sanitized = sanitized.Substring(0, 100);
        return sanitized;
    }

    public static string SanitizeEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            throw new ArgumentException("Email cannot be empty.");

        // Basic email validation
        if (!Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
            throw new ArgumentException("Invalid email format.");

        // For XSS, encode HTML entities
        string sanitized = HtmlEncoder.Default.Encode(email);
        if (sanitized.Length > 100)
            sanitized = sanitized.Substring(0, 100);
        return sanitized;
    }

    public static string SanitizeRole(string role)
    {
        if (string.IsNullOrWhiteSpace(role))
            throw new ArgumentException("Role cannot be empty.");

        // Allow only 'user' or 'admin'
        if (role.ToLower() != "user" && role.ToLower() != "admin")
            throw new ArgumentException("Invalid role. Must be 'user' or 'admin'.");

        return role.ToLower();
    }

    public static string SanitizePassword(string password)
    {
        if (string.IsNullOrWhiteSpace(password) || password.Length < 6)
            throw new ArgumentException("Password must be at least 6 characters long.");

        // Limit length
        if (password.Length > 100)
            password = password.Substring(0, 100);
        return password;
    }
}