using Microsoft.Data.SqlClient;
using BCrypt.Net;

public static class DatabaseHelper
{
    private static string connectionString = "Server=localhost;Database=SafeVault;Integrated Security=True;"; // Adjust as needed

    public static void InsertUser(string username, string email, string password, string role)
    {
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(password);
        using (SqlConnection conn = new SqlConnection(connectionString))
        {
            conn.Open();
            string query = "INSERT INTO Users (Username, Email, Password, Role) VALUES (@Username, @Email, @Password, @Role)";
            using (SqlCommand cmd = new SqlCommand(query, conn))
            {
                cmd.Parameters.AddWithValue("@Username", username);
                cmd.Parameters.AddWithValue("@Email", email);
                cmd.Parameters.AddWithValue("@Password", passwordHash);
                cmd.Parameters.AddWithValue("@Role", role);
                cmd.ExecuteNonQuery();
            }
        }
    }

    public static (int UserID, string PasswordHash, string Role)? GetUserForAuth(string username)
    {
        using (SqlConnection conn = new SqlConnection(connectionString))
        {
            conn.Open();
            string query = "SELECT UserID, Password, Role FROM Users WHERE Username = @Username";
            using (SqlCommand cmd = new SqlCommand(query, conn))
            {
                cmd.Parameters.AddWithValue("@Username", username);
                using (SqlDataReader reader = cmd.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        return (reader.GetInt32(0), reader.GetString(1), reader.GetString(2));
                    }
                }
            }
        }
        return null;
    }

    public static bool VerifyPassword(string password, string hash)
    {
        return BCrypt.Net.BCrypt.Verify(password, hash);
    }

    public static (string Username, string Email, string Role)? GetUserProfile(string username)
    {
        using (SqlConnection conn = new SqlConnection(connectionString))
        {
            conn.Open();
            string query = "SELECT Username, Email, Role FROM Users WHERE Username = @Username";
            using (SqlCommand cmd = new SqlCommand(query, conn))
            {
                cmd.Parameters.AddWithValue("@Username", username);
                using (SqlDataReader reader = cmd.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        return (reader.GetString(0), reader.GetString(1), reader.GetString(2));
                    }
                }
            }
        }
        return null;
    }
}