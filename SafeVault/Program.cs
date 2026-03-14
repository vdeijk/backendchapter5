using System.IO;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Add JWT Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "SafeVault",
            ValidAudience = "SafeVault",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("your-secret-key-here")) // Use a secure key
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

// Endpoint to serve the form
app.MapGet("/form", () => Results.Content(File.ReadAllText("webform.html"), "text/html"));

// Endpoint to serve the login form
app.MapGet("/loginform", () => Results.Content(File.ReadAllText("login.html"), "text/html"));

// Endpoint to handle registration
app.MapPost("/register", (string username, string email, string password, string role) =>
{
    try
    {
        string sanitizedUsername = InputValidation.SanitizeUsername(username);
        string sanitizedEmail = InputValidation.SanitizeEmail(email);
        string sanitizedPassword = InputValidation.SanitizePassword(password);
        string sanitizedRole = InputValidation.SanitizeRole(role);
        DatabaseHelper.InsertUser(sanitizedUsername, sanitizedEmail, sanitizedPassword, sanitizedRole);
        return Results.Ok("User registered successfully.");
    }
    catch (Exception ex)
    {
        return Results.BadRequest(ex.Message);
    }
});

// Endpoint to handle login
app.MapPost("/login", (string username, string password) =>
{
    var user = DatabaseHelper.GetUserForAuth(username);
    if (user == null || !DatabaseHelper.VerifyPassword(password, user.Value.PasswordHash))
    {
        return Results.Unauthorized();
    }

    var claims = new[]
    {
        new Claim(ClaimTypes.Name, username),
        new Claim(ClaimTypes.Role, user.Value.Role)
    };

    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("your-secret-key-here"));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var token = new JwtSecurityToken(
        issuer: "SafeVault",
        audience: "SafeVault",
        claims: claims,
        expires: DateTime.Now.AddHours(1),
        signingCredentials: creds);

    return Results.Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
});

// Protected endpoint for admin
app.MapGet("/admin", () => "Welcome to Admin Dashboard").RequireAuthorization(policy => policy.RequireRole("admin"));

// Protected endpoint for user profile
app.MapGet("/profile", (HttpContext context) =>
{
    var username = context.User.Identity?.Name;
    if (string.IsNullOrEmpty(username))
        return Results.Unauthorized();

    var user = DatabaseHelper.GetUserProfile(username);
    if (user == null)
        return Results.NotFound();

    // Email is already encoded when sanitized, so safe for display
    return Results.Ok(new { Username = user.Value.Username, Email = user.Value.Email, Role = user.Value.Role });
}).RequireAuthorization();

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
