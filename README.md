# SafeVault – Secure Web Application

SafeVault is an ASP.NET Core 9 minimal-API application that demonstrates secure handling of user data, including input validation, parameterized database access, password hashing, JWT-based authentication, and role-based authorization.

---

## Project Structure

```
SafeVault/
├── InputValidation.cs      # Input sanitization (XSS, length, format)
├── DatabaseHelper.cs       # Parameterized SQL queries + BCrypt helpers
├── Program.cs              # Minimal API endpoints, JWT auth, RBAC
├── database.sql            # Users table schema
├── webform.html            # Registration form
├── login.html              # Login form
└── Tests/
    ├── InputValidation.cs  # Shared validation logic for test project
    └── TestInputValidation.cs  # NUnit test suite (14 tests)
```

---

## Running the Application

```bash
cd SafeVault
dotnet run
```

Endpoints:
| Method | Path | Description |
|--------|------|-------------|
| GET | `/form` | Registration form |
| GET | `/loginform` | Login form |
| POST | `/register` | Register a new user |
| POST | `/login` | Authenticate; returns JWT token |
| GET | `/profile` | Current user's profile (requires auth) |
| GET | `/admin` | Admin dashboard (requires `admin` role) |

## Running the Tests

```bash
cd SafeVault/Tests
dotnet test
```

All 14 tests pass, covering input validation, XSS encoding, SQL injection resistance, password hashing, role validation, and authentication logic.

---

## Security Summary

### Vulnerabilities Identified

| # | Vulnerability | Location |
|---|--------------|----------|
| 1 | SQL Injection via string concatenation | Database queries |
| 2 | XSS via unencoded user input rendered in HTML | Email/username fields |
| 3 | Plaintext password storage | User registration |
| 4 | Unrestricted role assignment | Registration endpoint |
| 5 | Missing input length enforcement | All form fields |

### Fixes Applied

**1. SQL Injection → Parameterized Queries**  
All database operations in `DatabaseHelper.cs` use `SqlCommand` with `SqlParameter` objects. User-supplied values are never concatenated into SQL strings.

```csharp
string query = "SELECT UserID, Password, Role FROM Users WHERE Username = @Username";
cmd.Parameters.AddWithValue("@Username", username);
```

**2. XSS → HTML Encoding + Input Sanitization**  
`InputValidation.SanitizeUsername()` strips all characters outside `[a-zA-Z0-9 _-]`. `SanitizeEmail()` applies `HtmlEncoder.Default.Encode()` so any injected markup is rendered inert.

```csharp
string sanitized = Regex.Replace(username, @"[^a-zA-Z0-9 _-]", "");
string sanitized = HtmlEncoder.Default.Encode(email);
```

**3. Plaintext Passwords → BCrypt Hashing**  
Passwords are hashed with `BCrypt.Net.BCrypt.HashPassword()` before storage and verified with `BCrypt.Net.BCrypt.Verify()` at login. The hash includes a per-user salt, making rainbow-table attacks infeasible.

**4. Unrestricted Roles → Allow-list Validation**  
`InputValidation.SanitizeRole()` rejects any value other than `"user"` or `"admin"`, preventing privilege escalation through role manipulation.

**5. Authentication & Authorization → JWT + RBAC**  
Successful login returns a signed JWT containing the user's name and role. Protected endpoints use `.RequireAuthorization()` and `policy.RequireRole("admin")` to enforce role-based access control.

### How Copilot Assisted

- **Code generation** – Copilot generated the initial `InputValidation`, `DatabaseHelper`, and `Program.cs` scaffolding, applying security patterns (parameterized queries, BCrypt, `HtmlEncoder`) from the outset.
- **Vulnerability detection** – Copilot identified that the original `DatabaseHelper.InsertUser` signature had no password or role parameters, flagging missing security controls.
- **Fix suggestions** – Copilot proposed the allow-list approach for role validation, the `HtmlEncoder` API for XSS prevention, and the correct `BCrypt.Net.BCrypt` fully-qualified call syntax.
- **Test generation** – Copilot produced test cases for attack scenarios (SQL injection strings, XSS payloads, wrong passwords, invalid roles, short passwords) ensuring the fixes are verifiable.
- **Build debugging** – Copilot diagnosed that the `Tests/` subfolder was being compiled into the main project (causing 44 duplicate-symbol errors) and resolved it by adding `<Compile Remove="Tests\**" />` to `SafeVault.csproj`.
