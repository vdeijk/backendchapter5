-- database.sql
CREATE TABLE Users (
    UserID INT PRIMARY KEY IDENTITY(1,1),
    Username NVARCHAR(100),
    Email NVARCHAR(100),
    Password NVARCHAR(255),
    Role NVARCHAR(50) DEFAULT 'user'
);