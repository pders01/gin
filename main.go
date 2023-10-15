package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

const userKey = "user"

var jwtSecretKey = os.Getenv("JWT_SECRET")
var Router *gin.Engine
var db *sqlx.DB

func main() {
	// Get environment variables
	dbURL := os.Getenv("DATABASE_URL")
	allowedOrigins := strings.Split(os.Getenv("ALLOWED_ORIGINS"), ",")

	// Initialize the database connection
	var err error
	db, err = sqlx.Connect("postgres", dbURL)
	if err != nil {
		log.Fatal("Failed to connect to the database:", err)
	}

	r := engine(allowedOrigins)
	r.Use(gin.Logger())
	if err := r.Run(); err != nil {
		log.Fatal("Unable to start:", err)
	}
}

func engine(allowedOrigins []string) *gin.Engine {
	r := gin.New()

	sessionSecret, err := generateSessionSecret()
	if err != nil {
		log.Fatal("Failed to generate session secret:", err)
	}

	// CORS middleware
	r.Use(corsMiddleware(allowedOrigins))

	// Use sessions middleware
	store := cookie.NewStore([]byte(sessionSecret))
	r.Use(sessions.Sessions("mysession", store))

	// Login and logout routes
	r.POST("/login", login)
	r.GET("/logout", logout)

	// Private group, require authentication to access
	private := r.Group("/private")
	private.Use(AuthRequired)
	{
		private.GET("/me", me)
		private.GET("/status", status)
		//private.GET("/feeds", getFeeds)
		//private.POST("/feeds", addFeed)
	}

	return r
}

// User represents the user entity in the database
type User struct {
	ID           int    `db:"id" json:"id"`
	Username     string `db:"username" json:"username"`
	PasswordHash string `db:"password_hash" json:"-"`
}

// AuthRequired middleware checks for a valid JWT token in the Authorization header
func AuthRequired(c *gin.Context) {
	tokenString := extractJWTTokenFromHeader(c.Request.Header.Get("Authorization"))
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		c.Abort()
		return
	}

	token, err := validateJWTToken(tokenString)
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		c.Abort()
		return
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		c.Abort()
		return
	}

	// Extract user information from claims
	username, ok := claims["username"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		c.Abort()
		return
	}

	// Fetch user details from the database based on the username
	var user User
	err = db.Get(&user, "SELECT * FROM users WHERE username = $1", username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		c.Abort()
		return
	}

	// Set user information in the context for further use in handlers
	c.Set("user", user)

	// Continue down the chain to handler, etc.
	c.Next()
}

// login is a handler that parses a form and checks for specific data.
func login(c *gin.Context) {
	session := sessions.Default(c)
	username := c.PostForm("username")
	password := c.PostForm("password")

	// Validate form input
	if strings.Trim(username, " ") == "" || strings.Trim(password, " ") == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Parameters can't be empty"})
		return
	}

	// Retrieve user from the database based on the entered username
	var user User
	err := db.Get(&user, "SELECT * FROM users WHERE username = $1", username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed"})
		return
	}

	// Verify the entered password against the stored hash
	if err := verifyPassword(user.PasswordHash, password); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed"})
		return
	}

	// Assuming user is valid, create a JWT token
	tokenString, err := createJWTToken(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// Save the username in the session
	session.Set(userKey, username)
	if err := session.Save(); err != nil {
		log.Println("Failed to save session:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}

	// Set the session cookie in the response
	c.SetCookie(
		"mysession",  // name of the cookie
		session.ID(), // value of the cookie (session ID)
		3600,         // max age in seconds (1 hour in this example)
		"/",          // path
		"",           // domain
		true,         // secure (set to true if using HTTPS)
		true,         // httpOnly (to prevent JavaScript access)
	)
	// Set the JWT token in the response JSON
	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// logout clears the JWT token and invalidates the session
func logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Delete(userKey)
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to invalidate session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}

// me is the handler that will return the user information stored in the session.
func me(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get(userKey)
	c.JSON(http.StatusOK, gin.H{"user": user})
}

// status is the handler that will tell the user whether it is logged in or not.
func status(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "You are logged in"})
}

// Handler to get all feeds for a user
// func getFeeds(c *gin.Context) {
// 	user, err := getUserFromSession(c)
// 	if err != nil {
// 		// Handle error, e.g., user not logged in
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
// 		return
// 	}

// 	// Retrieve all feeds associated with the user
// 	var feeds []Feed
// 	err = db.Select(&feeds, "SELECT * FROM feeds WHERE user_id = $1", user.ID)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve feeds from the database"})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{
// 		"feeds": feeds,
// 	})
// }

// func addFeed(c *gin.Context) {
// 	user, err := getUserFromSession(c)
// 	if err != nil {
// 		// Handle error, e.g., user not logged in
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
// 		return
// 	}

// 	// Get the URL from the request body
// 	var requestBody struct {
// 		URL string `json:"url" binding:"required"`
// 	}
// 	if err := c.BindJSON(&requestBody); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
// 		return
// 	}

// 	// Insert the URL into the `feeds` table associated with the user
// 	_, err = db.Exec("INSERT INTO feeds (user_id, url) VALUES ($1, $2)", user.ID, requestBody.URL)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to insert URL into the database"})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{
// 		"message": "Feed URL added to the database!",
// 	})
// }

// Function to hash a password
// func hashPassword(password string) (string, error) {
// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
// 	return string(hashedPassword), err
// }

// Function to verify a password
func verifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// corsMiddleware is a middleware to handle CORS.
func corsMiddleware(allowedOrigins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Check if the origin is in the list of allowed origins
		for _, allowedOrigin := range allowedOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
				c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
				c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")

				if c.Request.Method == http.MethodOptions {
					c.AbortWithStatus(http.StatusNoContent)
					return
				}

				break
			}
		}

		c.Next()
	}
}

// generateSessionSecret generates a random session secret.
func generateSessionSecret() (string, error) {
	b := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil
}

// createJWTToken generates a JWT token for the given username
func createJWTToken(username string) (string, error) {
	if jwtSecretKey == "" {
		err := errors.New("jwt secret is missing")
		return "", err
	}

	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // Token expiration time (e.g., 24 hours)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtSecretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// validateJWTToken validates a JWT token
func validateJWTToken(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}

		// Return the secret key used for signing
		return []byte(jwtSecretKey), nil
	})
}

// extractJWTTokenFromHeader extracts the JWT token from the Authorization header
func extractJWTTokenFromHeader(authorizationHeader string) string {
	// Check if the Authorization header is empty
	if authorizationHeader == "" {
		return ""
	}

	// Expecting a header value in the format "Bearer <token>"
	parts := strings.Split(authorizationHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}
