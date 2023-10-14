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

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

const userKey = "user"

var Router *gin.Engine
var db *sqlx.DB
var sessionSecret string

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

	// Generate a new session secret
	sessionSecret, err = generateSessionSecret()
	if err != nil {
		log.Fatal("Failed to generate session secret:", err)
	}

	r := engine(allowedOrigins)
	r.Use(gin.Logger())
	if err := r.Run(); err != nil {
		log.Fatal("Unable to start:", err)
	}
}

func engine(allowedOrigins []string) *gin.Engine {
	r := gin.New()

	// Setup the cookie store for session management
	store := cookie.NewStore([]byte(sessionSecret))
	store.Options(
		sessions.Options{
			MaxAge:   24 * 60 * 60,
			HttpOnly: true,
		},
	)
	r.Use(sessions.Sessions("mysession", store))

	// CORS middleware
	r.Use(corsMiddleware(allowedOrigins))

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
		private.POST("/feeds", addFeed)
	}

	return r
}

// AuthRequired is a simple middleware to check the session.
func AuthRequired(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get(userKey)
	if user == nil {
		// Abort the request with the appropriate error code
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	// Continue down the chain to handler etc
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

	// Generate a new session secret if not already set
	if session.Get("session_secret") == nil {
		newSecret, err := generateSessionSecret()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate session secret"})
			return
		}
		session.Set("session_secret", newSecret)
	}

	// Save the username and session secret in the session
	session.Set(userKey, username)
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Successfully authenticated user"})
}

// logout is the handler called for the user to log out.
func logout(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get(userKey)
	if user == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session token"})
		return
	}
	session.Delete(userKey)
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
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

func addFeed(c *gin.Context) {
	user, err := getUserFromSession(c)
	if err != nil {
		// Handle error, e.g., user not logged in
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// Get the URL from the request body
	var requestBody struct {
		URL string `json:"url" binding:"required"`
	}
	if err := c.BindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Insert the URL into the `feeds` table associated with the user
	_, err = db.Exec("INSERT INTO feeds (user_id, url) VALUES ($1, $2)", user.ID, requestBody.URL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to insert URL into the database"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Feed URL added to the database!",
	})
}

// Function to hash a password
// func hashPassword(password string) (string, error) {
// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
// 	return string(hashedPassword), err
// }

// Function to verify a password
func verifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// User represents the user entity in the database
type User struct {
	ID           int    `db:"id" json:"id"`
	Username     string `db:"username" json:"username"`
	PasswordHash string `db:"password_hash" json:"-"`
}

// Function to get user from session
func getUserFromSession(c *gin.Context) (*User, error) {
	session := sessions.Default(c)
	username := session.Get(userKey)
	if username == nil {
		return nil, errors.New("user not logged in")
	}

	// Fetch user details from the database based on the username
	var user User
	err := db.Get(&user, "SELECT * FROM users WHERE username = $1", username)
	if err != nil {
		return nil, err
	}

	return &user, nil
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
