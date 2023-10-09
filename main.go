package main

import (
	"fmt"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq" // PostgreSQL driver
)

var Router *gin.Engine
var db *sqlx.DB

func main() {
	// Get environment variables
	dbURL := os.Getenv("DATABASE_URL")

	// Initialize the database connection
	var err error
	db, err = sqlx.Connect("postgres", dbURL)
	if err != nil {
		panic(err)
	}

	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Hello world!",
		})
	})

	r.POST("/feed/add", func(c *gin.Context) {
		// Access environment variables
		pgDatabase := os.Getenv("PGDATABASE")
		pgHost := os.Getenv("PGHOST")
		pgPassword := os.Getenv("PGPASSWORD")
		pgPort := os.Getenv("PGPORT")
		pgUser := os.Getenv("PGUSER")

		// Use these variables to construct a connection string
		connectionString := fmt.Sprintf("user=%s password=%s host=%s port=%s dbname=%s", pgUser, pgPassword, pgHost, pgPort, pgDatabase)

		// Initialize a new database connection for this route (optional, depending on your needs)
		db, err := sqlx.Connect("postgres", connectionString)
		if err != nil {
			c.JSON(500, gin.H{
				"error": "Failed to connect to the database",
			})
			return
		}
		defer db.Close()

		// Get the URL from the request body
		var requestBody struct {
			URL string `json:"url" binding:"required"`
		}
		if err := c.BindJSON(&requestBody); err != nil {
			c.JSON(400, gin.H{
				"error": "Invalid request body",
			})
			return
		}

		// Insert the URL into the `urls` table
		_, err = db.Exec("INSERT INTO test (url) VALUES ($1)", requestBody.URL)
		if err != nil {
			c.JSON(500, gin.H{
				"error": "Failed to insert URL into the database",
			})
			return
		}

		c.JSON(200, gin.H{
			"message": "Feed URL added to the database!",
		})
	})

	r.Run()
}
