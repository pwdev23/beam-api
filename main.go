package main

import (
	"github.com/gin-gonic/gin"
	"github.com/pwdev23/beam-api/initializers"
	"github.com/pwdev23/beam-api/middleware"
	"github.com/pwdev23/beam-api/routes"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDB()
}

func main() {
	r := gin.Default()

	r.Use(middleware.CORSMiddleware())

	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Hello, Beam API!",
		})
	})

	routes.RegisterAuthRoutes(r)
	routes.RegisterUserRoutes(r)

	r.Run()
}
