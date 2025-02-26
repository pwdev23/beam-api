package main

import (
	"github.com/gin-gonic/gin"
	"github.com/pwdev23/beam-api/controllers"
	"github.com/pwdev23/beam-api/initializers"
	"github.com/pwdev23/beam-api/middleware"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDB()
}

func main() {
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Hello, Beam API!",
		})
	})

	// User Routes
	userRoutes := r.Group("/api/v1/users")
	{
		userRoutes.POST("/register", controllers.RegisterUser)
		userRoutes.POST("/login", controllers.LoginUser)
		userRoutes.GET("/profile", middleware.AuthMiddleware(), controllers.GetUserProfile)
	}

	r.Run()
}
