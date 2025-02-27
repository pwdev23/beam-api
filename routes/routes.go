package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/pwdev23/beam-api/controllers"
	"github.com/pwdev23/beam-api/middleware"
)

func RegisterAuthRoutes(r *gin.Engine) {
	authRoutes := r.Group("api/v1")
	{
		authRoutes.POST("/register", controllers.RegisterUser)
		authRoutes.POST("/login", controllers.LoginUser)
		authRoutes.POST("/request-password-reset", controllers.RequestPasswordReset)
		authRoutes.POST("/password-reset", controllers.ResetPassword)
		authRoutes.GET("/password-reset/:token", controllers.ValidateResetToken)
	}
}

func RegisterUserRoutes(r *gin.Engine) {
	userRoutes := r.Group("/api/v1/users", middleware.AuthMiddleware())
	{
		userRoutes.GET("", controllers.GetAllUsers)
		userRoutes.GET(":id", controllers.GetUser)
		userRoutes.PUT("", controllers.UpdateUser)
		userRoutes.PUT("/password", controllers.UpdatePassword)
	}
}
