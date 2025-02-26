package middleware

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

// Auth Middleware
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Ensure secret key is set
		if len(jwtSecret) == 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "JWT secret is not configured"})
			c.Abort()
			return
		}

		// Get Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Ensure "Bearer " prefix is present
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
			c.Abort()
			return
		}

		// Extract token part
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Parse & validate token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Ensure the signing method is HMAC
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Extract claims safely
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		// Extract userId safely
		userIDFloat, userIDExists := claims["userId"].(float64)
		if !userIDExists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid userId in token"})
			c.Abort()
			return
		}
		userID := uint(userIDFloat) // Convert float64 to uint safely

		// Extract role safely
		role, roleExists := claims["role"].(string)
		if !roleExists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid role in token"})
			c.Abort()
			return
		}

		// Set values in context
		c.Set("userId", userID)
		c.Set("role", role)

		// Proceed to next middleware/handler
		c.Next()
	}
}
