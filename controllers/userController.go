package controllers

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pwdev23/beam-api/initializers"
	"github.com/pwdev23/beam-api/models"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

func generateToken(userID uint, role string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId": userID,
		"role":   role,
		"exp":    time.Now().Add(time.Hour * 24 * 30).Unix(),
	})
	return token.SignedString(jwtSecret)
}

func RegisterUser(c *gin.Context) {
	var req struct {
		FullName    string `json:"fullName"`
		PhonePrefix string `json:"phonePrefix"`
		PhoneNumber string `json:"phoneNumber"`
		Email       string `json:"email"`
		Role        string `json:"role"`
		Password    string `json:"password"`
	}

	// Bind request JSON to struct
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Create user model instance
	user := models.User{
		FullName:     req.FullName,
		PhonePrefix:  req.PhonePrefix,
		PhoneNumber:  req.PhoneNumber,
		Email:        req.Email,
		Role:         req.Role,
		PasswordHash: string(hashedPassword), // Store hashed password
	}

	// Save user to DB
	if err := initializers.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	// Generate JWT token
	token, err := generateToken(user.ID, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// Return success response
	c.JSON(http.StatusCreated, gin.H{"message": "User registered", "token": token})
}

func LoginUser(c *gin.Context) {
	var req struct {
		PhonePrefix string `json:"phonePrefix"`
		PhoneNumber string `json:"phoneNumber"`
		Password    string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := initializers.DB.Where("phone_prefix = ? AND phone_number = ?", req.PhonePrefix, req.PhoneNumber).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid phone or password"})
		return
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid phone or password"})
		return
	}

	// Generate Token
	token, err := generateToken(user.ID, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Login successful", "token": token})
}

func GetUser(c *gin.Context) {
	id := c.Param("id")
	var user models.User
	if err := initializers.DB.Where("id = ?", id).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": user})
}

func GetAllUsers(c *gin.Context) {
	var users []models.User
	if err := initializers.DB.Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}

func UpdateUser(c *gin.Context) {
	userID, exists := c.Get("userId")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req struct {
		FullName    string `json:"fullName"`
		PhonePrefix string `json:"phonePrefix"`
		PhoneNumber string `json:"phoneNumber"`
		Email       string `json:"email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := initializers.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Update user fields
	user.FullName = req.FullName
	user.PhonePrefix = req.PhonePrefix
	user.PhoneNumber = req.PhoneNumber
	user.Email = req.Email

	if err := initializers.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update profile"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully", "user": user})
}

func RequestPasswordReset(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := initializers.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Generate reset token
	token := uuid.New().String()
	// log for testing purposes
	fmt.Println("Reset token: ", token)
	expiration := time.Now().Add(time.Hour * 6)

	reset := models.PasswordReset{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: expiration,
	}

	initializers.DB.Create(&reset)

	// Send email with reset link
	from := mail.NewEmail(os.Getenv("SENDGRID_SENDER_NAME"), os.Getenv("SENDGRID_SENDER"))
	to := mail.NewEmail(user.FullName, user.Email)
	subject := "Password reset request"
	frontendURL := os.Getenv("FRONTEND_URL")
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", frontendURL, token)
	plainTextContent := fmt.Sprintf("Click the following link to reset your password: %s", resetURL)
	htmlContent := fmt.Sprintf("<p>Click <a href='%s'>here</a> to reset your password.</p>", resetURL)
	message := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)

	client := sendgrid.NewSendClient(os.Getenv("SENDGRID_API_KEY"))
	_, err := client.Send(message)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send email"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset link sent"})
}

func ResetPassword(c *gin.Context) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var reset models.PasswordReset
	if err := initializers.DB.Where("token = ?", req.Token).First(&reset).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		return
	}

	if time.Now().After(reset.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
		initializers.DB.Delete(&reset)
		return
	}

	var user models.User
	if err := initializers.DB.First(&user, reset.UserID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Update password and delete token
	user.PasswordHash = string(hashedPassword)
	initializers.DB.Save(&user)
	initializers.DB.Delete(&reset)

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successful"})
}

func UpdatePassword(c *gin.Context) {
	userID, exists := c.Get("userId")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := initializers.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.OldPassword)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Old password is incorrect"})
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash new password"})
		return
	}

	// Update password in database
	user.PasswordHash = string(hashedPassword)
	if err := initializers.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
}

func ValidateResetToken(c *gin.Context) {
	token := c.Param("token")

	var reset models.PasswordReset
	if err := initializers.DB.Where("token = ?", token).First(&reset).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		return
	}

	if time.Now().After(reset.ExpiresAt) {
		initializers.DB.Delete(&reset) // Clean up expired tokens
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Token is valid"})
}
