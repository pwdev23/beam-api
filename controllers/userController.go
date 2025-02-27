package controllers

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pwdev23/beam-api/helpers"
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "errorCode:": helpers.FormatMessageCode(err.Error())})
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		m := "Failed to hash password"
		c.JSON(http.StatusInternalServerError, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
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
		m := "Failed to register user"
		c.JSON(http.StatusInternalServerError, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		return
	}

	// Generate JWT token
	token, err := generateToken(user.ID, user.Role)
	if err != nil {
		m := "Failed to generate token"
		c.JSON(http.StatusInternalServerError, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		return
	}

	// Return success response
	m := "User registered"
	c.JSON(http.StatusCreated, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m), "token": token})
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
		m := "Invalid phone or password"
		c.JSON(http.StatusUnauthorized, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		return
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		m := "Invalid phone or password"
		c.JSON(http.StatusUnauthorized, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		return
	}

	// Generate Token
	token, err := generateToken(user.ID, user.Role)
	if err != nil {
		m := "Failed to generate token"
		c.JSON(http.StatusInternalServerError, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		return
	}

	m := "Login successful"
	c.JSON(http.StatusOK, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m), "token": token})
}

func GetUser(c *gin.Context) {
	id := c.Param("id")
	var user models.User
	if err := initializers.DB.Where("id = ?", id).First(&user).Error; err != nil {
		m := "User not found"
		c.JSON(http.StatusNotFound, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": user})
}

func GetAllUsers(c *gin.Context) {
	var users []models.User
	if err := initializers.DB.Find(&users).Error; err != nil {
		m := "Failed to fetch users"
		c.JSON(http.StatusInternalServerError, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}

func UpdateUser(c *gin.Context) {
	userID, exists := c.Get("userId")
	if !exists {
		m := "Unauthorized"
		c.JSON(http.StatusUnauthorized, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
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
		m := "User not found"
		c.JSON(http.StatusNotFound, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		return
	}

	// Update user fields
	user.FullName = req.FullName
	user.PhonePrefix = req.PhonePrefix
	user.PhoneNumber = req.PhoneNumber
	user.Email = req.Email

	if err := initializers.DB.Save(&user).Error; err != nil {
		m := "Failed to update profile"
		c.JSON(http.StatusInternalServerError, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		return
	}

	m := "Profile updated successfully"
	c.JSON(http.StatusOK, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m), "user": user})
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
		m := "User not found"
		c.JSON(http.StatusNotFound, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		return
	}

	// Generate reset token
	token := uuid.New().String()
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

	// Disable click tracking
	trackingSettings := mail.NewTrackingSettings()
	clickTracking := mail.NewClickTrackingSetting()
	clickTracking.SetEnable(false) // Disable click tracking
	clickTracking.SetEnableText(false)
	trackingSettings.SetClickTracking(clickTracking)
	message.SetTrackingSettings(trackingSettings)

	client := sendgrid.NewSendClient(os.Getenv("SENDGRID_API_KEY"))
	_, err := client.Send(message)
	if err != nil {
		m := "Failed to send email"
		c.JSON(http.StatusInternalServerError, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		return
	}

	m := "Password reset link sent"
	c.JSON(http.StatusOK, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
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
		m := "Invalid or expired token"
		c.JSON(http.StatusUnauthorized, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		return
	}

	if time.Now().After(reset.ExpiresAt) {
		m := "Token expired"
		c.JSON(http.StatusUnauthorized, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		initializers.DB.Delete(&reset)
		return
	}

	var user models.User
	if err := initializers.DB.First(&user, reset.UserID).Error; err != nil {
		m := "User not found"
		c.JSON(http.StatusNotFound, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		m := "Failed to hash password"
		c.JSON(http.StatusInternalServerError, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		return
	}

	// Update password and delete token
	user.PasswordHash = string(hashedPassword)
	initializers.DB.Save(&user)
	initializers.DB.Delete(&reset)

	m := "Password reset successful"
	c.JSON(http.StatusOK, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
}

func UpdatePassword(c *gin.Context) {
	userID, exists := c.Get("userId")
	if !exists {
		m := "Unauthorized"
		c.JSON(http.StatusUnauthorized, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
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
		m := "User not found"
		c.JSON(http.StatusNotFound, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		return
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.OldPassword)); err != nil {
		m := "Old password is incorrect"
		c.JSON(http.StatusUnauthorized, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		m := "Failed to hash new password"
		c.JSON(http.StatusInternalServerError, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		return
	}

	// Update password in database
	user.PasswordHash = string(hashedPassword)
	if err := initializers.DB.Save(&user).Error; err != nil {
		m := "Failed to update password"
		c.JSON(http.StatusInternalServerError, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		return
	}

	m := "Password updated successfully"
	c.JSON(http.StatusOK, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
}

func ValidateResetToken(c *gin.Context) {
	token := c.Param("token")

	var reset models.PasswordReset
	if err := initializers.DB.Where("token = ?", token).First(&reset).Error; err != nil {
		m := "Invalid or expired token"
		c.JSON(http.StatusUnauthorized, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		return
	}

	if time.Now().After(reset.ExpiresAt) {
		initializers.DB.Delete(&reset) // Clean up expired tokens
		m := "Token expired"
		c.JSON(http.StatusUnauthorized, gin.H{"error": m, "errorCode": helpers.FormatMessageCode(m)})
		return
	}

	m := "Token is valid"
	c.JSON(http.StatusOK, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
}
