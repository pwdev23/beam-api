package controllers

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
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

const (
	userNotFound          = "User not found"
	tokenGenerationFailed = "Failed to generate token"
	invalidLogin          = "Invalid phone or password"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

func isValidPassword(password string) bool {
	var passwordRegex = `^.{8,}$`
	re := regexp.MustCompile(passwordRegex)
	return re.MatchString(password)
}

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
		FullName         string `json:"fullName"`
		PhoneCountryCode string `json:"phoneCountryCode"`
		PhoneNumber      string `json:"phoneNumber"`
		Email            string `json:"email"`
		Role             string `json:"role"` // "customer", "driver", "admin"
		Password         string `json:"password"`
		Currency         string `json:"currency,omitempty"`    // Default to "IDR" if empty
		VehicleType      string `json:"vehicleType,omitempty"` // Required if role == "driver"
		VehiclePlate     string `json:"vehiclePlate,omitempty"`
	}

	// Bind request JSON to struct
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error(), "messageCode": helpers.FormatMessageCode(err.Error()), "data": nil})
		return
	}

	var existingUser models.User
	p := req.PhoneCountryCode + req.PhoneNumber
	if err := initializers.DB.Where("email = ? OR phone_complete = ?", req.Email, p).First(&existingUser).Error; err == nil {
		m := "Email or phone number already registered"
		c.JSON(http.StatusBadRequest, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		return
	}

	// Validate the password before hashing
	if !isValidPassword(req.Password) {
		m := "Password must be at least 8 characters"
		c.JSON(http.StatusBadRequest, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m), "data": nil})
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		m := "Failed to generate hash"
		c.JSON(http.StatusInternalServerError, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m), "data": nil})
		return
	}

	// Create user model instance
	user := models.User{
		FullName:         req.FullName,
		PhoneCountryCode: req.PhoneCountryCode,
		PhoneNumber:      req.PhoneNumber,
		PhoneComplete:    req.PhoneCountryCode + req.PhoneNumber,
		Email:            req.Email,
		Role:             req.Role,
		PasswordHash:     string(hashedPassword), // Store hashed password
		Currency:         req.Currency,
	}

	tx := initializers.DB.Begin()

	if err := tx.Create(&user).Error; err != nil {
		tx.Rollback()
		m := "Failed to register user"
		c.JSON(http.StatusInternalServerError, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m), "data": nil})
		return
	}

	if req.Role == "driver" {
		driver := models.Driver{
			UserID:       user.ID,
			VehicleType:  req.VehicleType,
			VehiclePlate: req.VehiclePlate,
			Currency:     req.Currency,
			Balance:      0,
			Status:       "pending",
		}

		if err := tx.Create(&driver).Error; err != nil {
			tx.Rollback()
			m := "Failed to create driver profile"
			c.JSON(http.StatusInternalServerError, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m), "data": nil})
			return
		}
	}

	tx.Commit()

	// Generate JWT token
	token, err := generateToken(user.ID, user.Role)
	if err != nil {
		m := tokenGenerationFailed
		c.JSON(http.StatusInternalServerError, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m), "data": nil})
		return
	}

	// Return success response with user details
	m := "User registered successfully"
	c.JSON(http.StatusCreated, gin.H{
		"message":     m,
		"messageCode": helpers.FormatMessageCode(m),
		"token":       token,
		"data": gin.H{
			"id":       user.ID,
			"fullName": user.FullName,
			"email":    user.Email,
			"role":     user.Role,
			"currency": user.Currency,
			"phone": gin.H{
				"countryCode": user.PhoneCountryCode,
				"number":      user.PhoneNumber,
				"complete":    user.PhoneComplete,
			},
		},
	})
}

func LoginUser(c *gin.Context) {
	var req struct {
		Phone    string `json:"phone"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error(), "messageCode": helpers.FormatMessageCode(err.Error())})
		return
	}

	var user models.User
	if err := initializers.DB.Where("phone_complete = ?", req.Phone).First(&user).Error; err != nil {
		m := invalidLogin
		c.JSON(http.StatusUnauthorized, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m), "data": nil})
		return
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		m := invalidLogin
		c.JSON(http.StatusUnauthorized, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m), "data": nil})
		return
	}

	// Generate Token
	token, err := generateToken(user.ID, user.Role)
	if err != nil {
		m := tokenGenerationFailed
		c.JSON(http.StatusInternalServerError, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m), "data": nil})
		return
	}

	// Return only essential user details
	m := "Login successful"
	c.JSON(http.StatusOK, gin.H{
		"message":     m,
		"messageCode": helpers.FormatMessageCode(m),
		"token":       token,
		"data": gin.H{
			"id":       user.ID,
			"fullName": user.FullName,
			"role":     user.Role,
		},
	})
}

func GetUserById(c *gin.Context) {
	id := c.Param("id")
	var user models.User
	if err := initializers.DB.Where("id = ?", id).First(&user).Error; err != nil {
		m := userNotFound
		c.JSON(http.StatusNotFound, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m), "data": nil})
		return
	}

	m := "User found"
	c.JSON(http.StatusOK, gin.H{
		"message":     m,
		"messageCode": helpers.FormatMessageCode(m),
		"data": gin.H{
			"id":       user.ID,
			"fullName": user.FullName,
			"email":    user.Email,
			"role":     user.Role,
			"currency": user.Currency,
			"phone": gin.H{
				"countryCode": user.PhoneCountryCode,
				"number":      user.PhoneNumber,
				"complete":    user.PhoneComplete,
			},
		},
	})
}

func GetAllUsers(c *gin.Context) {
	var users []models.User
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	offset := (page - 1) * limit

	if err := initializers.DB.Limit(limit).Offset(offset).Find(&users).Error; err != nil {
		m := "Failed to fetch users"
		c.JSON(http.StatusInternalServerError, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m), "data": nil})
		return
	}

	// Format users for response
	var userList []gin.H
	for _, user := range users {
		userList = append(userList, gin.H{
			"id":       user.ID,
			"fullName": user.FullName,
			"email":    user.Email,
			"role":     user.Role,
			"currency": user.Currency,
			"phone": gin.H{
				"countryCode": user.PhoneCountryCode,
				"number":      user.PhoneNumber,
				"complete":    user.PhoneComplete,
			},
		})
	}

	// Success response
	m := "Users retrieved successfully"
	c.JSON(http.StatusOK, gin.H{
		"message":     m,
		"messageCode": helpers.FormatMessageCode(m),
		"data":        userList,
	})
}

func UpdateUser(c *gin.Context) {
	userID, exists := c.Get("userId")
	if !exists {
		m := "Unauthorized"
		c.JSON(http.StatusUnauthorized, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m), "data": nil})
		return
	}

	var req struct {
		FullName         string `json:"fullName"`
		PhoneCountryCode string `json:"phoneCountryCode"`
		PhoneNumber      string `json:"phoneNumber"`
		Email            string `json:"email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error(), "messageCode": helpers.FormatMessageCode(err.Error()), "data": nil})
		return
	}

	var user models.User
	if err := initializers.DB.First(&user, userID).Error; err != nil {
		m := userNotFound
		c.JSON(http.StatusNotFound, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m), "data": nil})
		return
	}

	// Update user fields
	user.FullName = req.FullName
	user.PhoneCountryCode = req.PhoneCountryCode
	user.PhoneNumber = req.PhoneNumber
	user.PhoneComplete = req.PhoneCountryCode + req.PhoneNumber
	user.Email = req.Email

	if err := initializers.DB.Save(&user).Error; err != nil {
		m := "Failed to update user"
		c.JSON(http.StatusInternalServerError, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		return
	}

	m := "Profile updated successfully"
	c.JSON(http.StatusOK, gin.H{
		"message":     m,
		"messageCode": helpers.FormatMessageCode(m),
		"data": gin.H{
			"id":       user.ID,
			"fullName": user.FullName,
			"email":    user.Email,
			"role":     user.Role,
			"currency": user.Currency,
			"phone": gin.H{
				"countryCode": user.PhoneCountryCode,
				"number":      user.PhoneNumber,
				"complete":    user.PhoneComplete,
			},
		},
	})
}

func RequestPasswordReset(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	var user models.User
	if err := initializers.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		m := userNotFound
		c.JSON(http.StatusNotFound, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
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
		c.JSON(http.StatusInternalServerError, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
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
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	// Validate the password before hashing
	if !isValidPassword(req.Password) {
		m := "Password must be at least 8 characters"
		c.JSON(http.StatusBadRequest, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		return
	}

	var reset models.PasswordReset
	if err := initializers.DB.Where("token = ?", req.Token).First(&reset).Error; err != nil {
		m := "Invalid or expired token"
		c.JSON(http.StatusUnauthorized, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		return
	}

	if time.Now().After(reset.ExpiresAt) {
		m := "Token expired"
		c.JSON(http.StatusUnauthorized, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		initializers.DB.Delete(&reset)
		return
	}

	var user models.User
	if err := initializers.DB.First(&user, reset.UserID).Error; err != nil {
		m := "User not found"
		c.JSON(http.StatusNotFound, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		m := "Failed to hash password"
		c.JSON(http.StatusInternalServerError, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
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
		c.JSON(http.StatusUnauthorized, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		return
	}

	var req struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	// Validate the password before hashing
	if !isValidPassword(req.NewPassword) {
		m := "Password must be at least 8 characters"
		c.JSON(http.StatusBadRequest, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		return
	}

	var user models.User
	if err := initializers.DB.First(&user, userID).Error; err != nil {
		m := "User not found"
		c.JSON(http.StatusNotFound, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		return
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.OldPassword)); err != nil {
		m := "Old password is incorrect"
		c.JSON(http.StatusUnauthorized, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		m := "Failed to hash new password"
		c.JSON(http.StatusInternalServerError, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		return
	}

	// Update password in database
	user.PasswordHash = string(hashedPassword)
	if err := initializers.DB.Save(&user).Error; err != nil {
		m := "Failed to update password"
		c.JSON(http.StatusInternalServerError, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
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
		c.JSON(http.StatusUnauthorized, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		return
	}

	if time.Now().After(reset.ExpiresAt) {
		initializers.DB.Delete(&reset) // Clean up expired tokens
		m := "Token expired"
		c.JSON(http.StatusUnauthorized, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		return
	}

	m := "Token is valid"
	c.JSON(http.StatusOK, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
}
