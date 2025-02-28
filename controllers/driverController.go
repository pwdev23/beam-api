package controllers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/pwdev23/beam-api/helpers"
	"github.com/pwdev23/beam-api/initializers"
	"github.com/pwdev23/beam-api/models"
)

func GetAllDrivers(c *gin.Context) {
	var drivers []models.Driver
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	offset := (page - 1) * limit

	if err := initializers.DB.Limit(limit).Offset(offset).Find(&drivers).Error; err != nil {
		m := "Failed to fetch drivers"
		c.JSON(http.StatusInternalServerError, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m), "data": nil})
		return
	}

	m := "Drivers retrieved successfully"
	c.JSON(http.StatusOK, gin.H{
		"message":     m,
		"messageCode": helpers.FormatMessageCode(m),
		"data":        drivers,
	})
}

func GetDriverByID(c *gin.Context) {
	driverID := c.Param("id")
	var driver models.Driver

	if err := initializers.DB.Preload("User").First(&driver, driverID).Error; err != nil {
		m := "Driver not found"
		c.JSON(http.StatusNotFound, gin.H{
			"message":     m,
			"messageCode": helpers.FormatMessageCode(m),
		})
		return
	}

	m := "Driver retrieved successfully"
	c.JSON(http.StatusOK, gin.H{
		"message":     m,
		"messageCode": helpers.FormatMessageCode(m),
		"data":        driver,
	})
}

func TopUpBalance(c *gin.Context) {
	var input struct {
		DriverID uint    `json:"driverId"`
		Amount   float64 `json:"amount"`
	}

	// Bind JSON
	if err := c.ShouldBindJSON(&input); err != nil {
		m := "Invalid input"
		c.JSON(http.StatusBadRequest, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		return
	}

	var driver models.Driver
	if err := initializers.DB.First(&driver, input.DriverID).Error; err != nil {
		m := "Driver not found"
		c.JSON(http.StatusNotFound, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		return
	}

	// Update driver balance
	driver.Balance += input.Amount
	if err := initializers.DB.Save(&driver).Error; err != nil {
		m := "Failed to top up balance"
		c.JSON(http.StatusInternalServerError, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		return
	}

	m := "Balance topped up successfully"
	c.JSON(http.StatusOK, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m), "data": driver})
}

func UpdateDriver(c *gin.Context) {
	// Get userID from JWT context
	userID, exists := c.Get("userId")
	if !exists {
		m := "Unauthorized"
		c.JSON(http.StatusUnauthorized, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m), "data": nil})
		return
	}

	var driver models.Driver
	// Find driver associated with the authenticated user, preload all relationships
	if err := initializers.DB.Preload("User").Preload("Identity").Where("user_id = ?", userID).First(&driver).Error; err != nil {
		m := "Driver not found"
		c.JSON(http.StatusNotFound, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		return
	}

	var req struct {
		// User fields
		FullName         string `json:"fullName"`
		PhoneCountryCode string `json:"phoneCountryCode"`
		PhoneNumber      string `json:"phoneNumber"`
		Email            string `json:"email"`

		// Driver fields
		VehicleType  string   `json:"vehicleType"`
		VehiclePlate string   `json:"vehiclePlate"`
		Status       string   `json:"status"`
		Balance      *float64 `json:"balance"`
		Currency     string   `json:"currency"`
		ProfilePic   string   `json:"profilePic"`
		VehiclePhoto string   `json:"vehiclePhoto"`

		// Identity fields
		CountryCode               string   `json:"countryCode"`
		NationalIDNumber          string   `json:"nationalIdNumber"`
		NationalIDURLs            []string `json:"nationalIdUrls"`
		DrivingLicenseNumber      string   `json:"drivingLicenseNumber"`
		DrivingLicenseURLs        []string `json:"drivingLicenseUrls"`
		VehicleRegistrationNumber string   `json:"vehicleRegistrationNumber"`
		VehicleRegistrationURLs   []string `json:"vehicleRegistrationUrls"`
		City                      string   `json:"city"`
		Province                  string   `json:"province"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		m := "Invalid request payload"
		c.JSON(http.StatusBadRequest, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		return
	}

	// Update driver fields, keeping old values if request fields are empty
	if req.VehicleType != "" {
		driver.VehicleType = req.VehicleType
	}
	if req.VehiclePlate != "" {
		driver.VehiclePlate = req.VehiclePlate
	}
	if req.Status != "" {
		driver.Status = req.Status
	}
	if req.Currency != "" {
		driver.Currency = req.Currency
	}
	if req.Balance != nil {
		driver.Balance = *req.Balance
	}
	if req.ProfilePic != "" {
		driver.ProfilePic = req.ProfilePic
	}
	if req.VehiclePhoto != "" {
		driver.VehiclePhoto = req.VehiclePhoto
	}

	// Update user fields, keeping old values if request fields are empty
	if req.FullName != "" {
		driver.User.FullName = req.FullName
	}
	if req.PhoneCountryCode != "" {
		driver.User.PhoneCountryCode = req.PhoneCountryCode
	}
	if req.PhoneNumber != "" {
		driver.User.PhoneNumber = req.PhoneNumber
	}

	// Only update PhoneComplete if either PhoneCountryCode or PhoneNumber has been updated
	if req.PhoneCountryCode != "" || req.PhoneNumber != "" {
		driver.User.PhoneComplete = driver.User.PhoneCountryCode + driver.User.PhoneNumber
	}

	if req.Email != "" {
		driver.User.Email = req.Email
	}

	// Check if Identity needs to be created
	if driver.Identity.ID == 0 {
		driver.Identity = models.DriverIdentity{
			DriverID: driver.ID,
		}
	}

	// Update identity fields, keeping old values if request fields are empty
	if req.CountryCode != "" {
		driver.Identity.CountryCode = req.CountryCode
	}
	if req.NationalIDNumber != "" {
		driver.Identity.NationalIDNumber = req.NationalIDNumber
	}
	if len(req.NationalIDURLs) > 0 {
		driver.Identity.NationalIDURLs = req.NationalIDURLs
	}
	if req.DrivingLicenseNumber != "" {
		driver.Identity.DrivingLicenseNumber = req.DrivingLicenseNumber
	}
	if len(req.DrivingLicenseURLs) > 0 {
		driver.Identity.DrivingLicenseURLs = req.DrivingLicenseURLs
	}
	if req.VehicleRegistrationNumber != "" {
		driver.Identity.VehicleRegistrationNumber = req.VehicleRegistrationNumber
	}
	if len(req.VehicleRegistrationURLs) > 0 {
		driver.Identity.VehicleRegistrationURLs = req.VehicleRegistrationURLs
	}
	if req.City != "" {
		driver.Identity.City = req.City
	}
	if req.Province != "" {
		driver.Identity.Province = req.Province
	}

	// Use a transaction to ensure atomicity of the update
	tx := initializers.DB.Begin()

	// Save driver (which includes relationships)
	if err := tx.Save(&driver).Error; err != nil {
		tx.Rollback()
		m := "Failed to update driver"
		c.JSON(http.StatusInternalServerError, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		return
	}

	// Save user
	if err := tx.Save(&driver.User).Error; err != nil {
		tx.Rollback()
		m := "Failed to update user details"
		c.JSON(http.StatusInternalServerError, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		return
	}

	// Save or create identity
	if driver.Identity.ID == 0 {
		if err := tx.Create(&driver.Identity).Error; err != nil {
			tx.Rollback()
			m := "Failed to create driver identity"
			c.JSON(http.StatusInternalServerError, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
			return
		}
	} else {
		if err := tx.Save(&driver.Identity).Error; err != nil {
			tx.Rollback()
			m := "Failed to update driver identity"
			c.JSON(http.StatusInternalServerError, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
			return
		}
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		m := "Failed to commit transaction"
		c.JSON(http.StatusInternalServerError, gin.H{"message": m, "messageCode": helpers.FormatMessageCode(m)})
		return
	}

	// Reload the driver with all relationships to get the updated data
	initializers.DB.Preload("User").Preload("Identity").First(&driver, driver.ID)

	m := "Driver updated successfully"
	c.JSON(http.StatusOK, gin.H{
		"message":     m,
		"messageCode": helpers.FormatMessageCode(m),
		"data":        driver,
	})
}
