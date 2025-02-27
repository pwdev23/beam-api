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
