package models

import (
	"time"

	"gorm.io/gorm"
)

type DriverTopUp struct {
	gorm.Model
	ID              uint           `json:"id"`
	CreatedAt       time.Time      `json:"createdAt"`
	UpdatedAt       time.Time      `json:"updatedAt"`
	DeletedAt       gorm.DeletedAt `json:"deletedAt,omitempty"`
	DriverID        uint           `json:"driverId"`
	Amount          float64        `json:"amount"`
	TransactionType string         `json:"transactionType"`
	Description     string         `json:"description"`
}
