package models

import (
	"time"

	"gorm.io/gorm"
)

type Driver struct {
	gorm.Model
	ID           uint           `json:"id"`
	CreatedAt    time.Time      `json:"createdAt"`
	UpdatedAt    time.Time      `json:"updatedAt"`
	DeletedAt    gorm.DeletedAt `json:"deletedAt,omitempty"`
	VehicleType  string         `json:"vehicleType"`
	VehiclePlate string         `json:"vehiclePlate"`
	Balance      float64        `json:"balance"`
	Status       string         `json:"status"`
}
