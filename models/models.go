package models

import (
	"time"

	"gorm.io/gorm"
)

type BaseModel struct {
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `json:"deletedAt,omitempty"`
}

type DriverIdentity struct {
	gorm.Model
	BaseModel
	ID                        uint       `json:"id" gorm:"primaryKey"`
	DriverID                  uint       `json:"driverId" gorm:"uniqueIndex;not null"`
	CountryCode               string     `json:"countryCode" gorm:"size:3;not null"`
	NationalIDNumber          string     `json:"nationalIdNumber" gorm:"unique;not null"`
	DrivingLicenseNumber      string     `json:"drivingLicenseNumber" gorm:"unique;not null"`
	VehicleRegistrationNumber string     `json:"vehicleRegistrationNumber" gorm:"unique;not null"`
	City                      string     `json:"city" gorm:"size:100"`
	Province                  string     `json:"province" gorm:"size:100"`
	NationalIDVerified        bool       `json:"nationalIdVerified" gorm:"default:false"`
	LicenseVerified           bool       `json:"licenseVerified" gorm:"default:false"`
	VehicleVerified           bool       `json:"vehicleVerified" gorm:"default:false"`
	VerifiedAt                *time.Time `json:"verifiedAt"`
}

type Driver struct {
	gorm.Model
	BaseModel
	ID           uint           `json:"id" gorm:"primaryKey"`
	VehicleType  string         `json:"vehicleType" gorm:"size:50;not null"`
	VehiclePlate string         `json:"vehiclePlate" gorm:"size:20;unique;not null"`
	Balance      float64        `json:"balance" gorm:"default:0"`
	Status       string         `json:"status" gorm:"size:20;not null"`
	Identity     DriverIdentity `json:"identity" gorm:"foreignKey:DriverID;constraint:OnDelete:CASCADE;"`
}

type DriverTopUp struct {
	gorm.Model
	BaseModel
	ID              uint    `json:"id" gorm:"primaryKey"`
	DriverID        uint    `json:"driverId" gorm:"not null;index"`
	Amount          float64 `json:"amount" gorm:"not null"`
	TransactionType string  `json:"transactionType" gorm:"size:20;not null"`
	Description     string  `json:"description" gorm:"size:255"`
}

type Session struct {
	gorm.Model
	BaseModel
	ID        uint      `json:"id" gorm:"primaryKey"`
	UserID    uint      `json:"userId" gorm:"not null;index"`
	Token     string    `json:"token" gorm:"unique;not null"`
	ExpiresAt time.Time `json:"expiresAt" gorm:"not null"`
}

type User struct {
	gorm.Model
	BaseModel
	ID           uint   `json:"id" gorm:"primaryKey"`
	FullName     string `json:"fullName" gorm:"size:100;not null"`
	Phone        string `json:"phone" gorm:"size:20;unique;not null"`
	Email        string `json:"email" gorm:"size:100;unique"`
	Role         string `json:"role" gorm:"size:20;not null"`
	PasswordHash string `json:"passwordHash" gorm:"not null"`
}
