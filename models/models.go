package models

import (
	"time"

	"gorm.io/gorm"
)

type BaseModel struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `json:"deletedAt,omitempty"`
}

type DriverIdentity struct {
	BaseModel
	DriverID                  uint       `json:"driverId" gorm:"uniqueIndex;not null"`
	CountryCode               string     `json:"countryCode" gorm:"size:3;not null"` // ISO 2-digit code from ISO 3166-alpha-2 (e.g., "ID")
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
	BaseModel
	VehicleType  string         `json:"vehicleType" gorm:"size:50;not null"`
	VehiclePlate string         `json:"vehiclePlate" gorm:"size:20;unique;not null"`
	Balance      float64        `json:"balance" gorm:"default:0"`
	Status       string         `json:"status" gorm:"size:20;not null"`
	Identity     DriverIdentity `json:"identity" gorm:"foreignKey:DriverID;constraint:OnDelete:CASCADE;"`
}

type DriverTransaction struct {
	BaseModel
	DriverID        uint    `json:"driverId" gorm:"not null;index"`
	Amount          float64 `json:"amount" gorm:"not null"`
	TransactionType string  `json:"transactionType" gorm:"size:20;not null"` // e.g., "topup", "deduction"
	Description     string  `json:"description" gorm:"size:255"`
}

type Session struct {
	BaseModel
	UserID    uint      `json:"userId" gorm:"not null;index"`
	Token     string    `json:"token" gorm:"unique;not null"`
	ExpiresAt time.Time `json:"expiresAt" gorm:"not null"`
}

type User struct {
	BaseModel
	FullName     string `json:"fullName" gorm:"size:100;not null"`
	PhonePrefix  string `json:"phonePrefix" gorm:"size:10;not null"` // e.g., "+62"
	PhoneNumber  string `json:"phoneNumber" gorm:"size:20;not null"` // e.g., "8123456789"
	Email        string `json:"email" gorm:"size:100;unique"`
	Role         string `json:"role" gorm:"size:20;not null"` // e.g., "admin", "driver", "customer"
	PasswordHash string `json:"-" gorm:"not null"`
}

type PasswordReset struct {
	BaseModel
	UserID    uint      `json:"userId" gorm:"not null;index"`
	Token     string    `json:"token" gorm:"unique;not null"`
	ExpiresAt time.Time `json:"expiresAt"`
}
