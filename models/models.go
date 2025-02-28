package models

import (
	"time"

	"github.com/lib/pq"
	"gorm.io/gorm"
)

type BaseModel struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `json:"deletedAt,omitempty"`
}

type User struct {
	BaseModel
	FullName         string  `json:"fullName" gorm:"size:100;not null"`
	PhoneCountryCode string  `json:"phoneCountryCode" gorm:"size:10;not null"`
	PhoneNumber      string  `json:"phoneNumber" gorm:"size:20;not null"`
	PhoneComplete    string  `json:"phoneComplete" gorm:"size:20;not null"`
	Email            string  `json:"email" gorm:"size:100;unique"`
	Role             string  `json:"role" gorm:"size:20;not null"`
	PasswordHash     string  `json:"-" gorm:"not null"`
	Currency         string  `json:"currency" gorm:"size:3;not null;default:'IDR'"` // Currency in ISO 4217 format (e.g., "IDR", "USD")
	Balance          float64 `json:"balance" gorm:"default:0"`
}

type DriverIdentity struct {
	BaseModel
	DriverID                  uint           `json:"driverId" gorm:"uniqueIndex;not null"`
	CountryCode               string         `json:"countryCode" gorm:"size:3;not null"` // ISO 3166-alpha-2 (e.g., "ID")
	NationalIDNumber          string         `json:"nationalIdNumber" gorm:"uniqueIndex;not null"`
	NationalIDURLs            pq.StringArray `json:"nationalIdUrls" gorm:"type:text[]"`
	DrivingLicenseNumber      string         `json:"drivingLicenseNumber" gorm:"uniqueIndex;not null"`
	DrivingLicenseURLs        pq.StringArray `json:"drivingLicenseUrls" gorm:"type:text[]"`
	VehicleRegistrationNumber string         `json:"vehicleRegistrationNumber" gorm:"uniqueIndex;not null"`
	VehicleRegistrationURLs   pq.StringArray `json:"vehicleRegistrationUrls" gorm:"type:text[]"`
	City                      string         `json:"city" gorm:"size:100"`
	Province                  string         `json:"province" gorm:"size:100"`
	NationalIDVerified        bool           `json:"nationalIdVerified" gorm:"default:false"`
	LicenseVerified           bool           `json:"licenseVerified" gorm:"default:false"`
	VehicleVerified           bool           `json:"vehicleVerified" gorm:"default:false"`
	VerifiedAt                *time.Time     `json:"verifiedAt"`
}

type Driver struct {
	BaseModel
	UserID       uint           `json:"userId" gorm:"uniqueIndex;not null"`
	User         User           `json:"user" gorm:"foreignKey:UserID"`
	VehicleType  string         `json:"vehicleType" gorm:"size:50;not null"`
	VehiclePlate string         `json:"vehiclePlate" gorm:"size:20;unique;not null"`
	Balance      float64        `json:"balance" gorm:"default:0"`
	Currency     string         `json:"currency" gorm:"size:3;not null;default:'IDR'"` // Currency in ISO 4217 format (e.g., "IDR", "USD")
	Status       string         `json:"status" gorm:"size:20;not null"`
	ProfilePic   string         `json:"profilePic"`   // URL of driver's profile picture
	VehiclePhoto string         `json:"vehiclePhoto"` // URL of uploaded vehicle photo
	Identity     DriverIdentity `json:"identity" gorm:"foreignKey:DriverID;constraint:OnDelete:CASCADE;"`
}

type DriverTransaction struct {
	BaseModel
	DriverID        uint    `json:"driverId" gorm:"not null;index"`
	Amount          float64 `json:"amount" gorm:"not null"`
	Currency        string  `json:"currency" gorm:"size:3;not null"`         // Ensure all transactions specify currency
	TransactionType string  `json:"transactionType" gorm:"size:20;not null"` // "topup" or "deduction"
	Description     string  `json:"description" gorm:"size:255"`
	ReferenceID     string  `json:"referenceId" gorm:"size:50;unique"` // Optional, for tracking payments
}

type Session struct {
	BaseModel
	UserID    uint      `json:"userId" gorm:"not null;index"`
	Token     string    `json:"token" gorm:"unique;not null"`
	ExpiresAt time.Time `json:"expiresAt" gorm:"not null"`
}

type PasswordReset struct {
	BaseModel
	UserID    uint      `json:"userId" gorm:"not null;index"`
	Token     string    `json:"token" gorm:"unique;not null"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type Ride struct {
	BaseModel
	UserID             uint       `json:"userId" gorm:"not null;index"`
	DriverID           uint       `json:"driverId" gorm:"not null;index"`
	PickupLocation     string     `json:"pickupLocation" gorm:"not null"`
	DropoffLocation    string     `json:"dropoffLocation" gorm:"not null"`
	PickupLatitude     float64    `json:"pickupLatitude"`
	PickupLongitude    float64    `json:"pickupLongitude"`
	DropoffLatitude    float64    `json:"dropoffLatitude"`
	DropoffLongitude   float64    `json:"dropoffLongitude"`
	Status             string     `json:"status" gorm:"not null"` // "pending", "accepted", "in_progress", "completed", "cancelled"
	RequestedAt        time.Time  `json:"requestedAt"`
	AcceptedAt         *time.Time `json:"acceptedAt"`
	StartedAt          *time.Time `json:"startedAt"`
	CompletedAt        *time.Time `json:"completedAt"`
	CancelledAt        *time.Time `json:"cancelledAt"`
	CancellationReason string     `json:"cancellationReason"`
	Fare               float64    `json:"fare"`
	Currency           string     `json:"currency" gorm:"size:3"`
	PaymentStatus      string     `json:"paymentStatus"`
	Rating             float32    `json:"rating"`
	Feedback           string     `json:"feedback"`
}

type UserTransaction struct {
	BaseModel
	UserID          uint    `json:"userId" gorm:"not null;index"`
	Amount          float64 `json:"amount" gorm:"not null"`
	Currency        string  `json:"currency" gorm:"size:3;not null"`
	TransactionType string  `json:"transactionType" gorm:"size:20;not null"` // "payment", "refund", etc.
	Description     string  `json:"description" gorm:"size:255"`
	ReferenceID     string  `json:"referenceId" gorm:"size:50;unique"`
	RideID          *uint   `json:"rideId" gorm:"index"` // Optional, to link to specific ride
}

type PaymentMethod struct {
	BaseModel
	UserID       uint   `json:"userId" gorm:"not null;index"`
	Type         string `json:"type" gorm:"not null"` // "credit_card", "digital_wallet", etc.
	IsDefault    bool   `json:"isDefault" gorm:"default:false"`
	LastFour     string `json:"lastFour" gorm:"size:4"` // Last 4 digits for cards
	PaymentToken string `json:"-" gorm:"size:255"`      // Token from payment processor
	ExpiryMonth  string `json:"expiryMonth" gorm:"size:2"`
	ExpiryYear   string `json:"expiryYear" gorm:"size:4"`
}

type DriverLocation struct {
	BaseModel
	DriverID    uint      `json:"driverId" gorm:"uniqueIndex;not null"`
	Latitude    float64   `json:"latitude" gorm:"not null"`
	Longitude   float64   `json:"longitude" gorm:"not null"`
	Heading     float64   `json:"heading"` // Direction in degrees
	Speed       float64   `json:"speed"`   // Speed in km/h
	UpdatedAt   time.Time `json:"updatedAt" gorm:"autoUpdateTime"`
	IsAvailable bool      `json:"isAvailable" gorm:"default:false"`
}

type Rating struct {
	BaseModel
	RideID         uint    `json:"rideId" gorm:"uniqueIndex;not null"`
	UserID         uint    `json:"userId" gorm:"not null;index"`
	DriverID       uint    `json:"driverId" gorm:"not null;index"`
	UserRating     float32 `json:"userRating"`   // Rating given by driver to user
	DriverRating   float32 `json:"driverRating"` // Rating given by user to driver
	UserFeedback   string  `json:"userFeedback"`
	DriverFeedback string  `json:"driverFeedback"`
}
