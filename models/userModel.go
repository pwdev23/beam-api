package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	ID           uint           `json:"id"`
	CreatedAt    time.Time      `json:"createdAt"`
	UpdatedAt    time.Time      `json:"updatedAt"`
	DeletedAt    gorm.DeletedAt `json:"deletedAt,omitempty"`
	FullName     string         `json:"fullName"`
	Phone        string         `json:"phone"`
	Email        string         `json:"email"`
	Role         string         `json:"role"`
	PasswordHash string         `json:"passwordHash"`
}
