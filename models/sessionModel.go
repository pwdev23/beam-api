package models

import (
	"time"

	"gorm.io/gorm"
)

type Session struct {
	gorm.Model
	ID        uint           `json:"id"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `json:"deletedAt,omitempty"`
	UserID    uint           `json:"userId"`
	Token     string         `json:"token"`
	ExpiresAt time.Time      `json:"expiresAt"`
}
