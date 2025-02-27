package main

import (
	"github.com/pwdev23/beam-api/initializers"
	"github.com/pwdev23/beam-api/models"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDB()
}

func main() {
	initializers.DB.AutoMigrate(
		&models.User{},
		&models.Driver{},
		&models.DriverIdentity{},
		&models.DriverTransaction{},
		&models.Session{},
		&models.PasswordReset{},
		&models.Ride{},
		&models.UserTransaction{},
		&models.PaymentMethod{},
		&models.DriverLocation{},
		&models.Rating{},
	)
}
