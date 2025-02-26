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
		&models.DriverIdentity{},
		&models.Driver{},
		&models.DriverTopUp{},
		&models.Session{},
		&models.User{},
	)
}
