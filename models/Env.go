package models

import (
	"log"

	"github.com/spf13/viper"
)

type Env struct {
	DBHost              string `mapstructure:"DB_HOST"`
	DBPort              string `mapstructure:"DB_PORT"`
	DBUser              string `mapstructure:"DB_USER"`
	DBPass              string `mapstructure:"DB_PASS"`
	DBName              string `mapstructure:"DB_NAME"`
	JWT_SECRET          string `mapstructure:"JWT_SECRET"`
	BASIC_AUTH_USERNAME string `mapstructure:"BASIC_AUTH_USERNAME"`
	BASIC_AUTH_PASSWORD string `mapstructure:"BASIC_AUTH_PASSWORD"`
}

func NewEnv() *Env {
	env := Env{}
	viper.SetConfigFile(".env")

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal("Can't find the file .env : ", err)
	}

	err = viper.Unmarshal(&env)

	if err != nil {
		log.Fatal("Environment can't be loaded: ", err)
	}

	return &env
}
