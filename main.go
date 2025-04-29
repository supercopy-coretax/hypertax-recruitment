package main

import (
	"context"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/supercopy-coretax/hypertax-backend/configs"
	"github.com/supercopy-coretax/hypertax-backend/db"
	_ "github.com/supercopy-coretax/hypertax-backend/docs"
	"github.com/supercopy-coretax/hypertax-backend/handlers"
	"github.com/supercopy-coretax/hypertax-backend/models"
	httpSwagger "github.com/swaggo/http-swagger/v2"
)

// @title Hypertax API
// @version 1.0.0
// @description Indonesian Tax API
// @host localhost:8080

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @BasePath /api/v1
func main() {
	env := models.NewEnv()

	dbConfig := configs.DatabaseConfig{
		Host:     env.DBHost,
		Port:     env.DBPort,
		User:     env.DBUser,
		Password: env.DBPass,
		DBName:   env.DBName,
	}

	pool, err := db.NewPool(dbConfig)
	if err != nil {
		log.Fatal("Failed to create connection pool:", err)
	}
	defer pool.Close()

	if err := pool.Ping(context.Background()); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	handler := handlers.NewHandler()

	r := mux.NewRouter()

	api := r.PathPrefix("/api/v1").Subrouter()

	api.HandleFunc("/auth/login", handler.HandleLogin).Methods("POST")
	api.HandleFunc("/auth/logout", handler.HandleLogout).Methods("POST")
	api.HandleFunc("/auth/register", handler.HandleRegister).Methods("POST")

	api.HandleFunc("/wajibpajak", handler.GetWajibPajak).Methods("GET")
	api.HandleFunc("/lapor", handler.HandleLapor).Methods("POST")

	r.PathPrefix("/swagger").Handler(httpSwagger.Handler(
		httpSwagger.URL("http://localhost:8080/swagger/doc.json"),
	))

	log.Fatal(http.ListenAndServe(":8080", r))
}
