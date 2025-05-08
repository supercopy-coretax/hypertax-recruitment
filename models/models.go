package models

import (
	"database/sql"
	"time"
)

type TaxPayersResponse struct {
	ID                int                 `json:"id"`
	NPWP              string              `json:"npwp"`
	FirstName         string              `json:"first_name"`
	LastName          string              `json:"last_name"`
	DateOfBirth       string              `json:"date_of_birth"`
	ProfilePictureURL string              `json:"profile_picture_url"`
	Address           string              `json:"address"`
	Phone             string              `json:"phone"`
	Email             string              `json:"email"`
	TaxReports        []TaxReportResponse `json:"tax_reports"`
	CreatedAt         time.Time           `json:"created_at"`
}

type TaxPayersEntity struct {
	ID                int
	NPWP              string
	FirstName         string
	LastName          string
	DateOfBirth       string
	ProfilePictureURL sql.NullString
	Address           sql.NullString
	Phone             string
	Email             string
	TaxReports        []TaxReportResponse
	CreatedAt         time.Time
}

type TaxReportResponse struct {
	TaxCategory string  `json:"tax_category"`
	TaxAmout    float64 `json:"tax_amount"`
	TaxPeriod   int     `json:"tax_period"`
}

type TaxReportRequest struct {
	UserId      int     `json:"user_id"`
	TaxCategory string  `json:"tax_category"`
	TaxAmout    float64 `json:"tax_amount"`
	TaxPeriod   int     `json:"tax_period"`
}

type User struct {
	ID                int       `json:"id"`
	Username          string    `json:"username"`
	Email             string    `json:"email"`
	NPWP              string    `json:"npwp"`
	PhoneNumber       string    `json:"phone_number"`
	Address           string    `json:"address"`
	FirstName         string    `json:"first_name"`
	LastName          string    `json:"last_name"`
	DateOfBirth       string    `json:"date_of_birth"`
	ProfilePictureURL string    `json:"profile_picture_url"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type RegisterUserRequest struct {
	Username             string    `json:"username"`
	Password             string    `json:"password"`
	PasswordConfirmation string    `json:"password_confirmation"`
	Email                string    `json:"email"`
	NPWP                 string    `json:"npwp,omitempty"`
	PhoneNumber          string    `json:"phone_number,omitempty"`
	Address              string    `json:"address,omitempty"`
	FirstName            string    `json:"first_name,omitempty"`
	LastName             string    `json:"last_name,omitempty"`
	DateOfBirth          string    `json:"date_of_birth,omitempty"` // Format: YYYY-MM-DD
	ProfilePictureURL    string    `json:"profile_picture_url,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type LoginUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Message string `json:"message"`
	Data    User   `json:"data"`
	Token   string `json:"token"`
}

type VoidResponse struct {
	Message string `json:"message"`
}
