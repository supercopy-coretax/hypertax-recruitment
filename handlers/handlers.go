package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/supercopy-coretax/hypertax-backend/models"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	dbPool *pgxpool.Pool
	env    *models.Env
}

func NewHandler(dbPool *pgxpool.Pool, env *models.Env) *Handler {
	return &Handler{
		dbPool: dbPool,
		env:    env,
	}
}

// @Summary Get list of tax payers
// @Description Get all registered tax payers
// @Tags wajibpajak
// @Accept json
// @Produce json
// @Success 200 {array} models.WajibPajak
// @Router /wajibpajak [get]
func (h *Handler) GetWajibPajak(w http.ResponseWriter, r *http.Request) {
	// Implementation
}

// @Summary Submit tax report
// @Description Submit a new tax report
// @Tags lapor
// @Accept json
// @Produce json
// @Param report body models.LaporPajak true "Tax Report"
// @Success 201 {object} models.LaporPajak
// @Router /lapor [post]
func (h *Handler) HandleLapor(w http.ResponseWriter, r *http.Request) {
	// Implementation
}

// @Summary Login user
// @Description Authenticate user and return token
// @Tags auth
// @Accept json
// @Produce json
// @Param credentials body models.LoginUserRequest true "User credentials"
// @Success 200 {object} models.LoginResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Security BasicAuth
// @Router /auth/login [post]
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var loginRequest models.LoginUserRequest
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		h.sendError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if loginRequest.Username == "" || loginRequest.Password == "" {
		h.sendError(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	query := `
		SELECT id, username, email, password
		FROM users
		WHERE username = $1`

	var user models.User
	var hashedPassword string

	err := h.dbPool.QueryRow(
		r.Context(),
		query,
		loginRequest.Username,
	).Scan(&user.ID, &user.Username, &user.Email, &hashedPassword)

	if err != nil {
		h.sendError(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(loginRequest.Password))
	if err != nil {
		h.sendError(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString([]byte(h.env.JWT_SECRET))

	if err != nil {
		h.sendError(w, "Error signing token", http.StatusInternalServerError)
		return
	}

	response := models.LoginResponse{
		Message: "Login successful",
		Data:    user,
		Token:   tokenString,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// @Summary Logout user
// @Description Invalidate user token
// @Tags auth
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string
// @Router /auth/logout [post]
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	// Implementation
}

// @Summary Register new user
// @Description Register a new user account
// @Tags auth
// @Accept json
// @Produce json
// @Param user body models.RegisterUserRequest true "User Registration Details"
// @Success 201 {object} models.VoidResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Security BasicAuth
// @Router /auth/register [post]
func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	var user models.RegisterUserRequest
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		h.sendError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if user.Username == "" || user.Password == "" || user.Email == "" {
		h.sendError(w, "Username, password and email are required", http.StatusBadRequest)
		return
	}

	if user.Password != user.PasswordConfirmation {
		h.sendError(w, "Password and confirmation do not match", http.StatusBadRequest)
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		h.sendError(w, "Error processing password", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	query := `
		INSERT INTO users (username, password, email, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING username`

	err = h.dbPool.QueryRow(
		r.Context(),
		query,
		user.Username,
		hashedPassword,
		user.Email,
		user.CreatedAt,
		user.UpdatedAt,
	).Scan(&user.Username)

	if err != nil {
		if strings.Contains(err.Error(), "SQLSTATE 23505") {
			if strings.Contains(err.Error(), "users_username_key") {
				h.sendError(w, "Username already exists", http.StatusConflict)
				return
			}
			if strings.Contains(err.Error(), "users_email_key") {
				h.sendError(w, "Email already exists", http.StatusConflict)
				return
			}
		}
		// Log the actual error for debugging
		log.Printf("Registration error: %v", err)
		h.sendError(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	response := models.VoidResponse{
		Message: fmt.Sprintf("User %s registered successfully", user.Username),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// Add this helper method to Handler struct
func (h *Handler) sendError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(models.NewErrorResponse(message))
}
