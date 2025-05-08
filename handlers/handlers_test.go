package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/supercopy-coretax/hypertax-backend/models"
	"github.com/supercopy-coretax/hypertax-backend/pkg"
)

func executeMigrations(pool *pgxpool.Pool, direction string) error {
	ctx := context.Background()
	migrationsDir := "../db/migrations"
	files, err := os.ReadDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	var migrationFiles []string
	for _, file := range files {
		if strings.HasSuffix(file.Name(), fmt.Sprintf(".%s.sql", direction)) {
			migrationFiles = append(migrationFiles, file.Name())
		}
	}

	sort.Strings(migrationFiles)

	if direction == "down" {
		for i := len(migrationFiles)/2 - 1; i >= 0; i-- {
			opp := len(migrationFiles) - 1 - i
			migrationFiles[i], migrationFiles[opp] = migrationFiles[opp], migrationFiles[i]
		}
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, fileName := range migrationFiles {
		filePath := filepath.Join(migrationsDir, fileName)
		content, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", fileName, err)
		}

		_, err = tx.Exec(ctx, string(content))
		if err != nil {
			return fmt.Errorf("failed to execute migration %s: %w", fileName, err)
		}
	}

	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func migrateUp(pool *pgxpool.Pool) error {
	return executeMigrations(pool, "up")
}

func migrateDown(pool *pgxpool.Pool) error {
	return executeMigrations(pool, "down")
}

func setupTestDB(t *testing.T, env *models.Env) *pgxpool.Pool {
	t.Helper()

	dburl := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?%s",
		env.DBUser,
		env.DBPass,
		env.DBHost,
		env.DBPort,
		env.DBName,
		"sslmode=disable",
	)

	pool, err := pgxpool.New(context.Background(), dburl)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	if err := migrateDown(pool); err != nil {
		t.Fatalf("Failed to clean database: %v", err)
	}
	if err := migrateUp(pool); err != nil {
		t.Fatalf("Failed to migrate database: %v", err)
	}

	return pool
}

func createRouter(pool *pgxpool.Pool, env *models.Env) *mux.Router {
	handler := NewHandler(pool, env)
	r := mux.NewRouter()

	authRouter := r.PathPrefix("/auth").Subrouter()
	authRouter.Use(pkg.BasicAuthMiddleware)
	authRouter.HandleFunc("/register", handler.HandleRegister).Methods("POST")

	return r
}

var env = &models.Env{
	DBHost:              "localhost",
	DBPort:              "5432",
	DBUser:              "bayazidsustamimn",
	DBPass:              "",
	DBName:              "hypertax",
	JWT_SECRET:          "garfields",
	BASIC_AUTH_PASSWORD: `garfield"`,
	BASIC_AUTH_USERNAME: `lasagna`,
}

func TestHandleRegister(t *testing.T) {

	pkg.SetEnv(env)

	pool := setupTestDB(t, env)
	defer pool.Close()

	router := createRouter(pool, env)

	tests := []struct {
		name           string
		requestBody    models.RegisterUserRequest
		setupFunc      func(*pgxpool.Pool)
		expectedStatus int
		expectedMsg    string
	}{
		{
			name: "Success - Valid Registration",
			requestBody: models.RegisterUserRequest{
				Username:             "testuser",
				Password:             "password123",
				PasswordConfirmation: "password123",
				Email:                "test@example.com",
				NPWP:                 "123456789012345",
				PhoneNumber:          "081234567890",
				FirstName:            "Test",
				LastName:             "User",
				DateOfBirth:          "1990-01-01",
				Address:              "Test Address",
			},
			expectedStatus: http.StatusCreated,
			expectedMsg:    "User testuser registered successfully",
		},
		{
			name: "Failure - Missing Required Fields",
			requestBody: models.RegisterUserRequest{
				Username:             "incomplete",
				Password:             "password123",
				PasswordConfirmation: "password123",
			},
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Username, password and email are required",
		},
		{
			name: "Failure - Password Mismatch",
			requestBody: models.RegisterUserRequest{
				Username:             "testuser2",
				Password:             "password123",
				PasswordConfirmation: "different",
				Email:                "test2@example.com",
			},
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Password and confirmation do not match",
		},
		{
			name: "Failure - Invalid Date Format",
			requestBody: models.RegisterUserRequest{
				Username:             "testuser3",
				Password:             "password123",
				PasswordConfirmation: "password123",
				Email:                "test3@example.com",
				DateOfBirth:          "not-a-date",
			},
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Invalid date format",
		},
		{
			name: "Failure - Duplicate Username",
			requestBody: models.RegisterUserRequest{
				Username:             "duplicate_user",
				Password:             "password123",
				PasswordConfirmation: "password123",
				Email:                "unique@example.com",
			},
			setupFunc: func(pool *pgxpool.Pool) {
				ctx := context.Background()
				_, err := pool.Exec(ctx,
					`INSERT INTO users (username, password, email, created_at, updated_at) 
					 VALUES ($1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
					"duplicate_user", "hashedpw", "existing@example.com")
				if err != nil {
					t.Fatalf("Failed to set up duplicate user: %v", err)
				}
			},
			expectedStatus: http.StatusConflict,
			expectedMsg:    "Username already exists",
		},
		{
			name: "Failure - Duplicate Email",
			requestBody: models.RegisterUserRequest{
				Username:             "unique_user",
				Password:             "password123",
				PasswordConfirmation: "password123",
				Email:                "duplicate@example.com",
			},
			setupFunc: func(pool *pgxpool.Pool) {
				ctx := context.Background()
				_, err := pool.Exec(ctx,
					`INSERT INTO users (username, password, email, created_at, updated_at) 
					 VALUES ($1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
					"existing_user", "hashedpw", "duplicate@example.com")
				if err != nil {
					t.Fatalf("Failed to set up duplicate email: %v", err)
				}
			},
			expectedStatus: http.StatusConflict,
			expectedMsg:    "Email already exists",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			if err := migrateDown(pool); err != nil {
				t.Fatalf("Failed to clean database: %v", err)
			}
			if err := migrateUp(pool); err != nil {
				t.Fatalf("Failed to migrate database: %v", err)
			}

			if tc.setupFunc != nil {
				tc.setupFunc(pool)
			}

			jsonBody, err := json.Marshal(tc.requestBody)
			if err != nil {
				t.Fatalf("Failed to marshal request body: %v", err)
			}

			req, err := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(jsonBody))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			req.Header.Set("Content-Type", "application/json")
			req.SetBasicAuth(env.BASIC_AUTH_USERNAME, env.BASIC_AUTH_PASSWORD)

			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			if status := rr.Code; status != tc.expectedStatus {
				t.Errorf("Handler returned wrong status code: got %v, want %v", status, tc.expectedStatus)
			}

			var response map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			var actualMsg string
			if msg, ok := response["message"]; ok && tc.expectedStatus == http.StatusCreated {
				actualMsg = msg.(string)
			} else if reason, ok := response["reason"]; ok {
				actualMsg = reason.(string)
			}

			if !strings.Contains(actualMsg, tc.expectedMsg) {
				t.Errorf("Response body did not contain expected message: got %v, want %v", actualMsg, tc.expectedMsg)
			}

			if tc.expectedStatus == http.StatusCreated {
				var count int
				err := pool.QueryRow(context.Background(),
					"SELECT COUNT(*) FROM users WHERE username = $1",
					tc.requestBody.Username).Scan(&count)

				if err != nil {
					t.Fatalf("Failed to query database: %v", err)
				}

				if count != 1 {
					t.Errorf("User was not created in the database")
				}
			}
		})
	}
}

func TestHandleLogin(t *testing.T) {

	pkg.SetEnv(env)

	pool := setupTestDB(t, env)
	defer pool.Close()

	handler := NewHandler(pool, env)
	r := mux.NewRouter()
	authRouter := r.PathPrefix("/auth").Subrouter()
	authRouter.Use(pkg.BasicAuthMiddleware)
	authRouter.HandleFunc("/login", handler.HandleLogin).Methods("POST")

	if err := migrateDown(pool); err != nil {
		t.Fatalf("Failed to clean database: %v", err)
	}
	if err := migrateUp(pool); err != nil {
		t.Fatalf("Failed to migrate database: %v", err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	ctx := context.Background()
	_, err = pool.Exec(ctx,
		`INSERT INTO users (username, password, email, created_at, updated_at) 
		VALUES ($1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		"testuser", string(hashedPassword), "test@example.com")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	var count int
	err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE username = $1", "testuser").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to verify test user creation: %v", err)
	}
	if count != 1 {
		t.Fatalf("Test user was not created properly")
	}

	tests := []struct {
		name           string
		requestBody    models.LoginUserRequest
		expectedStatus int
		expectedMsg    string
		checkToken     bool
	}{
		{
			name: "Success - Valid Login",
			requestBody: models.LoginUserRequest{
				Username: "testuser",
				Password: "password123",
			},
			expectedStatus: http.StatusOK,
			expectedMsg:    "Login successful",
			checkToken:     true,
		},
		{
			name: "Failure - Invalid Username",
			requestBody: models.LoginUserRequest{
				Username: "nonexistent",
				Password: "password123",
			},
			expectedStatus: http.StatusUnauthorized,
			expectedMsg:    "Invalid username or password",
		},
		{
			name: "Failure - Invalid Password",
			requestBody: models.LoginUserRequest{
				Username: "testuser",
				Password: "wrongpassword",
			},
			expectedStatus: http.StatusUnauthorized,
			expectedMsg:    "Invalid username or password",
		},
		{
			name: "Failure - Missing Credentials",
			requestBody: models.LoginUserRequest{
				Username: "testuser",
			},
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Username and password are required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jsonBody, err := json.Marshal(tc.requestBody)
			if err != nil {
				t.Fatalf("Failed to marshal request body: %v", err)
			}

			req, err := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(jsonBody))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			req.Header.Set("Content-Type", "application/json")
			req.SetBasicAuth(env.BASIC_AUTH_USERNAME, env.BASIC_AUTH_PASSWORD)

			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			t.Logf("Response status: %d", rr.Code)
			t.Logf("Response body: %s", rr.Body.String())

			if status := rr.Code; status != tc.expectedStatus {
				t.Errorf("Handler returned wrong status code: got %v, want %v", status, tc.expectedStatus)
			}

			var response map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			var actualMsg string
			if msg, ok := response["message"]; ok && tc.expectedStatus == http.StatusOK {
				actualMsg = msg.(string)
			} else if reason, ok := response["reason"]; ok {
				actualMsg = reason.(string)
			}

			if !strings.Contains(actualMsg, tc.expectedMsg) {
				t.Errorf("Response body did not contain expected message: got %v, want %v", actualMsg, tc.expectedMsg)
			}

			if tc.checkToken {
				token, ok := response["token"]
				if !ok || token.(string) == "" {
					t.Error("Expected token in response but got none")
				}
			}
		})
	}
}

func TestHandleLogout(t *testing.T) {

	pkg.SetEnv(env)

	pool := setupTestDB(t, env)
	defer pool.Close()

	handler := NewHandler(pool, env)
	r := mux.NewRouter()

	protectedRouter := r.PathPrefix("/auth").Subrouter()
	protectedRouter.Use(pkg.JWTMiddleware)
	protectedRouter.HandleFunc("/logout", handler.HandleLogout).Methods("POST")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": "testuser",
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString([]byte(env.JWT_SECRET))
	if err != nil {
		t.Fatalf("Failed to generate JWT token: %v", err)
	}

	tests := []struct {
		name           string
		setupAuth      func(*http.Request)
		expectedStatus int
		expectedMsg    string
	}{
		{
			name: "Success - Valid Logout",
			setupAuth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+tokenString)
			},
			expectedStatus: http.StatusOK,
			expectedMsg:    "Logout successful",
		},
		{
			name: "Failure - No Authorization",
			setupAuth: func(req *http.Request) {

			},
			expectedStatus: http.StatusUnauthorized,
			expectedMsg:    "Unauthorized",
		},
		{
			name: "Failure - Invalid Token",
			setupAuth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer invalidtoken")
			},
			expectedStatus: http.StatusUnauthorized,
			expectedMsg:    "Unauthorized",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", "/auth/logout", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			req.Header.Set("Content-Type", "application/json")
			if tc.setupAuth != nil {
				tc.setupAuth(req)
			}

			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			if status := rr.Code; status != tc.expectedStatus {
				t.Errorf("Handler returned wrong status code: got %v, want %v", status, tc.expectedStatus)
			}

			var response map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			var actualMsg string
			if msg, ok := response["message"]; ok && tc.expectedStatus == http.StatusOK {
				actualMsg = msg.(string)
			} else if reason, ok := response["reason"]; ok {
				actualMsg = reason.(string)
			}

			if !strings.Contains(actualMsg, tc.expectedMsg) {
				t.Errorf("Response body did not contain expected message: got %v, want %v", actualMsg, tc.expectedMsg)
			}
		})
	}
}

func TestHandleLapor(t *testing.T) {

	pkg.SetEnv(env)

	pool := setupTestDB(t, env)
	defer pool.Close()

	handler := NewHandler(pool, env)
	r := mux.NewRouter()

	protectedRouter := r.PathPrefix("/").Subrouter()
	protectedRouter.Use(pkg.JWTMiddleware)
	protectedRouter.HandleFunc("/lapor", handler.HandleLapor).Methods("POST")

	ctx := context.Background()
	var userId int
	err := pool.QueryRow(ctx,
		`INSERT INTO users (username, password, email, created_at, updated_at) 
		VALUES ($1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) RETURNING id`,
		"testuser", "hashedpw", "test@example.com").Scan(&userId)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": "testuser",
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString([]byte(env.JWT_SECRET))
	if err != nil {
		t.Fatalf("Failed to generate JWT token: %v", err)
	}

	tests := []struct {
		name           string
		requestBody    models.TaxReportRequest
		setupAuth      func(*http.Request)
		expectedStatus int
		expectedMsg    string
	}{
		{
			name: "Success - Valid Tax Report",
			requestBody: models.TaxReportRequest{
				UserId:      userId,
				TaxCategory: "OP",
				TaxAmout:    5000000.00,
				TaxPeriod:   2023,
			},
			setupAuth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+tokenString)
			},
			expectedStatus: http.StatusCreated,
			expectedMsg:    "Tax report submitted successfully",
		},
		{
			name: "Failure - No Authorization",
			requestBody: models.TaxReportRequest{
				UserId:      userId,
				TaxCategory: "OP",
				TaxAmout:    5000000.00,
				TaxPeriod:   2023,
			},
			setupAuth:      func(req *http.Request) {},
			expectedStatus: http.StatusUnauthorized,
			expectedMsg:    "Unauthorized",
		},
		{
			name: "Failure - Invalid Tax Category",
			requestBody: models.TaxReportRequest{
				UserId:      userId,
				TaxCategory: "INVALID",
				TaxAmout:    5000000.00,
				TaxPeriod:   2023,
			},
			setupAuth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+tokenString)
			},
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Invalid tax category",
		},
		{
			name: "Failure - Invalid Tax Amount",
			requestBody: models.TaxReportRequest{
				UserId:      userId,
				TaxCategory: "OP",
				TaxAmout:    -5000.00,
				TaxPeriod:   2023,
			},
			setupAuth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+tokenString)
			},
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Invalid tax amount",
		},
		{
			name: "Failure - Invalid Tax Period",
			requestBody: models.TaxReportRequest{
				UserId:      userId,
				TaxCategory: "OP",
				TaxAmout:    5000000.00,
				TaxPeriod:   0,
			},
			setupAuth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+tokenString)
			},
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Invalid tax period",
		},
		{
			name: "Failure - Missing Tax Category",
			requestBody: models.TaxReportRequest{
				UserId:    userId,
				TaxAmout:  5000000.00,
				TaxPeriod: 2023,
			},
			setupAuth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+tokenString)
			},
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Tax category is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jsonBody, err := json.Marshal(tc.requestBody)
			if err != nil {
				t.Fatalf("Failed to marshal request body: %v", err)
			}

			req, err := http.NewRequest("POST", "/lapor", bytes.NewBuffer(jsonBody))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			req.Header.Set("Content-Type", "application/json")
			if tc.setupAuth != nil {
				tc.setupAuth(req)
			}

			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			if status := rr.Code; status != tc.expectedStatus {
				t.Errorf("Handler returned wrong status code: got %v, want %v", status, tc.expectedStatus)
			}

			var response map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			var actualMsg string
			if msg, ok := response["message"]; ok && tc.expectedStatus == http.StatusCreated {
				actualMsg = msg.(string)
			} else if reason, ok := response["reason"]; ok {
				actualMsg = reason.(string)
			}

			if !strings.Contains(actualMsg, tc.expectedMsg) {
				t.Errorf("Response body did not contain expected message: got %v, want %v", actualMsg, tc.expectedMsg)
			}

			if tc.expectedStatus == http.StatusCreated {
				var count int
				err := pool.QueryRow(context.Background(),
					"SELECT COUNT(*) FROM tax_reports WHERE user_id = $1",
					tc.requestBody.UserId).Scan(&count)

				if err != nil {
					t.Fatalf("Failed to query database: %v", err)
				}

				if count != 1 {
					t.Errorf("Tax report was not created in the database")
				}
			}
		})
	}
}

func TestGetWajibPajak(t *testing.T) {

	pkg.SetEnv(env)

	pool := setupTestDB(t, env)
	defer pool.Close()

	handler := NewHandler(pool, env)
	r := mux.NewRouter()

	protectedRouter := r.PathPrefix("/").Subrouter()
	protectedRouter.Use(pkg.JWTMiddleware)
	protectedRouter.HandleFunc("/wajibpajak", handler.GetWajibPajak).Methods("GET")

	ctx := context.Background()

	var userId1 int
	err := pool.QueryRow(ctx,
		`INSERT INTO users (username, password, email, first_name, last_name, npwp, phone_number, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) RETURNING id`,
		"user1", "hashedpw", "user1@example.com", "John", "Doe", "123456789012345", "081234567890").Scan(&userId1)
	if err != nil {
		t.Fatalf("Failed to create test user 1: %v", err)
	}

	var userId2 int
	err = pool.QueryRow(ctx,
		`INSERT INTO users (username, password, email, first_name, last_name, npwp, phone_number, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) RETURNING id`,
		"user2", "hashedpw", "user2@example.com", "Jane", "Smith", "23.456.789.0-345.678", "082345678901").Scan(&userId2)
	if err != nil {
		t.Fatalf("Failed to create test user 2: %v", err)
	}

	_, err = pool.Exec(ctx,
		`INSERT INTO tax_reports (user_id, tax_amount, status, tax_period, tax_category, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5, $6, $6)`,
		userId1, 5000000.00, "pending", 2023, "OP", "2023-05-15T00:00:00Z")
	if err != nil {
		t.Fatalf("Failed to create tax report for user 1: %v", err)
	}

	_, err = pool.Exec(ctx,
		`INSERT INTO tax_reports (user_id, tax_amount, status, tax_period, tax_category, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5, $6, $6)`,
		userId2, 7500000.00, "pending", 2023, "HB", "2023-06-20T00:00:00Z")
	if err != nil {
		t.Fatalf("Failed to create tax report for user 2: %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": "user1",
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString([]byte(env.JWT_SECRET))
	if err != nil {
		t.Fatalf("Failed to generate JWT token: %v", err)
	}

	tests := []struct {
		name           string
		queryParams    string
		setupAuth      func(*http.Request)
		expectedStatus int
		expectedCount  int
		checkFields    map[string]interface{}
	}{
		{
			name:        "Success - Get All Tax Payers",
			queryParams: "",
			setupAuth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+tokenString)
			},
			expectedStatus: http.StatusOK,
			expectedCount:  2,
		},
		{
			name:        "Success - Search By Name",
			queryParams: "?search=John",
			setupAuth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+tokenString)
			},
			expectedStatus: http.StatusOK,
			expectedCount:  1,
			checkFields: map[string]interface{}{
				"first_name": "John",
			},
		},
		{
			name:        "Success - Search By NPWP",
			queryParams: "?search=456.789.0",
			setupAuth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+tokenString)
			},
			expectedStatus: http.StatusOK,
			expectedCount:  1,
			checkFields: map[string]interface{}{
				"npwp": "23.456.789.0-345.678",
			},
		},
		{
			name:        "Success - Filter By Date Range",
			queryParams: "?start_date=2023-06-01&end_date=2023-06-30",
			setupAuth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+tokenString)
			},
			expectedStatus: http.StatusOK,
			expectedCount:  1,
		},
		{
			name:           "Failure - No Authorization",
			queryParams:    "",
			setupAuth:      func(req *http.Request) {},
			expectedStatus: http.StatusUnauthorized,
			expectedCount:  0,
		},
		{
			name:        "Failure - Invalid Date Format",
			queryParams: "?start_date=invalid-date",
			setupAuth: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+tokenString)
			},
			expectedStatus: http.StatusBadRequest,
			expectedCount:  0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/wajibpajak"+tc.queryParams, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			req.Header.Set("Content-Type", "application/json")
			if tc.setupAuth != nil {
				tc.setupAuth(req)
			}

			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			if status := rr.Code; status != tc.expectedStatus {
				t.Errorf("Handler returned wrong status code: got %v, want %v", status, tc.expectedStatus)
			}

			if tc.expectedStatus == http.StatusOK {
				var response []interface{}
				if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
					t.Fatalf("Failed to unmarshal response: %v", err)
				}

				if len(response) != tc.expectedCount {
					t.Errorf("Expected %d tax payers, got %d", tc.expectedCount, len(response))
				}

				if tc.checkFields != nil && len(response) > 0 {
					firstUser := response[0].(map[string]interface{})
					for field, expectedValue := range tc.checkFields {
						if value, ok := firstUser[field]; !ok || value != expectedValue {
							t.Errorf("Expected %s to be %v, got %v", field, expectedValue, value)
						}
					}
				}
			} else if tc.expectedStatus != http.StatusUnauthorized {
				var errorResponse map[string]interface{}
				if err := json.Unmarshal(rr.Body.Bytes(), &errorResponse); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}

				if _, ok := errorResponse["reason"]; !ok {
					t.Error("Expected error reason in response")
				}
			}
		})
	}
}
