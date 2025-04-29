package pkg

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
	"github.com/supercopy-coretax/hypertax-backend/models"
)

type contextKey string

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		authorizationHeader := r.Header.Get("Authorization")
		if !strings.Contains(authorizationHeader, "Bearer") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(models.NewErrorResponse("Unauthorized"))
			return
		}

		tokenString := strings.Replace(authorizationHeader, "Bearer ", "", -1)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("signing method invalid")
			} else if method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("signing method invalid")
			}

			return []byte(viper.GetString("JWT_SECRET")), nil
		}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))

		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(models.NewErrorResponse("Unauthorized"))
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(models.NewErrorResponse("Unauthorized"))
			return
		}

		ctx := context.WithValue(r.Context(), contextKey("username"), claims["username"])
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func BasicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/auth/login") || strings.Contains(r.URL.Path, "/auth/register") {
			username, password, ok := r.BasicAuth()
			fmt.Printf("username: %s, password: %s, ok: %v\n", username, password, ok)
			if !ok || username != viper.GetString("BASIC_AUTH_USERNAME") || password != viper.GetString("BASIC_AUTH_PASSWORD") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(models.NewErrorResponse("Unauthorized"))
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
