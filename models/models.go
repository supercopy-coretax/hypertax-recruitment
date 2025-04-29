package models

import "time"

type WajibPajak struct {
	ID        int       `json:"id"`
	NPWP      string    `json:"npwp"`
	Nama      string    `json:"nama"`
	Alamat    string    `json:"alamat"`
	CreatedAt time.Time `json:"created_at"`
}

type LaporPajak struct {
	ID           int       `json:"id"`
	WajibPajakID int       `json:"wajib_pajak_id"`
	JenisPajak   string    `json:"jenis_pajak"`
	Periode      string    `json:"periode"`
	TotalPajak   float64   `json:"total_pajak"`
	TanggalLapor time.Time `json:"tanggal_lapor"`
}

type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type RegisterUserRequest struct {
	Username             string    `json:"username"`
	Password             string    `json:"password"`
	PasswordConfirmation string    `json:"password_confirmation"`
	Email                string    `json:"email"`
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
