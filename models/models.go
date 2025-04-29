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
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"`
}
