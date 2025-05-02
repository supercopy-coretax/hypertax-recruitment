CREATE TYPE tax_category_enum AS ENUM (
    'OP',    -- Orang pribadi
    'HB',    -- Hidup berpisah
    'PH',    -- Pisah harta
    'MT',    -- Memilih terpisah
    'WBT'    -- Warisan belum terbagi
);

CREATE TYPE tax_status_enum AS ENUM (
    'pending',  -- Menunggu
    'approved', -- Disetujui
    'rejected'  -- Ditolak
);

CREATE TABLE tax_reports (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    tax_amount DECIMAL(10, 2) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    tax_period INT NOT NULL,
    tax_category tax_category_enum NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_tax_reports_user_id ON tax_reports(user_id);
