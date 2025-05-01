
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE, 
    password VARCHAR(255) NOT NULL,       
    email VARCHAR(100) NOT NULL UNIQUE,   
    npwp VARCHAR(20) UNIQUE,              
    phone_number VARCHAR(20) UNIQUE,      
    address TEXT,                         
    first_name VARCHAR(100),              
    last_name VARCHAR(100),               
    date_of_birth DATE,                   
    profile_picture_url VARCHAR(255),     
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_name ON users(first_name, last_name);
