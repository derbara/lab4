

CREATE DATABASE IF NOT EXISTS lab4_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE lab4_db;

CREATE TABLE IF NOT EXISTS roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    login VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(256) NOT NULL,
    last_name VARCHAR(100),
    first_name VARCHAR(100) NOT NULL,
    middle_name VARCHAR(100),
    role_id INT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE SET NULL
);


INSERT INTO roles (name, description) VALUES
('Администратор', 'Полный доступ к системе'),
('Менеджер', 'Управление пользователями и данными'),
('Пользователь', 'Базовый доступ');


INSERT INTO users (login, password_hash, last_name, first_name, middle_name, role_id, created_at)
VALUES (
    'admin',
    SHA2('Admin123!', 256),
    'Иванов',
    'Иван',
    'Иванович',
    1,
    NOW()
);

INSERT INTO users (login, password_hash, last_name, first_name, middle_name, role_id, created_at)
VALUES
('manager1', SHA2('Manager1!', 256), 'Петров', 'Пётр', 'Петрович', 2, NOW()),
('user001', SHA2('Userpass1!', 256), NULL, 'Мария', 'Сергеевна', 3, NOW()),
('user002', SHA2('Userpass2!', 256), 'Сидоров', 'Алексей', NULL, NULL, NOW());
