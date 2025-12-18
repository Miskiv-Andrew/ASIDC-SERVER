/*
 ============================================================================
 Radiation Monitoring Server - База данных (Production версия)
 Версия: 1.1 (с учетом всех изменений)
 ============================================================================
*/

-- 1. СОЗДАНИЕ БАЗЫ ДАННЫХ
DROP DATABASE IF EXISTS guarder_base;
CREATE DATABASE guarder_base 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE guarder_base;

-- 2. ТАБЛИЦА ПРИБОРОВ (DOSIMETERS)
CREATE TABLE devices (
    id INT PRIMARY KEY AUTO_INCREMENT COMMENT 'Внутренний ID прибора',
    ser_num VARCHAR(50) UNIQUE NOT NULL COMMENT 'Серийный номер прибора (уникальный)',
    device_type TINYINT NOT NULL DEFAULT 1 COMMENT 'Тип прибора (резерв)',
    battery_capacity INT COMMENT 'Емкость аккумулятора (мАч)',
    calibration_date DATE COMMENT 'Дата последней калибровки',
    last_maintenance DATE COMMENT 'Дата последнего ТО',
    status ENUM('active', 'maintenance', 'retired') DEFAULT 'active' COMMENT 'Статус прибора',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'Дата регистрации в системе'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Дозиметры и приборы радиационного контроля';

-- 3. ТАБЛИЦА ПОЛЬЗОВАТЕЛЕЙ (С АУТЕНТИФИКАЦИЕЙ)
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT COMMENT 'ID пользователя',
    login VARCHAR(50) UNIQUE NOT NULL COMMENT 'Логин для входа',
    name VARCHAR(100) NOT NULL COMMENT 'ФИО пользователя',
    role ENUM('admin', 'operator', 'executor') NOT NULL COMMENT 'Роль в системе',
    phone VARCHAR(20) COMMENT 'Телефон для уведомлений',
    email VARCHAR(100) COMMENT 'Email для уведомлений',
    password_hash VARCHAR(255) NOT NULL COMMENT 'Хеш пароля (PBKDF2)',
    salt VARCHAR(50) NOT NULL COMMENT 'Соль для хеширования',
    is_active INT DEFAULT 1 COMMENT 'Флаг активности (1-активен, 0-неактивен)',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'Дата регистрации'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Пользователи системы с аутентификацией';

-- 4. ТАБЛИЦА ТОКЕНОВ (СЕССИИ АУТЕНТИФИКАЦИИ)
CREATE TABLE tokens (
    token VARCHAR(64) PRIMARY KEY COMMENT 'Уникальный токен доступа (32 байта в hex)',
    user_id INT NOT NULL COMMENT 'ID пользователя, владельца токена',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'Время создания токена',
    expires_at DATETIME NOT NULL COMMENT 'Время истечения срока действия токена',
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'Время последнего использования токена',
    initial_ip VARCHAR(45) COMMENT 'IP-адрес при создании токена (аудит)',
    last_ip VARCHAR(45) COMMENT 'Последний использованный IP-адрес (мониторинг)',
    user_agent TEXT COMMENT 'Заголовок User-Agent клиента (браузер/приложение)',
    is_suspicious BOOLEAN DEFAULT FALSE COMMENT 'Флаг подозрительной активности',
    is_mobile BOOLEAN DEFAULT FALSE COMMENT 'Флаг мобильной сессии',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_tokens_user (user_id),
    INDEX idx_tokens_expires (expires_at),
    INDEX idx_tokens_activity (last_activity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Таблица токенов (сессий аутентификации)';

-- 5. ТАБЛИЦА РАБОЧИХ СЕССИЙ (ПРИБОР + ИСПОЛНИТЕЛЬ)
CREATE TABLE sessions (
    id INT PRIMARY KEY AUTO_INCREMENT COMMENT 'ID сессии',
    device_id INT NOT NULL COMMENT 'ID прибора (ссылка на devices.id)',
    user_id INT NOT NULL COMMENT 'ID исполнителя',
    start_time DATETIME NOT NULL COMMENT 'Время начала сессии',
    end_time DATETIME NULL COMMENT 'Время окончания сессии',
    location_start_lat FLOAT COMMENT 'Широта начала работы',
    location_start_lon FLOAT COMMENT 'Долгота начала работы',
    location_end_lat FLOAT COMMENT 'Широта окончания работы',
    location_end_lon FLOAT COMMENT 'Долгота окончания работы',
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE RESTRICT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT,
    INDEX idx_sessions_device (device_id),
    INDEX idx_sessions_user (user_id),
    INDEX idx_sessions_time (start_time, end_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Рабочие сессии (прибор + исполнитель + время)';

-- 6. ТАБЛИЦА ИЗМЕРЕНИЙ
CREATE TABLE measurements (
    id BIGINT PRIMARY KEY AUTO_INCREMENT COMMENT 'ID измерения',
    session_id INT NOT NULL COMMENT 'Сессия',
    timestamp DATETIME NOT NULL COMMENT 'Время измерения',
    lat FLOAT NOT NULL COMMENT 'Широта',
    lon FLOAT NOT NULL COMMENT 'Долгота',
    battery_percent TINYINT UNSIGNED COMMENT 'Заряд батареи (%)',
    rad_type ENUM('alpha', 'beta', 'gamma') NOT NULL COMMENT 'Тип излучения',
    DER FLOAT NOT NULL COMMENT 'Мощность эквивалентной дозы (ПЭД)',
    dose FLOAT COMMENT 'Накопленная доза',
    acc_time INT COMMENT 'Время накопления (сек)',
    state BOOLEAN COMMENT 'Состояние прибора (тестовый байт)',
    alarm_triggered BOOLEAN DEFAULT FALSE COMMENT 'Флаг превышения порога',
    units ENUM('μSv/h', 'mSv/h', 'R/h') NOT NULL COMMENT 'Единицы измерения',
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
    INDEX idx_measurements_session (session_id),
    INDEX idx_measurements_time (timestamp),
    INDEX idx_measurements_alarm (alarm_triggered)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Измерения радиационного фона';

-- 7. ТАБЛИЦА ТРЕВОГ
CREATE TABLE alarms (
    id INT PRIMARY KEY AUTO_INCREMENT COMMENT 'ID тревоги',
    measurement_id BIGINT NOT NULL COMMENT 'Измерение с превышением',
    threshold_value FLOAT NOT NULL COMMENT 'Превышенный порог',
    notification_method ENUM('none', 'email', 'sms') DEFAULT 'none' COMMENT 'Способ уведомления',
    acknowledged_by INT NULL COMMENT 'Кто подтвердил тревогу',
    acknowledged_at DATETIME NULL COMMENT 'Когда подтверждена',
    notified BOOLEAN DEFAULT FALSE COMMENT 'Уведомление отправлено',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'Время создания записи',
    FOREIGN KEY (measurement_id) REFERENCES measurements(id) ON DELETE CASCADE,
    FOREIGN KEY (acknowledged_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_alarms_measurement (measurement_id),
    INDEX idx_alarms_acknowledged (acknowledged_by),
    INDEX idx_alarms_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='События превышения радиационного фона';

-- 8. СПРАВОЧНИК ДОПУСТИМЫХ УРОВНЕЙ
CREATE TABLE thresholds (
    country_code CHAR(2) NOT NULL COMMENT 'Код страны (RU, KZ, BY, ...)',
    radiation_type ENUM('alpha', 'beta', 'gamma') NOT NULL COMMENT 'Тип излучения',
    max_DER FLOAT NOT NULL COMMENT 'Макс. мощность дозы',
    max_dose FLOAT COMMENT 'Макс. накопленная доза',
    effective_date DATE NOT NULL COMMENT 'Дата вступления в силу',
    description TEXT COMMENT 'Описание нормы',
    PRIMARY KEY (country_code, radiation_type),
    INDEX idx_thresholds_country (country_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Нормы радиационной безопасности по странам';

-- 9. СОЗДАНИЕ АДМИНИСТРАТОРА (пароль: admin123)
INSERT INTO users (login, name, role, phone, email, password_hash, salt, is_active) 
VALUES (
    'admin',                            -- login
    'Администратор Системы',            -- name
    'admin',                            -- role
    '+79990000000',                     -- phone
    'admin@guarder.local',              -- email
    'pbkdf2_sha256:10000:13UUxX5VZKL2/Due4lO0Xg==:b26jVfsubAf1aYlgKY2b2fgC13gjkSs1lPYYeqasmig=',
    '13UUxX5VZKL2/Due4lO0Xg==',
    1                                   -- is_active
);

-- 10. ПРОВЕРОЧНЫЕ ЗАПРОСЫ
SELECT 'Database created successfully' AS Status;

SELECT 
    'Users' AS TableName, 
    COUNT(*) AS RecordCount 
FROM users
UNION ALL
SELECT 'Devices', COUNT(*) FROM devices
UNION ALL
SELECT 'Tokens', COUNT(*) FROM tokens
UNION ALL
SELECT 'Thresholds', COUNT(*) FROM thresholds;

-- 11. ИНФОРМАЦИЯ ДЛЯ ВХОДА
SELECT '=== LOGIN CREDENTIALS ===' AS Info;
SELECT 'Admin: login=admin, password=admin123' AS Credentials;
SELECT 'Change password after first login!' AS Warning;