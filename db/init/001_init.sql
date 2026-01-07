-- ============================================================================
-- Radiation Monitoring Server - База данных (Production версия)
-- Версия: 1.2 (с новыми таблицами devices и measures)
-- ============================================================================

-- 1. СОЗДАНИЕ БАЗЫ ДАННЫХ
CREATE DATABASE IF NOT EXISTS guarder_base 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE guarder_base;

-- 2. ТАБЛИЦА ПРИБОРОВ (упрощенная версия для быстрого старта)
CREATE TABLE IF NOT EXISTS devices (
    dev_id INT PRIMARY KEY COMMENT 'ID устройства',
    device_name VARCHAR(100) COMMENT 'Название устройства',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Дата создания'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Устройства (упрощенная таблица)';

-- 3. ТАБЛИЦА ИЗМЕРЕНИЙ (упрощенная версия)
CREATE TABLE IF NOT EXISTS measures (
    id INT AUTO_INCREMENT PRIMARY KEY COMMENT 'ID измерения',
    dev_id INT NOT NULL COMMENT 'ID устройства',
    measure_key VARCHAR(50) NOT NULL COMMENT 'Ключ измерения',
    measure_value DECIMAL(10,4) COMMENT 'Значение измерения',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Время измерения',
    FOREIGN KEY (dev_id) REFERENCES devices(dev_id) ON DELETE CASCADE,
    INDEX idx_dev_time (dev_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Измерения от устройств';

-- 4. ТАБЛИЦА ПОЛЬЗОВАТЕЛЕЙ (С АУТЕНТИФИКАЦИЕЙ)
CREATE TABLE IF NOT EXISTS users (
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

-- 5. ТАБЛИЦА ТОКЕНОВ (СЕССИИ АУТЕНТИФИКАЦИИ)
CREATE TABLE IF NOT EXISTS tokens (
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

-- 6. ТАБЛИЦА РАБОЧИХ СЕССИЙ (ПРИБОР + ИСПОЛНИТЕЛЬ)
CREATE TABLE IF NOT EXISTS sessions (
    id INT PRIMARY KEY AUTO_INCREMENT COMMENT 'ID сессии',
    device_id INT NOT NULL COMMENT 'ID прибора (ссылка на devices.dev_id)',
    user_id INT NOT NULL COMMENT 'ID исполнителя',
    start_time DATETIME NOT NULL COMMENT 'Время начала сессии',
    end_time DATETIME NULL COMMENT 'Время окончания сессии',
    location_start_lat FLOAT COMMENT 'Широта начала работы',
    location_start_lon FLOAT COMMENT 'Долгота начала работы',
    location_end_lat FLOAT COMMENT 'Широта окончания работы',
    location_end_lon FLOAT COMMENT 'Долгота окончания работы',
    FOREIGN KEY (device_id) REFERENCES devices(dev_id) ON DELETE RESTRICT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT,
    INDEX idx_sessions_device (device_id),
    INDEX idx_sessions_user (user_id),
    INDEX idx_sessions_time (start_time, end_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Рабочие сессии (прибор + исполнитель + время)';

-- 7. ТАБЛИЦА ИЗМЕРЕНИЙ (расширенная версия)
CREATE TABLE IF NOT EXISTS measurements (
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

-- 8. ТАБЛИЦА ТРЕВОГ
CREATE TABLE IF NOT EXISTS alarms (
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

-- 9. СПРАВОЧНИК ДОПУСТИМЫХ УРОВНЕЙ
CREATE TABLE IF NOT EXISTS thresholds (
    country_code CHAR(2) NOT NULL COMMENT 'Код страны (RU, KZ, BY, ...)',
    radiation_type ENUM('alpha', 'beta', 'gamma') NOT NULL COMMENT 'Тип излучения',
    max_DER FLOAT NOT NULL COMMENT 'Макс. мощность дозы',
    max_dose FLOAT COMMENT 'Макс. накопленная доза',
    effective_date DATE NOT NULL COMMENT 'Дата вступления в силу',
    description TEXT COMMENT 'Описание нормы',
    PRIMARY KEY (country_code, radiation_type),
    INDEX idx_thresholds_country (country_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Нормы радиационной безопасности по странам';

-- 10. СОЗДАНИЕ АДМИНИСТРАТОРА (только если не существует)
INSERT IGNORE INTO users (login, name, role, phone, email, password_hash, salt, is_active) 
VALUES (
    'admin',
    'Администратор Системы',
    'admin',
    '+79990000000',
    'admin@guarder.local',
    'pbkdf2_sha256:10000:dxhzP9AhBbFmZMknlT6zIg==:taV4HAvvqsD99xY4e9AZCHDEtF2dDJML4OPgwkbUZ38=',
    'dxhzP9AhBbFmZMknlT6zIg==',
    1
);

-- 11. ПРОВЕРОЧНЫЕ ЗАПРОСЫ
SELECT 'Database initialized successfully' AS Status;

SELECT 
    'Users' AS TableName, 
    COUNT(*) AS RecordCount 
FROM users
UNION ALL
SELECT 'Devices', COUNT(*) FROM devices
UNION ALL
SELECT 'Measures', COUNT(*) FROM measures
UNION ALL
SELECT 'Tokens', COUNT(*) FROM tokens
UNION ALL
SELECT 'Thresholds', COUNT(*) FROM thresholds;

-- 12. ИНФОРМАЦИЯ ДЛЯ ВХОДА
SELECT '=== LOGIN CREDENTIALS ===' AS Info;
SELECT 'Admin: login=admin, password=Admin@Secure12345!' AS Credentials;
SELECT 'Change password after first login!' AS Warning;