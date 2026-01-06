-- ==================================================
-- Файл: create_procedures.sql
-- Описание: Создание stored procedures для проекта
-- ==================================================
USE guarder_base;  -- Замените на имя вашей БД

-- Удаляем процедуру если существует
DROP PROCEDURE IF EXISTS save_device_measures;

-- Меняем разделитель для корректного создания процедуры
DELIMITER $$

-- Создаем процедуру
CREATE PROCEDURE save_device_measures (
    IN p_data JSON
)
proc_body: BEGIN
    DECLARE v_dev_id INT;
    DECLARE v_cnt INT DEFAULT 0;
    DECLARE v_keys_len INT;
    DECLARE i INT DEFAULT 0;
    DECLARE v_key VARCHAR(50);
    DECLARE v_value DECIMAL(10,4);

    -- Извлекаем dev_id из JSON
    SET v_dev_id = CAST(JSON_UNQUOTE(JSON_EXTRACT(p_data, '$.dev_id')) AS UNSIGNED);

    -- Проверяем существование устройства
    SELECT COUNT(*) INTO v_cnt FROM devices WHERE dev_id = v_dev_id;

    IF v_cnt = 0 THEN
		-- Устройство не найдено
        SELECT 2 AS status, 'Device not found' AS message;
        LEAVE proc_body;
    END IF;

    -- Получаем длину массива keys
    SET v_keys_len = JSON_LENGTH(p_data, '$.keys');

    IF v_keys_len IS NULL OR v_keys_len = 0 THEN
        -- Пустой или невалидный массив
        SELECT 1 AS status, 'Invalid or empty keys array' AS message;
        LEAVE proc_body;
    END IF;

    -- Цикл записи данных
    WHILE i < v_keys_len DO
        -- Извлекаем название ключа (первый ключ объекта)
        SET v_key = JSON_UNQUOTE(
            JSON_EXTRACT(
                JSON_KEYS(JSON_EXTRACT(p_data, CONCAT('$.keys[', i, ']'))),
                '$[0]'
            )
        );
        
        -- Извлекаем значение по ключу
        SET v_value = JSON_EXTRACT(p_data, CONCAT('$.keys[', i, '].', v_key));
        
        -- Вставляем запись
        INSERT INTO measures (dev_id, measure_key, measure_value, created_at)
        VALUES (v_dev_id, v_key, v_value, NOW());

        SET i = i + 1;
    END WHILE;
    
    -- Успешное выполнение
    SELECT 0 AS status, 'Data saved successfully' AS message, v_keys_len AS records_inserted;
END$$

-- Возвращаем стандартный разделитель
DELIMITER ;

-- Проверка создания
SELECT 
    ROUTINE_NAME, 
    ROUTINE_TYPE, 
    CREATED 
FROM 
    information_schema.ROUTINES 
WHERE 
    ROUTINE_SCHEMA = DATABASE() 
    AND ROUTINE_NAME = 'save_device_measures';
