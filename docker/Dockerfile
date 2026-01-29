FROM ubuntu:22.04 AS build

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    unixodbc-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN cmake -B build && cmake --build build


FROM ubuntu:22.04

# Установка необходимых пакетов включая MySQL ODBC драйвер
RUN apt-get update && apt-get install -y \
    libssl3 \
    libstdc++6 \
    unixodbc \
    libodbc2 \
    ca-certificates \
    odbc-mariadb \
    && rm -rf /var/lib/apt/lists/*

# Настройка ODBC для MySQL/MariaDB
RUN echo "[MySQL ODBC 8.0 Driver]" > /etc/odbcinst.ini && \
    echo "Description = MariaDB ODBC Connector" >> /etc/odbcinst.ini && \
    echo "Driver = /usr/lib/x86_64-linux-gnu/odbc/libmaodbc.so" >> /etc/odbcinst.ini && \
    echo "Setup = /usr/lib/x86_64-linux-gnu/odbc/libmaodbc.so" >> /etc/odbcinst.ini && \
    echo "FileUsage = 1" >> /etc/odbcinst.ini

WORKDIR /app
# Создаем директорию для SSL сертификатов (они будут примонтированы через volume)
RUN mkdir -p /app/ssl_certs
COPY config/ssl_certs app/ssl_certs

COPY --from=build /build/build/bin/GuarderServerCLI .

CMD ["./GuarderServerCLI"]