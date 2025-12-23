# =========================
# Build stage
# =========================
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
	libjsoncpp-dev \
    libssl-dev \
    unixodbc-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Копируем только то, что нужно для сборки
COPY CMakeLists.txt .
COPY config ./config
COPY apps ./apps
COPY core ./core
COPY third_party ./third_party

# Если jsoncpp / nanodbc через FetchContent — они подтянутся сами

RUN mkdir build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release && \
    cmake --build . -j$(nproc)

# =========================
# Runtime stage
# =========================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    libssl3 \
    unixodbc \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Бинарник
COPY --from=builder /build/build/bin/GuarderServerCLI /app/GuarderServerCLI

# Конфиги и сертификаты
# COPY config /app/config
COPY config /app

EXPOSE 8443

CMD ["./GuarderServerCLI"]
