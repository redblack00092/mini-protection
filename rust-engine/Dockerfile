##############################################################################
# Stage 1 — Build
##############################################################################
FROM rust:1.87-bookworm AS builder

# rdkafka cmake-build에 필요한 도구
RUN apt-get update && apt-get install -y \
    cmake \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cargo.toml + Cargo.lock 먼저 복사하여 의존성 레이어를 캐시한다
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release || true
RUN rm -rf src

# 실제 소스 + 테스트 복사 후 빌드
COPY src ./src
COPY tests ./tests
RUN touch src/main.rs && cargo build --release

##############################################################################
# Stage 2 — Runtime
##############################################################################
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/mini-protection-engine /usr/local/bin/mini-protection-engine

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
    CMD wget -qO- http://localhost:8080/__mini-protection/health || exit 1

CMD ["mini-protection-engine"]
