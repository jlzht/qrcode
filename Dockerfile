FROM debian:bookworm AS builder
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
    g++ \
    python3 \
    python3-pip \
    ninja-build \
    cmake \
    pkg-config && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages meson conan

WORKDIR /app
COPY . .
RUN conan profile detect
RUN conan install . --output-folder=build --build=missing
RUN meson setup build --native-file build/conan_meson_native.ini
RUN meson compile -C build

FROM debian:bookworm-slim

WORKDIR /data

COPY --from=builder /app/build/qrcode /usr/local/bin/qrcode
COPY --from=builder /app/places.csv ./places.csv
COPY --from=builder /app/templates ./templates/
COPY --from=builder /app/static ./static/

ENTRYPOINT ["/usr/local/bin/qrcode"]

CMD ["-i", "places.csv", "-o", "routes.csv", "-p", "8080", "-t", "./templates", "-d", "http://localhost:8080/"]
