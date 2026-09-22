FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd --system --no-create-home hush
USER hush
COPY --from=build /src/target/release/hush-directory /usr/local/bin/hush-directory
ENV PORT=8080
EXPOSE 8080
CMD ["hush-directory"]
