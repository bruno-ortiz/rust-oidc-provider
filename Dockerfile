FROM rust:1.77 AS build

WORKDIR /app
COPY . .

RUN apt-get update && apt-get install -y protobuf-compiler

RUN cargo build --release


FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y libssl-dev libssl3 && apt-get clean

COPY --from=build /app/target/release/oidc-example /app/
COPY --from=build /app/example/static /app/static

ENV STATIC_ASSETS=/app/static

EXPOSE 3000 4000

# Command to run the application
CMD ["/app/oidc-example"]