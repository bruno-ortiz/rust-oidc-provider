FROM rust:1.76 AS build

WORKDIR /app
COPY . .

RUN apt-get update && apt-get install -y protobuf-compiler

RUN cargo build --release


FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y libssl-dev libssl3 && apt-get clean

COPY --from=build /app/target/release/oidc-example /app/

EXPOSE 3000 4000

# Command to run the application
CMD ["/app/oidc-example"]