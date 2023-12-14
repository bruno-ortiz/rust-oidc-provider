# Rust OpenId Connect Provider

## !!!THIS IS A WORK IN PROGRESS!!!

This is a library that allows the creation and deployment of a openId authorisation server entirely in rust.
It is built on top o Axum and Tonic.

## Usage

You can refer to the **example** crate to see how to run and configure the Authorisation Server.

But mainly its just this:

```rust
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/interaction/login", get(login_page))
        .route("/interaction/consent", get(consent_page))
        .route("/login", post(login))
        .route("/consent", post(consent))
        .nest_service("/assets", ServeDir::new("./example/static/assets"));

    let config = OpenIDProviderConfigurationBuilder::default()
        .issuer("https://my.domain.com")
        .profile_resolver(MockProfileResolver)
        .claims_supported(ClaimsSupported::all())
        .build()
        .expect("Expected valid configuration");
    
    
    //This is only an example, don't commit the plain credentials in production
    create_client(
        &config,
        "Test client 1",
        "1d8fca3b-a2f1-48c2-924d-843e5173a951",
        "1fCW^$)*(I#tll2EH#!MfsHFQ$*6&gEx",
        AuthMethod::ClientSecretBasic,
    )
    .await;

    OidcServer::with_configuration(config)
        .with_router(app)
        .run()
        .await
        .unwrap()
}
```

This will start 2 servers. The first one at port **3000** is open for http calls and its mainly used to resolve the openId protocol, the other, at port 4000, it's a grpc server used as an Admin.

This approach allows the server administrator to only open the OpenID API port to the Internet, and keep the admin APIs closed to a private network.

## STATUS

CUrrently the server passes in **21 of 34** test of the openId certification process. The development was halted due to personal matter, it will be resumed soon.