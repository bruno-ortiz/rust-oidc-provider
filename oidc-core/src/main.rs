use rocket::{get, routes};

#[get("/?<name>")]
fn index(name: String) -> String {
    format!("Hello, {}!", name)
}

#[rocket::main]
async fn main() {
    rocket::build()
        .mount("/hello", routes![index])
        .launch()
        .await;
}