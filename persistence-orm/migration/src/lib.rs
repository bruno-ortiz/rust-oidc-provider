pub use sea_orm_migration::prelude::*;

mod m20240122_205256_create_client_information;
mod m20240122_205432_create_grant;
mod m20240122_205439_create_authorization_code;
mod m20240122_205712_create_token;
mod m20240122_210013_create_authenticated_user;
mod m20240123_010404_create_interaction;
mod macros;
mod models;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20240122_205256_create_client_information::Migration),
            Box::new(m20240122_205432_create_grant::Migration),
            Box::new(m20240122_205439_create_authorization_code::Migration),
            Box::new(m20240122_205712_create_token::Migration),
            Box::new(m20240122_210013_create_authenticated_user::Migration),
            Box::new(m20240123_010404_create_interaction::Migration),
        ]
    }
}
