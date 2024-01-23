pub use sea_orm::{ConnectOptions, Database, DatabaseConnection};

use oidc_migration::{Migrator, MigratorTrait};

mod entities;

pub async fn run_migrations(db_conn: &DatabaseConnection) -> anyhow::Result<()> {
    Migrator::refresh(db_conn).await?;
    Ok(())
}

#[cfg(feature = "sqlite")]
pub fn get_default_db_connection() -> DatabaseConnection {
    futures::executor::block_on(async {
        Database::connect("sqlite::memory:")
            .await
            .expect("Error creating sqlite default connection")
    })
}

#[cfg(not(feature = "sqlite"))]
pub fn get_default_db_connection() -> DatabaseConnection {
    DatabaseConnection::default()
}
