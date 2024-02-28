#[macro_export]
macro_rules! exclude_sqlite {
    ($manager:expr; $action:ident;$build_fk:expr) => {
        match $manager.get_database_backend() {
            $crate::sea_orm::DbBackend::Sqlite => {} // Passthrough
            _ => {
                let fk = $build_fk;
                $manager.$action(fk).await?;
            }
        }
    };
}
