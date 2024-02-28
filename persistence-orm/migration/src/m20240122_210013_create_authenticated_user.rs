use sea_orm_migration::prelude::*;

use crate::exclude_sqlite;
use crate::models::{AuthenticatedUser, Grant};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AuthenticatedUser::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AuthenticatedUser::Session)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(AuthenticatedUser::Subject)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AuthenticatedUser::AuthTime)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(AuthenticatedUser::GrantId).uuid())
                    .col(
                        ColumnDef::new(AuthenticatedUser::InteractionId)
                            .uuid()
                            .not_null(),
                    )
                    .col(ColumnDef::new(AuthenticatedUser::Acr).string().not_null())
                    .col(ColumnDef::new(AuthenticatedUser::Amr).string())
                    .to_owned(),
            )
            .await?;

        exclude_sqlite! {
            manager;
            create_foreign_key;
            ForeignKey::create()
                .name("fk-authenticated_user-grant_id")
                .from_tbl(AuthenticatedUser::Table)
                .from_col(AuthenticatedUser::GrantId)
                .to_tbl(Grant::Table)
                .to_col(Grant::Id)
                .to_owned()
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        exclude_sqlite! {
            manager;
            drop_foreign_key;
                ForeignKey::drop()
                    .name("fk-authenticated_user-grant_id")
                    .table(AuthenticatedUser::Table)
                    .to_owned()
        }
        manager
            .drop_table(Table::drop().table(AuthenticatedUser::Table).to_owned())
            .await?;
        Ok(())
    }
}
