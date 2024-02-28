use crate::exclude_sqlite;
use sea_orm_migration::prelude::*;

use crate::models::{ClientInformation, Grant, Status};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Grant::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Grant::Id).uuid().not_null().primary_key())
                    .col(
                        ColumnDef::new(Grant::Status)
                            .enumeration(Status::Table, [Status::Awaiting, Status::Consumed])
                            .not_null(),
                    )
                    .col(ColumnDef::new(Grant::ClientId).uuid().not_null())
                    .col(ColumnDef::new(Grant::Subject).string().not_null())
                    .col(
                        ColumnDef::new(Grant::AuthTime)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Grant::MaxAge).big_integer())
                    .col(ColumnDef::new(Grant::RedirectUri).string())
                    .col(ColumnDef::new(Grant::Scopes).string())
                    .col(ColumnDef::new(Grant::Acr).string().not_null())
                    .col(ColumnDef::new(Grant::Amr).string())
                    .col(ColumnDef::new(Grant::Claims).json())
                    .col(ColumnDef::new(Grant::RejectedClaims).json().not_null())
                    .to_owned(),
            )
            .await?;

        exclude_sqlite! {
            manager;
            create_foreign_key;
            ForeignKey::create()
                .name("fk-grant-client_id")
                .from_tbl(Grant::Table)
                .from_col(Grant::ClientId)
                .to_tbl(ClientInformation::Table)
                .to_col(ClientInformation::Id)
                .to_owned()
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        exclude_sqlite! {
            manager;
            drop_foreign_key;
            ForeignKey::drop()
                    .name("fk-grant-client_id")
                    .table(Grant::Table)
                    .to_owned()
        }

        manager
            .drop_table(Table::drop().table(Grant::Table).to_owned())
            .await?;
        Ok(())
    }
}
