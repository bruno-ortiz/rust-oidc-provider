use crate::exclude_sqlite;
use sea_orm_migration::prelude::*;

use crate::models::{AuthorisationCode, CodeChallengeMethod, Grant, Status};
use crate::sea_orm::Iterable;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AuthorisationCode::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AuthorisationCode::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(AuthorisationCode::Code).string().not_null())
                    .col(ColumnDef::new(AuthorisationCode::GrantId).uuid().not_null())
                    .col(
                        ColumnDef::new(AuthorisationCode::Status)
                            .enumeration(Status::Table, [Status::Awaiting, Status::Consumed])
                            .not_null(),
                    )
                    .col(ColumnDef::new(AuthorisationCode::CodeChallenge).string())
                    .col(
                        ColumnDef::new(AuthorisationCode::CodeChallengeMethod).enumeration(
                            CodeChallengeMethod::Table,
                            CodeChallengeMethod::iter().skip(1),
                        ),
                    )
                    .col(
                        ColumnDef::new(AuthorisationCode::ExpiresIn)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AuthorisationCode::Scopes)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(AuthorisationCode::State).string())
                    .col(ColumnDef::new(AuthorisationCode::Nonce).string())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx-authorization_code_code")
                    .table(AuthorisationCode::Table)
                    .col(AuthorisationCode::Code)
                    .to_owned(),
            )
            .await?;

        exclude_sqlite! {
            manager;
            create_foreign_key;
            ForeignKey::create()
                .name("fk-authorization_code-grant_id")
                .from_tbl(AuthorisationCode::Table)
                .from_col(AuthorisationCode::GrantId)
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
                .name("fk-authorization_code-grant_id")
                .table(AuthorisationCode::Table)
                .to_owned()
        }
        manager
            .drop_index(
                Index::drop()
                    .name("idx-authorization_code_code")
                    .table(AuthorisationCode::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(AuthorisationCode::Table).to_owned())
            .await?;
        Ok(())
    }
}
