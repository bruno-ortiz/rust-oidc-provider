use sea_orm_migration::prelude::*;

use crate::models::{AuthorizationCode, Grant, Status};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AuthorizationCode::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AuthorizationCode::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(AuthorizationCode::Code).string().not_null())
                    .col(ColumnDef::new(AuthorizationCode::GrantId).uuid().not_null())
                    .col(
                        ColumnDef::new(AuthorizationCode::Status)
                            .enumeration(Status::Table, [Status::Awaiting, Status::Consumed])
                            .not_null(),
                    )
                    .col(ColumnDef::new(AuthorizationCode::CodeChallenge).string())
                    .col(ColumnDef::new(AuthorizationCode::CodeChallengeMethod).string())
                    .col(
                        ColumnDef::new(AuthorizationCode::ExpiresIn)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AuthorizationCode::Scopes)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(AuthorizationCode::State).string())
                    .col(ColumnDef::new(AuthorizationCode::Nonce).string())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx-authorization_code_code")
                    .table(AuthorizationCode::Table)
                    .col(AuthorizationCode::Code)
                    .to_owned(),
            )
            .await?;

        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name("fk-authorization_code-grant_id")
                    .from_tbl(AuthorizationCode::Table)
                    .from_col(AuthorizationCode::GrantId)
                    .to_tbl(Grant::Table)
                    .to_col(Grant::Id)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_foreign_key(
                ForeignKey::drop()
                    .name("fk-authorization_code-grant_id")
                    .table(AuthorizationCode::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx-authorization_code_code")
                    .table(AuthorizationCode::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(AuthorizationCode::Table).to_owned())
            .await?;
        Ok(())
    }
}
