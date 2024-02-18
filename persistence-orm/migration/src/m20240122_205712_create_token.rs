use crate::models::Token;
use crate::models::{Grant, Status, TokenType};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Token::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Token::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Token::GrantId).uuid().not_null())
                    .col(
                        ColumnDef::new(Token::Status)
                            .enumeration(Status::Table, [Status::Awaiting, Status::Consumed])
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Token::Type)
                            .enumeration(TokenType::Table, [TokenType::Access, TokenType::Refresh])
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Token::ExpiresIn)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Token::Created)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Token::Scopes).string().not_null())
                    .col(ColumnDef::new(Token::TType).string())
                    .col(ColumnDef::new(Token::CertificateThumbprint).string())
                    .col(ColumnDef::new(Token::State).string())
                    .col(ColumnDef::new(Token::Nonce).string())
                    .to_owned(),
            )
            .await?;

        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name("fk-token-grant_id")
                    .from_tbl(Token::Table)
                    .from_col(Token::GrantId)
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
                    .name("fk-token-grant_id")
                    .table(Token::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(Token::Table).to_owned())
            .await?;
        Ok(())
    }
}
