use sea_orm_migration::prelude::*;

use crate::models::ClientInformation;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ClientInformation::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ClientInformation::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ClientInformation::IssueDate)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ClientInformation::Secret)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ClientInformation::SecretExpiresAt)
                            .timestamp_with_time_zone(),
                    )
                    .col(
                        ColumnDef::new(ClientInformation::Metadata)
                            .json()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ClientInformation::Table).to_owned())
            .await?;
        Ok(())
    }
}
