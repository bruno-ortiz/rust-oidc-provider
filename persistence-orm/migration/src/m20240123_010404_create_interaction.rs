use sea_orm::Iterable;
use sea_orm_migration::prelude::*;

use crate::models::{Interaction, InteractionType};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Interaction::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Interaction::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Interaction::Session).uuid().not_null())
                    .col(
                        ColumnDef::new(Interaction::Created)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Interaction::Request).text().not_null())
                    .col(
                        ColumnDef::new(Interaction::Type)
                            .enumeration(InteractionType::Table, InteractionType::iter().skip(1))
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Interaction::Table).to_owned())
            .await?;
        Ok(())
    }
}
