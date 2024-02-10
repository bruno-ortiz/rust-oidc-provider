//! `SeaORM` Entity. Generated by sea-orm-codegen 0.12.11

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "authenticated_user")]
pub struct Model {
    #[sea_orm(
        primary_key,
        auto_increment = false,
        column_type = "Binary(BlobSize::Blob(Some(16)))"
    )]
    pub session: Vec<u8>,
    pub subject: String,
    pub auth_time: TimeDateTimeWithTimeZone,
    #[sea_orm(column_type = "Binary(BlobSize::Blob(Some(16)))", nullable)]
    pub grant_id: Option<Vec<u8>>,
    #[sea_orm(column_type = "Binary(BlobSize::Blob(Some(16)))")]
    pub interaction_id: Vec<u8>,
    pub acr: String,
    pub amr: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::grant::Entity",
        from = "Column::GrantId",
        to = "super::grant::Column::Id",
        on_update = "NoAction",
        on_delete = "NoAction"
    )]
    Grant,
}

impl Related<super::grant::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Grant.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}