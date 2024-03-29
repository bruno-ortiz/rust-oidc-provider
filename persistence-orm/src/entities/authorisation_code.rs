//! `SeaORM` Entity. Generated by sea-orm-codegen 0.12.11

use super::sea_orm_active_enums::CodeChallengeMethod;
use super::sea_orm_active_enums::Status;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "authorisation_code")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub code: String,
    #[sea_orm(column_type = "Binary(BlobSize::Blob(Some(16)))")]
    pub grant_id: Vec<u8>,
    pub status: Status,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
    pub expires_in: TimeDateTimeWithTimeZone,
    pub scopes: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
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
