use crate::sea_orm::EnumIter;
use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
pub(crate) enum AuthorizationCode {
    Table,
    Id,
    Code,
    GrantId,
    Status,
    CodeChallenge,
    CodeChallengeMethod,
    ExpiresIn,
    Scopes,
    State,
    Nonce,
}

#[derive(DeriveIden)]
pub(crate) enum Grant {
    Table,
    Id,
    Status,
    ClientId,
    Scopes,
    Subject,
    Acr,
    Amr,
    AuthTime,
    Claims,
    RejectedClaims,
    MaxAge,
    RedirectUri,
}

#[derive(DeriveIden)]
pub(crate) enum Token {
    Table,
    #[sea_orm(iden = "token")]
    Id,
    GrantId,
    Status,
    TType,
    #[sea_orm(iden = "token_type")]
    Type,
    ExpiresIn,
    Created,
    Scopes,
    State,
    Nonce,
}
#[derive(DeriveIden)]
pub(crate) enum AuthenticatedUser {
    Table,
    Session,
    Subject,
    AuthTime,
    GrantId,
    InteractionId,
    Acr,
    Amr,
}

#[derive(DeriveIden)]
pub(crate) enum ClientInformation {
    Table,
    Id,
    IssueDate,
    Secret,
    SecretExpiresAt,
    Metadata,
}

#[derive(DeriveIden)]
pub(crate) enum Interaction {
    Table,
    Id,
    Session,
    Request,
    Subject,
    Created,
    #[sea_orm(iden = "interaction_type")]
    Type,
}

#[derive(Iden, EnumIter)]
pub(crate) enum Status {
    Table,
    #[iden = "Awaiting"]
    Awaiting,
    #[iden = "Consumed"]
    Consumed,
}

#[derive(Iden, EnumIter)]
pub(crate) enum TokenType {
    Table,
    #[iden = "Access"]
    Access,
    #[iden = "Refresh"]
    Refresh,
}

#[derive(Iden, EnumIter)]
pub(crate) enum InteractionType {
    Table,
    #[iden = "Login"]
    Login,
    #[iden = "Consent"]
    Consent,
    #[iden = "None"]
    None,
}
