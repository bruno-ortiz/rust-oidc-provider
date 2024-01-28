use entities::sea_orm_active_enums;
use oidc_core::adapter::PersistenceError;
use sea_orm::DbErr;

use crate::{entities, enum_conversion_impl};

enum_conversion_impl! {
    sea_orm_active_enums::CodeChallengeMethod,
    oidc_types::pkce::CodeChallengeMethod,
    Plain,
    S256
}

enum_conversion_impl! {
    sea_orm_active_enums::Status,
    oidc_core::models::Status,
    Awaiting,
    Consumed
}

pub(crate) fn db_err(err: DbErr) -> PersistenceError {
    PersistenceError::DB(err.into())
}

mod macros {
    #[macro_export]
    macro_rules! enum_conversion_impl {
        ($from_enum:path, $to_enum:path $(, $variant:ident)*) => {
            impl From<$from_enum> for $to_enum {
                fn from(value: $from_enum) -> Self {
                    match value {
                         $(<$from_enum>::$variant => <$to_enum>::$variant,)*
                    }
                }
            }

            impl From<$to_enum> for $from_enum {
                fn from(value: $to_enum) -> Self {
                    match value {
                        $(<$to_enum>::$variant => <$from_enum>::$variant,)*
                    }
                }
            }
        };
    }
    #[macro_export]
    macro_rules! insert_model {
        ($self:ident, $model:expr) => {{
            if let Some(ref txn) = $self.active_txn {
                $model
                    .insert(std::ops::Deref::deref(txn.get::<$crate::TxnWrapper>()))
                    .await
                    .map_err(|err| PersistenceError::DB(err.into()))?
            } else {
                $model
                    .insert(&$self.db.0)
                    .await
                    .map_err(|err| PersistenceError::DB(err.into()))?
            }
        }};
    }

    #[macro_export]
    macro_rules! update_model {
        ($self:ident, $model:expr) => {{
            if let Some(ref txn) = $self.active_txn {
                $model
                    .update(std::ops::Deref::deref(txn.get::<$crate::TxnWrapper>()))
                    .await
                    .map_err(|err| PersistenceError::DB(err.into()))?
            } else {
                $model
                    .update(&$self.db.0)
                    .await
                    .map_err(|err| PersistenceError::DB(err.into()))?
            }
        }};
    }
}
