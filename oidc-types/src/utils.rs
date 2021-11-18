#[macro_export]
macro_rules! serialize_to_str {
    ($t:ty) => {
        impl serde::Serialize for $t {
            fn serialize<S>(
                &self,
                serializer: S,
            ) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }
    };
}
