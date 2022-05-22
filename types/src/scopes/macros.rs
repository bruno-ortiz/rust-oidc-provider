#[macro_export]
macro_rules! scopes {
    ($($scope:expr),*) =>{
        {
            let mut temp_vec = Vec::new();
            $(
                temp_vec.push($scope);
            )*
            $crate::scopes::Scopes::new(temp_vec)
        }
    }
}
