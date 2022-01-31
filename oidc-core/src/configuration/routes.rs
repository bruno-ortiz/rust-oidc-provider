#[derive(Debug)]
pub struct Routes {
    pub authorisation: String,
}

impl Default for Routes {
    fn default() -> Self {
        Routes {
            authorisation: "/authorise".into(),
        }
    }
}
