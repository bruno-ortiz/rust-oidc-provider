pub struct CustomServer {
    // configuration: Option<Box<dyn FnOnce(&mut ServiceConfig)>>,
}

impl CustomServer {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn run(self) -> std::io::Result<()> {
        todo!()
    }
}
