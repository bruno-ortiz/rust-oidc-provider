use actix_web::body::MessageBody;
use actix_web::dev::{Service, ServiceFactory, ServiceRequest, ServiceResponse, Transform};
use actix_web::web::ServiceConfig;
use actix_web::{App, Error, HttpServer};

pub struct CustomServer<A> {
    inner_app: A,
    configuration: Option<Box<dyn FnOnce(&mut ServiceConfig)>>,
}

impl CustomServer<()> {
    pub fn new() -> CustomServer<
        App<
            impl ServiceFactory<
                ServiceRequest,
                Response = ServiceResponse<impl MessageBody>,
                Error = Error,
                InitError = (),
                Config = (),
            >,
        >,
    > {
        CustomServer {
            inner_app: App::new(),
            configuration: None,
        }
    }
}

impl<T, B> CustomServer<App<T>>
where
    T: ServiceFactory<
        ServiceRequest,
        Response = ServiceResponse<B>,
        Error = Error,
        InitError = (),
        Config = (),
    >,
    B: MessageBody,
{
    pub fn with_configuration<F>(mut self, configuration: F) -> Self
    where
        F: FnOnce(&mut ServiceConfig) + 'static,
    {
        self.configuration = Some(Box::new(configuration));
        self
    }

    pub fn wrap<M, B2>(
        self,
        mw: M,
    ) -> CustomServer<
        App<
            impl ServiceFactory<
                ServiceRequest,
                Response = ServiceResponse<impl MessageBody>,
                Error = Error,
                InitError = (),
                Config = (),
            >,
        >,
    >
    where
        M: Transform<
                T::Service,
                ServiceRequest,
                Response = ServiceResponse<B2>,
                Error = Error,
                InitError = (),
            > + 'static,
        B2: MessageBody,
    {
        //register middleware
        CustomServer {
            inner_app: self.inner_app.wrap(mw),
            configuration: self.configuration,
        }
    }

    pub async fn run(self) -> std::io::Result<()> {
        HttpServer::new(move || self.inner_app).bind("")?.run();

        Ok(())
    }
}
