pub trait Identifiable<ID: Clone> {
    fn id(&self) -> &ID;
}
