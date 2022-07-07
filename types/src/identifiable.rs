pub trait Identifiable<ID> {
    fn id(&self) -> ID;
}
