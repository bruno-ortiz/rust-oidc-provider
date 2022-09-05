pub trait Identifiable<ID> {
    //TODO: return Cow<ID> to avoid cloning the id
    fn id(&self) -> ID;
}
