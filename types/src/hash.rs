pub trait Hashable {
    fn identifier(&self) -> &[u8];
}
