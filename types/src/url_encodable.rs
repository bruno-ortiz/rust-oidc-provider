use indexmap::IndexMap;

pub trait UrlEncodable {
    fn params(self) -> IndexMap<String, String>;
}

impl UrlEncodable for IndexMap<String, String> {
    fn params(self) -> IndexMap<String, String> {
        self
    }
}

impl<T1, T2> UrlEncodable for (T1, T2)
where
    T1: UrlEncodable,
    T2: UrlEncodable,
{
    fn params(self) -> IndexMap<String, String> {
        let mut first = self.0.params();
        let second = self.1.params();
        first.extend(second);
        first
    }
}

impl<T1, T2, T3> UrlEncodable for (T1, T2, T3)
where
    T1: UrlEncodable,
    T2: UrlEncodable,
    T3: UrlEncodable,
{
    fn params(self) -> IndexMap<String, String> {
        let mut first = self.0.params();
        let second = self.1.params();
        let third = self.2.params();
        first.extend(second);
        first.extend(third);
        first
    }
}
