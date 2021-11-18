use lazy_static::lazy_static;
use regex::Regex;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};

lazy_static! {
    static ref PARAMETERIZED_SCOPE_PATTERN: Regex =
        Regex::new("^\\w+:\\w+$").expect("Could no create Parameterized Scopes");
}

#[derive(Eq, PartialEq, Debug)]
pub enum Scope {
    SimpleScope(String),
    ParameterizedScope(String, String),
}

impl Scope {
    pub fn value(&self) -> String {
        match self {
            Scope::SimpleScope(scope) => scope.to_lowercase(),
            Scope::ParameterizedScope(scope, param) => {
                format!("{}:{}", scope.to_lowercase(), param)
            }
        }
    }
}

impl Display for Scope {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value())
    }
}

#[derive(Debug, PartialEq)]
pub struct Scopes(Vec<Scope>);

impl Scopes {
    pub fn new<I: Into<Scopes>>(values: I) -> Self {
        values.into()
    }

    pub fn from_vec(values: Vec<Scope>) -> Self {
        Scopes(values)
    }

    pub fn get(&self, idx: usize) -> Option<&Scope> {
        self.0.get(idx)
    }
}

impl Display for Scopes {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let scope_vec = self
            .0
            .iter()
            .map(|scope| format!("{}", scope))
            .collect::<Vec<String>>();
        write!(f, "{}", scope_vec.join(" "))
    }
}

impl From<Vec<&str>> for Scopes {
    fn from(values: Vec<&str>) -> Self {
        let mut vec: Vec<Scope> = Vec::with_capacity(values.capacity());
        for v in values {
            vec.push(v.into());
        }
        Scopes(vec)
    }
}

impl From<&str> for Scope {
    fn from(scope: &str) -> Self {
        match PARAMETERIZED_SCOPE_PATTERN.is_match(scope) {
            true => {
                let parts: Vec<&str> = scope.split(':').collect();
                Scope::ParameterizedScope(parts[0].to_owned(), parts[1].to_owned())
            }
            false => Scope::SimpleScope(scope.to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::scopes;
    use crate::scopes::{Scope, Scopes};

    #[test]
    fn test_can_create_scopes() {
        let scopes: Scopes = scopes!("xpto", "rng:42");

        let first = scopes.get(0);
        let second = scopes.get(1);
        assert!(first.is_some());
        assert!(second.is_some());

        match first.unwrap() {
            Scope::SimpleScope(scope) => {
                assert_eq!("xpto", scope)
            }
            Scope::ParameterizedScope(_, _) => {
                panic!("should be a simple scope")
            }
        };

        match second.unwrap() {
            Scope::SimpleScope(_) => {
                panic!("should be a parameterized scope")
            }
            Scope::ParameterizedScope(scope, param) => {
                assert_eq!("rng", scope);
                assert_eq!("42", param);
            }
        };
    }
}
