use regex::Regex;
use lazy_static::lazy_static;
use std::fmt::{Display, Formatter, Debug};
use std::fmt;

lazy_static! {
    static ref PARAMETERIZED_SCOPE_PATTERN: Regex = Regex::new("^\\w+:\\w+$")
        .expect("Could no create Parameterized Scopes");
}

pub trait Scope: Debug + Display {
    fn value(&self) -> String;
}

impl PartialEq for dyn Scope {
    fn eq(&self, other: &Self) -> bool {
        self.value() == other.value()
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct SimpleScope(String);

impl SimpleScope {
    pub fn new<T: Into<String>>(value: T) -> Self {
        Self(value.into())
    }
}

impl Scope for SimpleScope {
    fn value(&self) -> String {
        self.0.to_lowercase()
    }
}

impl From<&str> for SimpleScope {
    fn from(value: &str) -> Self {
        SimpleScope(value.to_owned())
    }
}

impl Display for SimpleScope {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value())
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct ParameterizedScope(String, String);

impl ParameterizedScope {
    pub fn new<T: Into<String>>(value: T, param: T) -> Self {
        Self(value.into(), param.into())
    }
}

impl Scope for ParameterizedScope {
    fn value(&self) -> String {
        format!("{}:{}", self.0.to_lowercase(), self.1.to_owned())
    }
}

impl From<&str> for ParameterizedScope {
    fn from(value: &str) -> Self {
        let parts: Vec<&str> = value.split(':').collect();
        ParameterizedScope(parts[0].to_owned(), parts[1].to_owned())
    }
}

impl Display for ParameterizedScope {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value())
    }
}

#[derive(Debug, PartialEq)]
pub struct
Scopes(Vec<Box<dyn Scope>>);

impl Scopes {
    pub fn new<I: Into<Scopes>>(values: I) -> Self {
        values.into()
    }

    pub fn new_boxed(values: Vec<Box<dyn Scope>>) -> Self {
        let mut vec: Vec<Box<dyn Scope>> = Vec::with_capacity(values.capacity());
        for v in values {
            vec.push(v);
        }
        Scopes(vec)
    }

    fn get(&self, idx: usize) -> Option<&Box<dyn Scope>> {
        self.0.get(idx)
    }
}

impl Display for Scopes {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let scope_vec = self.0.iter()
            .map(|scope| format!("{}", scope))
            .collect::<Vec<String>>();
        write!(f, "{}", scope_vec.join(" "))
    }
}

impl From<Vec<&str>> for Scopes {
    fn from(values: Vec<&str>) -> Self {
        let mut vec: Vec<Box<dyn Scope>> = Vec::with_capacity(values.capacity());
        for v in values {
            vec.push(v.into());
        }
        Scopes(vec)
    }
}

impl From<&str> for Box<dyn Scope> {
    fn from(scope: &str) -> Self {
        match PARAMETERIZED_SCOPE_PATTERN.is_match(scope) {
            true => { Box::new(ParameterizedScope::from(scope)) }
            false => { Box::new(SimpleScope::from(scope)) }
        }
    }
}
