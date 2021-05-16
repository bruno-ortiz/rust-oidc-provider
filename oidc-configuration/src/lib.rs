mod configuration;
mod error;

#[cfg(test)]
mod tests {
    use crate::configuration::load_config;

    #[test]
    fn can_load_config() {
        let config = load_config().err().unwrap();
        println!("{}", config);
        assert_eq!(2 + 2, 4);
    }
}
