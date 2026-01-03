use validator::ValidationError;

pub fn validate_required(value: &String) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        let mut error = ValidationError::new("is_required");
        error.message = Some(std::borrow::Cow::from("This field is required"));
        Err(error)
    } else {
        Ok(())
    }
}