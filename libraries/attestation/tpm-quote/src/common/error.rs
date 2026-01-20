pub type Result<T> = std::result::Result<T, WrapperErrorKind>;

/// List of error types that might occur in the wrapper.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum WrapperErrorKind {
    /// Returned when a size or length-defined parameter does not conform with the size
    /// restrictions for it.
    WrongParamSize,
    /// Returned when a required parameter was not passed, usually to a builder.
    ParamsMissing,
    /// Returned when two or more parameters have inconsistent values or variants.
    InconsistentParams,
    /// Returned when the value of a parameter is not yet supported.
    UnsupportedParam,
    /// Returned when the value of a parameter is invalid for that type.
    InvalidParam,
    /// An unexpected internal error occurred.
    InternalError,
}
