pub fn to_vec<T>(value: &T) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>>
where
    T: serde::ser::Serialize,
{
    let mut vec = Vec::new();
    ciborium::ser::into_writer(value, &mut vec)?;
    Ok(vec)
}

pub fn from_slice<T>(slice: &[u8]) -> Result<T, ciborium::de::Error<std::io::Error>>
where
    T: serde::de::DeserializeOwned,
{
    ciborium::de::from_reader(slice)
}
