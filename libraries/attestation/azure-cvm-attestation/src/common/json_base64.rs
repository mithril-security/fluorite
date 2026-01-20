use base64::prelude::*;

use serde::de::{self, Deserialize, DeserializeOwned, Deserializer};
use serde::ser::{self, Serialize, Serializer};
use serde_json;

pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: Serializer,
{
    let j = serde_json::to_string(value).map_err(ser::Error::custom)?;
    let j = BASE64_STANDARD.encode(j);
    j.serialize(serializer)
}

pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: DeserializeOwned,
    D: Deserializer<'de>,
{
    let j = String::deserialize(deserializer)?;
    // let b64_string:String = serde_json::from_str(&j).map_err(de::Error::custom)?;
    let t_json = BASE64_STANDARD.decode(j).map_err(de::Error::custom)?;
    serde_json::from_slice(&t_json).map_err(de::Error::custom)
}
