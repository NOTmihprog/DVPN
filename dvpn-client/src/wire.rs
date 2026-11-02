//! msgpack messages: encoding, fields, and taking answers apart into [`crate::types`].

use rmpv::Value;
use serde::de::DeserializeOwned;

use crate::Error;

pub fn encode(v: &Value) -> Vec<u8> {
    let mut d = Vec::new();
    rmpv::encode::write_value(&mut d, v).expect("write to a Vec");
    d
}

pub fn decode(data: &[u8]) -> Option<Value> {
    rmpv::decode::read_value(&mut &data[..]).ok()
}

/// A map with string keys.
pub fn map(pairs: Vec<(&str, Value)>) -> Value {
    Value::Map(pairs.into_iter().map(|(k, v)| (Value::from(k), v)).collect())
}

/// Field `key` of a map; nil counts as missing.
pub fn field<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.as_map()?.iter().find(|(k, _)| k.as_str() == Some(key)).map(|(_, v)| v).filter(|v| !v.is_nil())
}

pub fn field_str<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    field(v, key).and_then(Value::as_str)
}

/// An answer as a type of [`crate::types`] (fields it does not know are ignored).
pub fn from_value<T: DeserializeOwned>(v: Value) -> Result<T, Error> {
    let shown = v.to_string();
    rmpv::ext::from_value(v).map_err(|e| Error::Protocol(format!("{e}: {}", short(&shown))))
}

fn short(s: &str) -> &str {
    match s.char_indices().nth(300) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}
