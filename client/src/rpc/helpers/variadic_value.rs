use serde::{
    de::{DeserializeOwned, Error},
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_json::{from_value, Value};

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum VariadicValue<T> {
    /// None
    Null,
    /// Single
    Single(T),
    /// List
    Multiple(Vec<T>),
}

impl<T> Into<Option<Vec<T>>> for VariadicValue<T> {
    fn into(self) -> Option<Vec<T>> {
        match self {
            VariadicValue::Null => None,
            VariadicValue::Single(x) => Some(vec![x]),
            VariadicValue::Multiple(xs) => Some(xs),
        }
    }
}

impl<T> VariadicValue<T> {
    pub fn iter<'a>(&'a self) -> Box<dyn std::iter::Iterator<Item = &T> + 'a> {
        match self {
            VariadicValue::Null => Box::new(std::iter::empty()),
            VariadicValue::Single(x) => Box::new(std::iter::once(x)),
            VariadicValue::Multiple(xs) => Box::new(xs.iter()),
        }
    }
}

impl<T> Serialize for VariadicValue<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self {
            &VariadicValue::Null => serializer.serialize_none(),
            &VariadicValue::Single(x) => x.serialize(serializer),
            &VariadicValue::Multiple(xs) => xs.serialize(serializer),
        }
    }
}

impl<'a, T> Deserialize<'a> for VariadicValue<T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<VariadicValue<T>, D::Error>
    where
        D: Deserializer<'a>,
    {
        let v: Value = Deserialize::deserialize(deserializer)?;

        if v.is_null() {
            return Ok(VariadicValue::Null);
        }

        from_value(v.clone())
            .map(VariadicValue::Single)
            .or_else(|_| from_value(v).map(VariadicValue::Multiple))
            .map_err(|err| {
                D::Error::custom(format!(
                    "Invalid variadic value type: {}",
                    err
                ))
            })
    }
}

// helper implementing automatic Option<Vec<A>> -> Option<Vec<B>> conversion
pub fn maybe_vec_into<A, B>(src: &Option<Vec<A>>) -> Option<Vec<B>>
where
    A: Clone + Into<B>,
{
    src.clone().map(|x| x.into_iter().map(Into::into).collect())
}

#[cfg(test)]
mod tests {
    use super::VariadicValue;
    use serde_json;

    #[test]
    fn test_serialize_variadic_value() {
        let value: VariadicValue<u64> = VariadicValue::Null;
        let serialized_value = serde_json::to_string(&value).unwrap();
        assert_eq!(serialized_value, "null");

        let value = VariadicValue::Single(1);
        let serialized_value = serde_json::to_string(&value).unwrap();
        assert_eq!(serialized_value, "1");

        let value = VariadicValue::Multiple(vec![1, 2, 3, 4]);
        let serialized_value = serde_json::to_string(&value).unwrap();
        assert_eq!(serialized_value, "[1,2,3,4]");

        let value = VariadicValue::Multiple(vec![
            VariadicValue::Null,
            VariadicValue::Single(1),
            VariadicValue::Multiple(vec![2, 3]),
            VariadicValue::Single(4),
        ]);
        let serialized_value = serde_json::to_string(&value).unwrap();
        assert_eq!(serialized_value, "[null,1,[2,3],4]");
    }

    #[test]
    fn test_deserialize_variadic_value() {
        let serialized = "null";
        let deserialized_value: VariadicValue<u64> =
            serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized_value, VariadicValue::Null);

        let serialized = "1";
        let deserialized_value: VariadicValue<u64> =
            serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized_value, VariadicValue::Single(1));

        let serialized = "[1,2,3,4]";
        let deserialized_value: VariadicValue<u64> =
            serde_json::from_str(serialized).unwrap();
        assert_eq!(
            deserialized_value,
            VariadicValue::Multiple(vec![1, 2, 3, 4])
        );
    }
}
