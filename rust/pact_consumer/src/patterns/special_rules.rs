//! Special matching rules, including `SomethingLike`, `Term`, etc.

use pact_matching::models::Matchers;
use regex::Regex;
use serde_json;
#[cfg(test)]
use std::collections::HashMap;
use std::iter::repeat;
use std::marker::PhantomData;

use super::Pattern;
use super::json_pattern::JsonPattern;
use super::string_pattern::StringPattern;

macro_rules! impl_from_for_pattern {
    ($from:ty, $pattern:ident) => {
        impl From<$from> for $pattern {
            fn from(pattern: $from) -> Self {
                $pattern::pattern(pattern)
            }
        }
    }
}

/// Match values based on their data types.
#[derive(Debug)]
pub struct SomethingLike<Nested: Pattern> {
    example: Nested,
}

impl<Nested: Pattern> SomethingLike<Nested> {
    /// Match all values which have the same type as `example`.
    pub fn new<E: Into<Nested>>(example: E) -> Self {
        SomethingLike { example: example.into() }
    }
}

impl<Nested: Pattern> Pattern for SomethingLike<Nested> {
    type Matches = Nested::Matches;

    fn to_example(&self) -> Self::Matches {
        self.example.to_example()
    }

    fn extract_matching_rules(&self, path: &str, rules_out: &mut Matchers) {
        rules_out.insert(path.to_owned(), hashmap!(s!("match") => s!("type")));
        self.example.extract_matching_rules(path, rules_out);
    }
}

impl_from_for_pattern!(SomethingLike<JsonPattern>, JsonPattern);
impl_from_for_pattern!(SomethingLike<StringPattern>, StringPattern);

#[test]
fn something_like_is_pattern() {
    let matchable = SomethingLike::<JsonPattern>::new(json_pattern!("hello"));
    assert_eq!(matchable.to_example(), json!("hello"));
    let mut rules = HashMap::new();
    matchable.extract_matching_rules("$", &mut rules);
    assert_eq!(json!(rules), json!({"$": {"match": "type"}}));
}

#[test]
fn something_like_into() {
    // Make sure we can convert `SomethingLike` into different pattern types.
    let _: JsonPattern = SomethingLike::new(json_pattern!("hello")).into();
    // We don't particularly care about having a nice syntax for
    // `StringPattern`, because it's rarely useful in practice.
    let _: StringPattern = SomethingLike::new("hello".to_owned()).into();
}

/// Generates the specified value, matches any value of the same data type. This
/// is intended for use inside `json_pattern!`, and it interprets its arguments
/// as a `json_pattern!`.
///
/// ```
/// # #[macro_use] extern crate pact_consumer;
/// # fn main() {
/// json_pattern!({
///   "id": something_like!(10),
///   "metadata": something_like!({}),
/// });
/// # }
/// ```
///
/// If you're building `StringPattern` values, you'll need to call
/// `SomethingLike::new` manually instead.
#[macro_export]
macro_rules! something_like {
    ($($json_pattern:tt)+) => {
        $crate::patterns::SomethingLike::new(json_pattern!($($json_pattern)+))
    }
}

/// Match an array with the specified "shape".
#[derive(Debug)]
pub struct ArrayLike {
    example_element: JsonPattern,
    min_length: usize,
}

impl ArrayLike {
    /// Match arrays containing elements like `example_element`.
    pub fn new(example_element: JsonPattern) -> ArrayLike {
        ArrayLike {
            example_element: example_element,
            min_length: 1,
        }
    }

    /// Use this after `new` to set a minimum length for the matching array.
    pub fn with_min_length(mut self, min_length: usize) -> ArrayLike {
        self.min_length = min_length;
        self
    }
}

impl_from_for_pattern!(ArrayLike, JsonPattern);

impl Pattern for ArrayLike {
    type Matches = serde_json::Value;

    fn to_example(&self) -> serde_json::Value {
        let element = self.example_element.to_example();
        serde_json::Value::Array(repeat(element).take(self.min_length).collect())
    }

    fn extract_matching_rules(&self, path: &str, rules_out: &mut Matchers) {
        rules_out.insert(
            path.to_owned(),
            hashmap!(
                s!("match") => s!("type"),
                s!("min") => format!("{}", self.min_length),
            ),
        );
        rules_out.insert(
            format!("{}[*].*", path),
            hashmap!(
                s!("match") => s!("type"),
            ),
        );
        let new_path = format!("{}[*]", path);
        self.example_element.extract_matching_rules(
            &new_path,
            rules_out,
        );
    }
}

#[test]
fn array_like_is_pattern() {
    let elem = SomethingLike::new(json_pattern!("hello"));
    let matchable = ArrayLike::new(json_pattern!(elem)).with_min_length(2);
    assert_eq!(matchable.to_example(), json!(["hello", "hello"]));

    let mut rules = HashMap::new();
    matchable.extract_matching_rules("$", &mut rules);
    let expected_rules = json!({
        // Ruby omits the `type` here, but the Rust `pact_matching` library
        // claims to want `"type"` when `"min"` is used.
        "$": {"match": "type", "min": "2"},
        // TODO: Ruby always generates this; I'm not sure what it's intended to
        // do. It looks like it makes child objects in the array match their
        // fields by type automatically?
        "$[*].*": {"match": "type"},
        // This is inserted by our nested `SomethingLike` rule.
        "$[*]": {"match": "type"},
    });
    assert_eq!(json!(rules), expected_rules);
}

/// Generates the specified value, matches any value of the same data type. This
/// is intended for use inside `json_pattern!`, and it interprets its arguments
/// as a `json_pattern!`.
///
/// ```
/// # #[macro_use] extern crate pact_consumer;
/// # fn main() {
/// json_pattern!({
///   // Expect an array of strings.
///   "tags": array_like!("tag"),
///
///   // Expect an array of objects, each of which has a name key containing
///   // a string (but match the actual names by type).
///   "people": array_like!({
///     "name": "J. Smith",
///   }),
/// });
/// # }
/// ```
#[macro_export]
macro_rules! array_like {
    ($($json_pattern:tt)+) => {
        $crate::patterns::ArrayLike::new(json_pattern!($($json_pattern)+))
    };

    ($($json_pattern:tt)+, $min_len:expr) => {
        $crate::patterns::ArrayLike::new(json_pattern!($($json_pattern)+))
    };
}

/// Match and generate strings that match a regular expression.
#[derive(Debug)]
pub struct Term<Nested: Pattern> {
    /// The example string we generate when asked.
    example: String,
    /// The regex we use to match.
    regex: Regex,
    /// Since we always store `example` as a string, we need to mention our
    /// `Nested` type somewhere. We can do that using the zero-length
    /// `PhantomData` type.
    phantom: PhantomData<Nested>,
}

impl<Nested: Pattern> Term<Nested> {
    /// Construct a new `Term`, given a regex and the example string to
    /// generate.
    pub fn new<S: Into<String>>(regex: Regex, example: S) -> Self {
        Term {
            example: example.into(),
            regex: regex,
            phantom: PhantomData,
        }
    }
}

impl<Nested> Pattern for Term<Nested>
where
    Nested: Pattern,
    Nested::Matches: From<String>,
{
    type Matches = Nested::Matches;

    fn to_example(&self) -> Self::Matches {
        From::from(self.example.clone())
    }

    fn extract_matching_rules(&self, path: &str, rules_out: &mut Matchers) {
        rules_out.insert(
            path.to_owned(),
            hashmap!(
                s!("match") => s!("regex"),
                s!("regex") => s!(self.regex.as_str()),
            ),
        );
    }
}

impl_from_for_pattern!(Term<JsonPattern>, JsonPattern);
impl_from_for_pattern!(Term<StringPattern>, StringPattern);

#[test]
fn term_is_pattern() {
    let matchable = Term::<JsonPattern>::new(Regex::new("[Hh]ello").unwrap(), "hello");
    assert_eq!(matchable.to_example(), json!("hello"));

    let mut rules = HashMap::new();
    matchable.extract_matching_rules("$", &mut rules);
    let expected_rules = json!({
        "$": { "match": "regex", "regex": "[Hh]ello" },
    });
    assert_eq!(json!(rules), expected_rules);
}

#[test]
fn term_into() {
    // Make sure we can convert `Term` into different pattern types.
    let _: JsonPattern = Term::new(Regex::new("[Hh]ello").unwrap(), "hello").into();
    let _: StringPattern = Term::new(Regex::new("[Hh]ello").unwrap(), "hello").into();
}

/// Internal helper function called by `term!` to build a regex. Panics if the
/// regex is invalid. (We use this partly because it's hard to refer to the
/// `regex` crate from inside a public macro unless our caller imports it.)
#[doc(hidden)]
pub fn build_regex<S: AsRef<str>>(regex_str: S) -> Regex {
    let regex_str = regex_str.as_ref();
    match Regex::new(regex_str) {
        Ok(regex) => regex,
        Err(msg) => panic!("could not parse regex {:?}: {}", regex_str, msg),
    }
}

/// A pattern which macthes the regular expression `$regex` (specified as a
/// string) literal, and which generates `$example`.
///
/// ```
/// # #[macro_use] extern crate pact_consumer;
/// # fn main() {
/// json_pattern!({
///   // Match a string consisting of numbers and lower case letters, and
///   // generate `"10a"`.$crate::patterns::
///   "id_string": term!("^[0-9a-z]$", "10a")
/// });
/// # }
/// ```
#[macro_export]
macro_rules! term {
    ($regex:expr, $example:expr) => {
        {
            $crate::patterns::Term::new($crate::patterns::build_regex($regex), $example)
        }
    }
}
