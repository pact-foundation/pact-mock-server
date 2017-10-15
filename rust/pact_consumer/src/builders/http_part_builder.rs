use pact_matching::models::*;
#[cfg(test)]
use regex::Regex;
use std::collections::HashMap;

use prelude::*;
use util::obj_key_for_path;

/// Various methods shared between `RequestBuilder` and `ResponseBuilder`.
pub trait HttpPartBuilder {
    /// (Implementation detail.) This function fetches the mutable state that's
    /// needed to update this builder's `headers`. You should not need to use
    /// this under normal circumstances.
    ///
    /// This function has two return values because its job is to split a single
    /// `&mut` into two `&mut` pointing to sub-objects, which has to be done
    /// carefully in Rust.
    #[doc(hidden)]
    fn headers_and_matching_rules_mut(&mut self) -> (&mut HashMap<String, String>, &mut Matchers);

    /// (Implementation detail.) This function fetches the mutable state that's
    /// needed to update this builder's `body`. You should not need to use this
    /// under normal circumstances.
    ///
    /// This function has two return values because its job is to split a single
    /// `&mut` into two `&mut` pointing to sub-objects, which has to be done
    /// carefully in Rust.
    #[doc(hidden)]
    fn body_and_matching_rules_mut(&mut self) -> (&mut OptionalBody, &mut Matchers);

    /// Specify a header pattern.
    ///
    /// ```
    /// #[macro_use]
    /// extern crate pact_consumer;
    /// extern crate regex;
    ///
    /// use pact_consumer::prelude::*;
    /// use pact_consumer::builders::RequestBuilder;
    /// use regex::Regex;
    ///
    /// # fn main() {
    /// let digits_re = Regex::new("^[0-9]+$").unwrap();
    /// RequestBuilder::default()
    ///     .header("X-Simple", "value")
    ///     .header("X-Digits", Term::new(digits_re, "123"));
    /// # }
    /// ```
    fn header<N, V>(&mut self, name: N, value: V) -> &mut Self
    where
        N: Into<String>,
        V: Into<StringPattern>,
    {
        let name = name.into();
        let value = value.into();
        {
            let (headers, rules) = self.headers_and_matching_rules_mut();
            headers.insert(name.clone(), value.to_example());
            value.extract_matching_rules(&format!("$.headers{}", obj_key_for_path(&name)), rules)
        }
        self
    }

    /// Set the `Content-Type` header.
    fn content_type<CT>(&mut self, content_type: CT) -> &mut Self
    where
        CT: Into<StringPattern>,
    {
        self.header("Content-Type", content_type)
    }

    /// Set the `Content-Type` header to `text/html`.
    fn html(&mut self) -> &mut Self {
        self.content_type("text/html")
    }

    /// Set the `Content-Type` header to `application/json`.
    fn json(&mut self) -> &mut Self {
        self.content_type("application/json")
    }

    /// Specify a body literal. This does not allow using patterns.
    ///
    /// ```
    /// #[macro_use]
    /// extern crate pact_consumer;
    ///
    /// use pact_consumer::prelude::*;
    /// use pact_consumer::builders::RequestBuilder;
    ///
    /// # fn main() {
    /// RequestBuilder::default().body("Hello");
    /// # }
    /// ```
    ///
    /// TODO: We may want to change this to `B: Into<Vec<u8>>` depending on what
    /// happens with https://github.com/pact-foundation/pact-reference/issues/19
    fn body<B: Into<String>>(&mut self, body: B) -> &mut Self {
        let body = body.into();
        {
            let (body_ref, _) = self.body_and_matching_rules_mut();
            *body_ref = OptionalBody::Present(body);
        }
        self
    }

    /// Specify the body as `JsonPattern`, possibly including special matching
    /// rules.
    ///
    /// ```
    /// #[macro_use]
    /// extern crate pact_consumer;
    ///
    /// use pact_consumer::prelude::*;
    /// use pact_consumer::builders::RequestBuilder;
    ///
    /// # fn main() {
    /// RequestBuilder::default().json_body(json_pattern!({
    ///     "message": SomethingLike::new(json_pattern!("Hello")),
    /// }));
    /// # }
    /// ```
    fn json_body<B: Into<JsonPattern>>(&mut self, body: B) -> &mut Self {
        let body = body.into();
        {
            let (body_ref, rules) = self.body_and_matching_rules_mut();
            *body_ref = OptionalBody::Present(body.to_example().to_string());
            body.extract_matching_rules("$.body", rules);
        }
        self
    }
}

#[test]
fn header_pattern() {
    let application_regex = Regex::new("application/.*").unwrap();
    let pattern = PactBuilder::new("C", "P")
        .interaction("I", |i| {
            i.request.header(
                "Content-Type",
                Term::new(application_regex, "application/json"),
            );
        })
        .build();
    let good = PactBuilder::new("C", "P")
        .interaction("I", |i| {
            i.request.header("Content-Type", "application/xml");
        })
        .build();
    let bad = PactBuilder::new("C", "P")
        .interaction("I", |i| { i.request.header("Content-Type", "text/html"); })
        .build();
    assert_requests_match!(good, pattern);
    assert_requests_do_not_match!(bad, pattern);
}

#[test]
fn body_literal() {
    let pattern = PactBuilder::new("C", "P")
        .interaction("I", |i| { i.request.body("Hello"); })
        .build();
    let good = PactBuilder::new("C", "P")
        .interaction("I", |i| { i.request.body("Hello"); })
        .build();
    let bad = PactBuilder::new("C", "P")
        .interaction("I", |i| { i.request.body("Bye"); })
        .build();
    assert_requests_match!(good, pattern);
    assert_requests_do_not_match!(bad, pattern);
}

#[test]
fn json_body_pattern() {
    let pattern = PactBuilder::new("C", "P")
        .interaction("I", |i| {
            i.request.json_body(json_pattern!({
                "message": SomethingLike::new(json_pattern!("Hello")),
            }));
        })
        .build();
    let good = PactBuilder::new("C", "P")
        .interaction("I", |i| {
            i.request.json_body(json_pattern!({ "message": "Goodbye" }));
        })
        .build();
    let bad = PactBuilder::new("C", "P")
        .interaction("I", |i| {
            i.request.json_body(json_pattern!({ "message": false }));
        })
        .build();
    assert_requests_match!(good, pattern);
    assert_requests_do_not_match!(bad, pattern);
}
