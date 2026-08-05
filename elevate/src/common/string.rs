use core::fmt;
use std::{
    ffi::{CStr, OsString},
    ops,
};

use crate::common::Error;

const NULL_BYTE: char = '\0';
const NULL_BYTE_UTF8_LEN: usize = NULL_BYTE.len_utf8();

/// A UTF-8 encoded string with no interior null bytes
///
/// This type can be converted into a C (null-terminated) string at no cost
#[derive(Clone, PartialEq, Eq)]
pub struct ElevateString {
    inner: String,
}

impl ElevateString {
    pub fn new(mut string: String) -> Result<Self, Error> {
        if string.as_bytes().contains(&0) {
            return Err(Error::StringValidation(string));
        }

        string.push(NULL_BYTE);

        Ok(Self { inner: string })
    }

    pub fn from_cli_string(cli_string: impl Into<String>) -> Self {
        Self::new(cli_string.into())
            .expect("strings that come in from CLI should not have interior null bytes")
    }

    pub fn as_cstr(&self) -> &CStr {
        CStr::from_bytes_with_nul(self.inner.as_bytes()).unwrap()
    }

    pub fn as_str(&self) -> &str {
        self
    }
}

impl Default for ElevateString {
    fn default() -> Self {
        Self {
            inner: NULL_BYTE.into(),
        }
    }
}

#[cfg(test)]
impl From<&'_ str> for ElevateString {
    fn from(value: &'_ str) -> Self {
        ElevateString::try_from(value.to_string()).unwrap()
    }
}

impl TryFrom<String> for ElevateString {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ElevateString> for String {
    fn from(value: ElevateString) -> Self {
        let mut s = value.inner;
        s.pop();
        s
    }
}

impl From<ElevateString> for OsString {
    fn from(value: ElevateString) -> Self {
        let mut s = value.inner;
        s.pop();
        OsString::from(s)
    }
}

impl AsRef<str> for ElevateString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl ops::Deref for ElevateString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        let num_bytes = self.inner.len();
        &self.inner[..num_bytes - NULL_BYTE_UTF8_LEN]
    }
}

impl fmt::Debug for ElevateString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: &str = self;
        fmt::Debug::fmt(s, f)
    }
}

impl fmt::Display for ElevateString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self)
    }
}

impl PartialEq<str> for ElevateString {
    fn eq(&self, other: &str) -> bool {
        let s: &str = self;
        s == other
    }
}

impl PartialEq<&'_ str> for ElevateString {
    fn eq(&self, other: &&str) -> bool {
        let s: &str = self;
        s == *other
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;

    #[test]
    fn null_byte_is_utf8_encoded_as_a_single_byte() {
        assert_eq!(1, NULL_BYTE_UTF8_LEN)
    }

    #[test]
    fn sanity_check() {
        let expected = "hello";
        let s = ElevateString::new("hello".to_string()).unwrap();
        assert_eq!(expected, &*s);
    }

    #[test]
    fn cstr_conversion() {
        let expected = "hello";
        let cstr = CString::from_vec_with_nul((expected.to_string() + "\0").into_bytes()).unwrap();
        let s = ElevateString::new(expected.to_string()).unwrap();
        assert_eq!(&*cstr, s.as_cstr());
    }

    #[test]
    fn rejects_string_that_contains_interior_null() {
        assert!(ElevateString::new("he\0llo".to_string()).is_err());
    }
}
