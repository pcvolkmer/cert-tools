/*
 * This file is part of cert-tools
 *
 * Copyright (C) 2025 the original author or authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
use std::cmp::Ordering;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Public};
use openssl::x509::X509;
use std::fmt::Display;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use itertools::Itertools;

pub fn hex_encode<T: AsRef<[u8]>>(s: T) -> String {
    s.as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
        .to_ascii_uppercase()
}

#[allow(clippy::expect_used, clippy::unwrap_used, clippy::cast_possible_wrap)]
fn asn1time(time: &SystemTime) -> Asn1Time {
    Asn1Time::from_unix(
        time.duration_since(UNIX_EPOCH)
            .expect("time not went backwards")
            .as_secs() as i64,
    )
    .unwrap()
}

#[derive(PartialEq)]
pub enum StringValue {
    Valid(String),
    Invalid,
    Empty,
}

impl Display for StringValue {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            StringValue::Valid(val) => write!(f, "{val}"),
            StringValue::Invalid => write!(f, "*Invalid*"),
            StringValue::Empty => write!(f, "*Empty*"),
        }
    }
}

impl From<String> for StringValue {
    fn from(value: String) -> Self {
        if value.trim().is_empty() {
            return StringValue::Empty;
        }
        StringValue::Valid(value)
    }
}

pub struct PrivateKey {
    modulus: StringValue,
}

impl PrivateKey {
    pub fn read(path: &Path) -> Result<Self, String> {
        let file = fs::read(path).map_err(|err| err.to_string())?;
        let key = PKey::private_key_from_pem(&file).map_err(|err| err.to_string())?;

        match key.rsa() {
            Ok(key) => Ok(PrivateKey {
                modulus: hex_encode(key.n().to_vec()).into(),
            }),
            Err(err) => Err(err.to_string()),
        }
    }
}

pub struct Fingerprint {
    pub sha1: StringValue,
    pub sha256: StringValue,
}

#[derive(Clone, Eq, PartialEq)]
pub struct Certificate {
    cert: X509,
}

impl Certificate {
    pub fn from_x509(x509: &X509) -> Result<Self, String> {
        let result = Self { cert: x509.clone() };
        Ok(result)
    }

    pub fn to_pem(&self) -> Result<String, String> {
        match self.cert.to_pem() {
            Ok(pem) => String::from_utf8(pem).map_err(|err| err.to_string()),
            Err(err) => Err(err.to_string()),
        }
    }

    pub fn name(&self) -> StringValue {
        match self
            .cert
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .last()
        {
            None => StringValue::Invalid,
            Some(cn) => match String::from_utf8(cn.data().as_slice().to_vec()) {
                Ok(value) => StringValue::Valid(value),
                _ => StringValue::Invalid,
            },
        }
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint {
            sha1: match self.cert.digest(MessageDigest::sha1()) {
                Ok(value) => StringValue::Valid(hex_encode(value)),
                _ => StringValue::Empty,
            },
            sha256: match self.cert.digest(MessageDigest::sha256()) {
                Ok(value) => StringValue::Valid(hex_encode(value)),
                _ => StringValue::Empty,
            },
        }
    }

    pub fn issuer(&self) -> StringValue {
        match self
            .cert
            .issuer_name()
            .entries_by_nid(Nid::COMMONNAME)
            .last()
        {
            None => StringValue::Invalid,
            Some(cn) => match String::from_utf8(cn.data().as_slice().to_vec()) {
                Ok(value) => StringValue::Valid(value),
                _ => StringValue::Invalid,
            },
        }
    }

    pub fn not_before(&self) -> StringValue {
        StringValue::Valid(self.cert.not_before().to_string())
    }

    pub fn is_valid_not_before(&self, time: &SystemTime) -> bool {
        self.cert.not_before().lt(&asn1time(time))
    }

    pub fn not_after(&self) -> StringValue {
        StringValue::Valid(self.cert.not_after().to_string())
    }

    pub fn is_valid_not_after(&self, time: &SystemTime) -> bool {
        self.cert.not_after().gt(&asn1time(time))
    }

    pub fn dns_names(&self) -> Vec<String> {
        match self.cert.subject_alt_names() {
            Some(names) => names
                .iter()
                .map(|name| name.dnsname().unwrap_or_default().to_string())
                .filter(|name| !name.trim().is_empty())
                .collect::<Vec<_>>(),
            _ => vec![],
        }
    }

    pub fn key_modulo(&self) -> StringValue {
        match self.cert.public_key() {
            Ok(key) => match key.rsa() {
                Ok(rsa) => StringValue::Valid(hex_encode(rsa.n().to_vec())),
                _ => StringValue::Invalid,
            },
            _ => StringValue::Empty,
        }
    }

    pub fn subject_key_id(&self) -> StringValue {
        match self.cert.subject_key_id() {
            Some(id) => StringValue::Valid(hex_encode(id.as_slice())),
            _ => StringValue::Empty,
        }
    }

    pub fn authority_key_id(&self) -> StringValue {
        match self.cert.authority_key_id() {
            Some(id) => StringValue::Valid(hex_encode(id.as_slice())),
            _ => StringValue::Empty,
        }
    }

    fn public_key(&self) -> Result<PKey<Public>, ()> {
        self.cert.public_key().map_err(drop)
    }

    #[allow(dead_code)]
    pub fn is_ca(&self) -> bool {
        if let Some(text) = self.to_text() {
            return text.contains("CA:TRUE");
        }
        false
    }

    fn verify(&self, key: &PKeyRef<Public>) -> bool {
        if let Ok(value) = self.cert.verify(key) {
            return value;
        }
        false
    }

    pub fn within_timerange(&self, time: &SystemTime) -> bool {
        self.is_valid_not_before(time) && self.is_valid_not_after(time)
    }

    #[allow(dead_code)]
    pub fn to_text(&self) -> Option<String> {
        match self.cert.to_text() {
            Ok(text) => match String::from_utf8(text) {
                Ok(value) => Some(value),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn public_key_matches(&self, private_key: &PrivateKey) -> bool {
        if self.key_modulo().to_string() == private_key.modulus.to_string() {
            return true;
        }
        false
    }
}

impl Hash for Certificate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.fingerprint().sha256.to_string().hash(state);
    }
}

pub struct Chain {
    certs: Vec<Certificate>,
}

impl Chain {
    pub fn read(path: &Path) -> Result<Self, String> {
        let file = fs::read(path).map_err(|err| err.to_string())?;
        let certs = X509::stack_from_pem(&file).map_err(|err| err.to_string())?;

        let certs = certs.iter().map(Certificate::from_x509).collect::<Vec<_>>();

        if certs.iter().filter(|item| item.is_err()).count() > 0 {
            return Err("Certificate chain contains invalid certificate".to_string());
        }

        if certs.is_empty() {
            return Err("No Certificates found".to_string());
        }

        Ok(Self {
            certs: certs.into_iter().flatten().collect::<Vec<_>>(),
        })
    }

    pub fn from(certs: Vec<Certificate>) -> Self {
        Self { certs }
    }

    pub fn fixed_from(certs: Vec<Certificate>) -> Result<Chain, String> {
        let mut certs = certs.iter().collect::<Vec<_>>();
        certs.sort_by(|cert1, cert2| {
            if cert1.subject_key_id() == cert2.authority_key_id() {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        });
        let chain = Chain::from(certs.iter().unique().map(|&c| c.clone()).collect::<Vec<_>>());
        if !chain.is_valid() {
            return Err("Cannot merge files to valid chain - giving up!".to_string());
        }
        Ok(chain)
    }

    pub fn certs(&self) -> &Vec<Certificate> {
        &self.certs
    }

    pub fn into_vec(self) -> Vec<Certificate> {
        self.certs
    }

    pub fn push(&mut self, cert: Certificate) {
        self.certs.push(cert);
    }

    pub fn is_valid(&self) -> bool {
        let mut x: Option<PKey<Public>> = None;
        let mut time_issue = false;
        for cert in self.certs.iter().rev() {
            if !cert.within_timerange(&SystemTime::now()) {
                time_issue = true;
            }
            if let Some(x) = &x {
                if !cert.verify(x) {
                    return false;
                }
            }
            x = match cert.public_key() {
                Ok(public_key) => Some(public_key),
                Err(()) => None,
            }
        }
        !time_issue && !self.certs.is_empty()
    }

    pub fn has_missing_tail(&self) -> bool {
        match self.certs.last() {
            Some(cert) => {
                matches!(cert.authority_key_id(), StringValue::Valid(_))
            }
            _ => false,
        }
    }
}
