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

use itertools::Itertools;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkcs7::Pkcs7;
use openssl::pkey::{PKey, PKeyRef, Private, Public};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::X509;
use std::cmp::Ordering;
use std::fmt::Display;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

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

pub fn save_p12_file(path: &Path, password: &str, certs: &Vec<Certificate>, private_key: Option<PrivateKey>) -> Result<(), String> {
    if certs.is_empty() {
        return Err("Invalid chain".to_owned());
    }

    let mut pkcs12_builder = Pkcs12::builder();
    pkcs12_builder.cert(&certs[0].cert);

    if certs.len() > 1 {
        let mut ca_stack = Stack::<X509>::new().map_err(|_| "Invalid chain".to_owned())?;
        certs[1..].iter().for_each(|cert| {
            let _ = ca_stack.push(cert.clone().cert);
        });
        pkcs12_builder.ca(ca_stack);
    }

    if let Some(private_key) = private_key {
        let key = &PKey::from_rsa(private_key.key).map_err(|_| "Invalid key".to_owned())?;
        pkcs12_builder.pkey(key);
    }

    let result = pkcs12_builder.build2(password).map_err(|e| e.to_string())?;
    let result = result.to_der().map_err(|e| e.to_string())?;

    fs::write(path, result).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn read_p12_file(path: &Path, password: &str) -> Result<(Chain, PrivateKey), String> {
    let file = fs::read(path).map_err(|err| err.to_string())?;
    let pkcs12 = Pkcs12::from_der(&file).map_err(|_| "Cannot read file".to_owned())?;
    let pkcs12 = pkcs12.parse2(password).map_err(|_| "Wrong password".to_owned())?;

    let mut certs = vec![];
    if let Some(cert) = pkcs12.cert {
        let cert = Certificate::from_x509(&cert)?;
        certs.push(cert);
    }

    if let Some(ca_certs) = pkcs12.ca {
        ca_certs.iter().for_each(|cert| {
            if let Ok(pem) = cert.to_pem() {
                if let Ok(cert) = X509::from_pem(pem.as_slice()) {
                    let cert = Certificate::from_x509(&cert).unwrap();
                    certs.push(cert);
                }
            }
        });
    }

    let pkey = if let Some(key) = pkcs12.pkey {
        match key.rsa() {
            Ok(key) => Ok(PrivateKey {
                key: key.clone(),
                modulus: hex_encode(key.n().to_vec()).into(),
            }),
            Err(err) => Err(err.to_string()),
        }
    } else {
        Err("Cannot read file: Error in private key".to_owned())
    };

    if certs.is_empty() || pkey.is_err() {
        Err("Cannot read file".to_owned())
    } else {
        Ok((Chain::from(certs), pkey?))
    }
}

#[derive(Clone, PartialEq)]
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

#[derive(Clone)]
pub struct PrivateKey {
    key: Rsa<Private>,
    modulus: StringValue,
}

impl PrivateKey {
    pub fn read(path: &Path) -> Result<Self, String> {
        let file = fs::read(path).map_err(|err| err.to_string())?;
        let key = PKey::private_key_from_pem(&file).map_err(|err| err.to_string())?;

        match key.rsa() {
            Ok(key) => Ok(PrivateKey {
                key: key.clone(),
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
            Ok(text) => String::from_utf8(text).ok(),
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

        let certs = if file.starts_with("-----BEGIN CERTIFICATE-----".as_bytes()) {
            let certs = X509::stack_from_pem(&file).map_err(|err| err.to_string())?;
            certs.iter().map(Certificate::from_x509).collect::<Vec<_>>()
        } else if file.starts_with("-----BEGIN PKCS7-----".as_bytes()) {
            let pkcs7 = Pkcs7::from_pem(&file).map_err(|err| err.to_string())?;
            if let Some(signed) = pkcs7.signed() {
                signed
                    .certificates()
                    .iter()
                    .flat_map(|stack_ref| {
                        stack_ref.iter().map(|x509_ref| {
                            let pem = x509_ref.to_pem().unwrap_or_else(|_| "".as_bytes().to_vec());
                            match X509::from_pem(pem.as_slice()) {
                                Ok(cert) => Certificate::from_x509(&cert),
                                Err(_) => Err(String::from("Invalid PEM")),
                            }
                        })
                    })
                    .collect::<Vec<_>>()
            } else {
                vec![]
            }
        } else {
            return Err("Not a parsable file".to_string());
        };

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

    pub fn create_fixed(certs: &[Certificate]) -> Result<Chain, String> {
        let mut certs = certs.to_vec();
        certs.sort_by(|cert1, cert2| {
            if cert1.subject_key_id() == cert2.authority_key_id() {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        });
        let chain = Chain::from(certs.iter().unique().cloned().collect::<Vec<_>>());
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

        for (idx, cert) in self.certs.iter().rev().enumerate() {
            if cert.authority_key_id().to_string() == "*Empty*" && idx > 0 {
                return false;
            }
            if !cert.within_timerange(&SystemTime::now()) {
                time_issue = true;
            }
            if let Some(x) = &x {
                if !cert.verify(x) {
                    return false;
                }
            }
            x = cert.public_key().ok();
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
