#![allow(non_snake_case, dead_code)]
use std::{hash::{Hash, Hasher}, collections::{HashSet, HashMap}};

use secp256k1::{Secp256k1, SecretKey, PublicKey, Scalar};
use bech32::ToBase32;

pub mod receiving;
pub mod sending;
pub mod structs;
pub mod utils;
pub mod error;

use crate::error::Error;

#[derive(Debug, Eq, PartialEq)]
struct Label {s: Scalar}

impl Label {
    pub fn into_inner(self) -> Scalar {
        self.s
    }
    
    pub fn as_inner(&self) -> &Scalar {
        &self.s
    }
}

impl Hash for Label {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let bytes = self.s.to_be_bytes();
        bytes.hash(state);
    }
}

impl From<Scalar> for Label {
    fn from(s: Scalar) -> Self {
        Label {s}
    }
}

impl TryFrom<String> for Label {
    type Error = Error;

    fn try_from(s: String) -> Result<Label, Error> {
        // Is it valid hex?
        let bytes = hex::decode(s)?;
        // Is it 32B long?
        let bytes: [u8;32] = bytes.try_into()
            .map_err(|_| Error::InvalidLabel("Label must be 32 bytes (256 bits) long".to_owned()))?;
        // Is it on the curve? If yes, push it on our labels list
        Ok(Label::from(Scalar::from_be_bytes(bytes)?))
    }
}

impl TryFrom<&str> for Label {
    type Error = Error;

    fn try_from(s: &str) -> Result<Label, Error> {
        // Is it valid hex?
        let bytes = hex::decode(s)?;
        // Is it 32B long?
        let bytes: [u8;32] = bytes.try_into()
            .map_err(|_| Error::InvalidLabel("Label must be 32 bytes (256 bits) long".to_owned()))?;
        // Is it on the curve? If yes, push it on our labels list
        Ok(Label::from(Scalar::from_be_bytes(bytes)?))
    }
}

impl From<Label> for Scalar {
    fn from(l: Label) -> Self {
        l.s
    }
}

#[derive(Debug)]
pub struct SilentPayment {
    version: u8,
    scan_privkey: SecretKey,
    spend_privkey: SecretKey,
    labels: HashSet<Label>,
}

impl SilentPayment {
    pub fn new(version: u32, scan_privkey: SecretKey, spend_privkey: SecretKey) -> Result<Self, Error> {
        let labels: HashSet<Label> = HashSet::new();

        // Check version, we just refuse anything other than 0 for now
        if version != 0 {
            return Err(Error::GenericError("Can't have other version than 0 for now".to_owned()));
        }

        Ok(SilentPayment {
            version: version as u8,
            scan_privkey,
            spend_privkey,
            labels,
        })
    }

    /// Takes an hexstring that must be exactly 32B and must be on the order of the curve
    pub fn add_label(&mut self, label: String) -> Result<bool, Error> {
        let m: Label = label.try_into()?;
        Ok(self.labels.insert(m))
    }

    fn encode_silent_payment_address(
        &self,
        hrp: Option<&str>,
        m_pubkey: Option<PublicKey>
    ) -> String {
        let secp = Secp256k1::new();
        let hrp = hrp.unwrap_or("sp");
        let version = bech32::u5::try_from_u8(self.version).unwrap();

        let B_scan_bytes = self.scan_privkey.public_key(&secp).serialize();
        let B_m_bytes: [u8;33];
        if let Some(spend_pubkey) = m_pubkey {
            B_m_bytes = spend_pubkey.serialize();
        } else {
            B_m_bytes = self.spend_privkey.public_key(&secp).serialize();
        }

        let mut data = [B_scan_bytes, B_m_bytes].concat().to_base32();

        data.insert(0, version);

        bech32::encode(hrp, data, bech32::Variant::Bech32m).unwrap()
    }

    fn create_labeled_silent_payment_address(
        &self,
        m: Label,
        hrp: Option<&str>,
    ) -> Result<String, Error> {
        let secp = Secp256k1::new();
        let base_spend_key = self.spend_privkey.clone();
        let b_m = base_spend_key.add_tweak(m.as_inner())?;

        Ok(self.encode_silent_payment_address(hrp, Some(b_m.public_key(&secp))))
    }

    pub fn get_receiving_addresses(
        &mut self,
        labels: Vec<String>,
        is_testnet: bool
    ) -> Result<HashMap<String, String>, Error> {
        let mut receiving_addresses: HashMap<String, String> = HashMap::new();

        let hrp = match is_testnet {
            false => "sp",
            true => "tsp"
        };

        let no_label: String = hex::ToHex::encode_hex(&[0;32]);
        receiving_addresses.insert(no_label, self.encode_silent_payment_address(Some(hrp), None));
        for label in labels {
            let _inserted = self.add_label(label.clone())?;
            receiving_addresses.insert(
                label.clone(),
                self.create_labeled_silent_payment_address(
                    label.try_into()?,
                    Some(hrp)
            )?
        );
        }

        Ok(receiving_addresses)
    }
}

#[cfg(test)]
mod tests {
    use crate::Label;

    #[test]
    fn string_to_label() {
        // Invalid characters
        let s: String = "deadbeef?:{+!&".to_owned();
        Label::try_from(s).unwrap_err();
        // Invalid length
        let s: String = "deadbee".to_owned();
        Label::try_from(s).unwrap_err();
        // Not 32B 
        let s: String = "deadbeef".to_owned();
        Label::try_from(s).unwrap_err();
    }
}
