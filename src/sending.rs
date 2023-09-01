use bech32::{FromBase32, ToBase32};

use secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey};
use std::collections::{HashSet, HashMap};

use crate::{
    error::Error, 
    structs::Outpoint,
    utils::{hash_outpoints, ser_uint32, sha256, Result
}};

struct SilentPaymentAddress {
    version: u8,
    scan_pubkey: PublicKey,
    m_pubkey: PublicKey,
    is_testnet: bool,
}

impl SilentPaymentAddress {
    pub fn new(
        scan_pubkey: PublicKey,
        m_pubkey: PublicKey,
        is_testnet: bool,
        version: u8,
    ) -> Result<Self> {
        if version != 0 {
            return Err(Error::GenericError(
                "Can't have other version than 0 for now".to_owned(),
            ));
        }

        Ok(SilentPaymentAddress {
            scan_pubkey,
            m_pubkey,
            is_testnet,
            version,
        })
    }
}

impl TryFrom<&str> for SilentPaymentAddress {
    type Error = Error;

    fn try_from(addr: &str) -> Result<Self> {
        let (hrp, data, _variant) = bech32::decode(&addr)?;

        if data.len() != 107 {
            return Err(Error::GenericError("Address length is wrong".to_owned()));
        }

        let version = data[0].to_u8();

        let is_testnet = match hrp.as_str() {
            "sp" => false,
            "tsp" => true,
            _ => {
                return Err(Error::InvalidAddress(format!(
                    "Wrong prefix, expected \"sp\" or \"tsp\", got \"{}\"",
                    &hrp
                )))
            }
        };

        let data = Vec::<u8>::from_base32(&data[1..])?;

        let scan_pubkey = PublicKey::from_slice(&data[..33])?;
        let m_pubkey = PublicKey::from_slice(&data[33..])?;

        SilentPaymentAddress::new(scan_pubkey, m_pubkey, is_testnet, version.into())
    }
}

impl TryFrom<String> for SilentPaymentAddress {
    type Error = Error;

    fn try_from(addr: String) -> Result<Self> {
        addr.as_str().try_into()
    }
}

impl Into<String> for SilentPaymentAddress {
    fn into(self) -> String {
        let hrp = match self.is_testnet {
            true => "tsp",
            false => "sp",
        };

        let version = bech32::u5::try_from_u8(self.version).unwrap();

        let B_scan_bytes = self.scan_pubkey.serialize();
        let B_m_bytes = self.m_pubkey.serialize();

        let mut data = [B_scan_bytes, B_m_bytes].concat().to_base32();

        data.insert(0, version);

        bech32::encode(hrp, data, bech32::Variant::Bech32m).unwrap()
    }
}

fn decode_silent_payment_address(addr: &str) -> Result<(PublicKey, PublicKey)> {
    let (_hrp, data, _variant) = bech32::decode(&addr)?;

    let data = Vec::<u8>::from_base32(&data[1..])?;

    let B_scan = PublicKey::from_slice(&data[..33])?;
    let B_spend = PublicKey::from_slice(&data[33..])?;

    Ok((B_scan, B_spend))
}

fn get_a_sum_secret_keys(input: &Vec<(SecretKey, bool)>) -> Result<SecretKey> {
    let secp = Secp256k1::new();

    let mut negated_keys: Vec<SecretKey> = vec![];

    for (key, x_only) in input {
        let (_, parity) = key.x_only_public_key(&secp);

        if *x_only && parity == Parity::Odd {
            negated_keys.push(key.negate());
        } else {
            negated_keys.push(*key);
        }
    }

    let (head, tail) = negated_keys.split_first().ok_or(Error::GenericError("Empty input list".to_owned()))?;

    let result: Result<SecretKey> = tail
        .iter()
        .fold(Ok(*head), |acc: Result<SecretKey>, &item| {
            Ok(acc?.add_tweak(&item.into())?)
        });

    result
}

pub fn create_outputs(
    outpoints: &HashSet<Outpoint>,
    input_priv_keys: &Vec<(SecretKey, bool)>,
    recipients: &Vec<(String, f32)>,
) -> Result<Vec<HashMap<String, f32>>> {
    let secp = Secp256k1::new();

    let outpoints_hash = hash_outpoints(outpoints)?;

    let a_sum = get_a_sum_secret_keys(input_priv_keys)?;

    let mut silent_payment_groups: HashMap<PublicKey, Vec<(PublicKey, f32)>> = HashMap::new();
    for (payment_address, amount) in recipients {
        let (B_scan, B_m) = decode_silent_payment_address(&payment_address)?;

        if let Some(payments) = silent_payment_groups.get_mut(&B_scan) {
            payments.push((B_m, *amount));
        } else {
            silent_payment_groups.insert(B_scan, vec![(B_m, *amount)]);
        }
    }

    let mut result: Vec<HashMap<String, f32>> = vec![];
    for (B_scan, B_m_values) in silent_payment_groups.into_iter() {
        let mut n = 0;

        //calculate shared secret
        let intermediate = B_scan.mul_tweak(&secp, &a_sum.into())?;
        let scalar = Scalar::from_be_bytes(outpoints_hash)?;
        let ecdh_shared_secret = intermediate.mul_tweak(&secp, &scalar)?.serialize();

        for (B_m, amount) in B_m_values {
            let mut bytes: Vec<u8> = Vec::new();
            bytes.extend_from_slice(&ecdh_shared_secret);
            bytes.extend_from_slice(&ser_uint32(n));

            let t_n = sha256(&bytes);

            let G: PublicKey = SecretKey::from_slice(&Scalar::ONE.to_be_bytes())?.public_key(&secp);
            let res = G.mul_tweak(&secp, &Scalar::from_be_bytes(t_n)?)?;
            let reskey = res.combine(&B_m)?;
            let (reskey_xonly, _) = reskey.x_only_public_key();

            let mut toAdd: HashMap<String, f32> = HashMap::new();

            toAdd.insert(reskey_xonly.to_string(), amount);

            result.push(toAdd);
            n += 1;
        }
    }
    Ok(result)
}

pub fn decode_scan_pubkey(silent_payment_address: String) -> Result<PublicKey> {
    let address: SilentPaymentAddress = silent_payment_address.try_into()?;
    Ok(address.scan_pubkey)
}
