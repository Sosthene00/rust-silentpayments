use std::{fs::File, io::Read, str::FromStr};

use bitcoin::{consensus::serialize, secp256k1::{self, silentpayments::SilentpaymentsRecipient, Scalar, SecretKey, XOnlyPublicKey}, OutPoint, Txid};
use bitcoin_hashes::Hash;
use serde_json::from_str;
use silentpayments::utils::SilentPaymentAddress;

use super::structs::{OutputWithSignature, TestData};

use std::io::{self, Cursor};

fn deser_compact_size(f: &mut Cursor<&Vec<u8>>) -> io::Result<u64> {
    let mut buf = [0; 8];
    f.read_exact(&mut buf[..1])?;
    match buf[0] {
        0xfd => {
            f.read_exact(&mut buf[..2])?;
            Ok(u16::from_le_bytes(buf[..2].try_into().unwrap()) as u64)
        }
        0xfe => {
            f.read_exact(&mut buf[..4])?;
            Ok(u32::from_le_bytes(buf[..4].try_into().unwrap()) as u64)
        }
        0xff => {
            f.read_exact(&mut buf)?;
            Ok(u64::from_le_bytes(buf))
        }
        _ => Ok(buf[0] as u64),
    }
}

fn deser_string(f: &mut Cursor<&Vec<u8>>) -> io::Result<Vec<u8>> {
    let size = deser_compact_size(f)? as usize;
    let mut buf = vec![0; size];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn get_smallest_outpoint(outpoints: Vec<(String, u32)>) -> anyhow::Result<[u8; 36]> {
    let mut sorted_outpoints = Vec::with_capacity(outpoints.len());
    for (txid, vout) in outpoints {
        let txid = Txid::from_str(&txid)?;
        let outpoint = OutPoint::new(txid, vout);
        sorted_outpoints.push(serialize(&outpoint));
    }
    sorted_outpoints.sort_unstable();

    let smallest_outpoint = sorted_outpoints.first().take().unwrap();

    let mut ret = [0u8; 36];
    ret.copy_from_slice(&smallest_outpoint);

    Ok(ret)
}

pub fn deser_string_vector(f: &mut Cursor<&Vec<u8>>) -> io::Result<Vec<Vec<u8>>> {
    // Check if the buffer is empty before attempting to deserialize the size
    if f.get_ref().is_empty() {
        return Ok(Vec::new()); // Return an empty vector if the buffer is empty
    }
    let size = deser_compact_size(f)? as usize;
    let mut vec = Vec::with_capacity(size);
    for _ in 0..size {
        vec.push(deser_string(f)?);
    }
    Ok(vec)
}

pub fn read_file() -> Vec<TestData> {
    let mut file = File::open("tests/resources/send_and_receive_test_vectors.json").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    from_str(&contents).unwrap()
}

pub fn decode_outputs_to_check(outputs: &Vec<String>) -> Vec<XOnlyPublicKey> {
    outputs
        .iter()
        .map(|x| XOnlyPublicKey::from_str(x).unwrap())
        .collect()
}

pub fn decode_recipients(recipients: Vec<String>) -> Vec<SilentpaymentsRecipient> {
    recipients
        .iter()
        .enumerate()
        .map(|(i, sp_addr_str)| {
            let sp_addr = SilentPaymentAddress::try_from(sp_addr_str.as_str()).unwrap();

            let recipient = SilentpaymentsRecipient::new(&sp_addr.get_scan_key(), &sp_addr.get_spend_key(), i);
            recipient
        })
        .collect()
}

pub fn verify_and_calculate_signatures(
    key_tweaks: Vec<[u8; 32]>,
    b_spend: SecretKey,
) -> Result<Vec<OutputWithSignature>, secp256k1::Error> {
    let secp = secp256k1::Secp256k1::new();

    let msg = bitcoin_hashes::sha256::Hash::hash(b"message").to_byte_array();
    let aux = bitcoin_hashes::sha256::Hash::hash(b"random auxiliary data").to_byte_array();

    let mut res: Vec<OutputWithSignature> = vec![];
    for tweak in key_tweaks {
        // Add the tweak to the b_spend to get the final key
        let k = b_spend.add_tweak(&Scalar::from_be_bytes(tweak).unwrap())?;

        // get public key
        let P = k.x_only_public_key(&secp).0;

        // Sign the message with schnorr
        let sig = secp.sign_schnorr_with_aux_rand(&msg, &k.keypair(&secp), &aux);

        // Verify the message is correct
        secp.verify_schnorr(&sig, &msg, &P)?;

        // Push result to list
        res.push(OutputWithSignature {
            pub_key: P.to_string(),
            priv_key_tweak: hex::encode(tweak),
            signature: sig.to_string(),
        });
    }
    Ok(res)
}
