use secp256k1::{SecretKey, Message, hashes::Hash, Scalar};
use silentpayments::structs::OutputWithSignature;

pub mod utils;
pub mod structs;

pub fn verify_and_calculate_signatures(
    privkeys: Vec<SecretKey>,
    b_spend: SecretKey,
) -> Result<Vec<OutputWithSignature>, secp256k1::Error> {
    let secp = secp256k1::Secp256k1::new();

    let msg = Message::from_hashed_data::<secp256k1::hashes::sha256::Hash>(b"message");
    let aux = secp256k1::hashes::sha256::Hash::hash(b"random auxiliary data").to_byte_array();

    let mut res: Vec<OutputWithSignature> = vec![];
    for mut k in privkeys {
        let (P, parity) = k.x_only_public_key(&secp);
        let tweak = k.add_tweak(&Scalar::from_be_bytes(b_spend.negate().secret_bytes()).unwrap())?;

        if parity == secp256k1::Parity::Odd {
            k = k.negate();
        }

        let sig = secp.sign_schnorr_with_aux_rand(&msg, &k.keypair(&secp), &aux);

        secp.verify_schnorr(&sig, &msg, &P)?;


        res.push(OutputWithSignature {
            pub_key: P.to_string(),
            priv_key_tweak: hex::encode(tweak.secret_bytes()),
            signature: sig.to_string(),
        });
    }
    Ok(res)
}
