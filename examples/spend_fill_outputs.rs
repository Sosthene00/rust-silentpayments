use std::{collections::HashSet, env, error::Error, io::Write};

use bitcoin::{key::TweakedPublicKey, Address, OutPoint, PrivateKey, Script, Txid};
use secp256k1::{
    hashes::{hex::FromHex, sha256, Hash},
    Scalar, Secp256k1, SecretKey,
};
use silentpayments::sending::generate_recipient_pubkeys;
use silentpayments::utils::sending::calculate_partial_secret;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    // get the outpoints
    let args_outpoints: Vec<&str> = args.get(1).unwrap().split_whitespace().collect();

    let mut outpoints: Vec<(String, u32)> = vec![];
    for o in args_outpoints {
        let txid_vout: Vec<&str> = o.split(':').collect();
        assert!(txid_vout.len() == 2);
        outpoints.push((txid_vout[0].to_owned(), txid_vout[1].parse().unwrap()))
    }

    // get the corresponding private key
    let privkey = PrivateKey::from_wif(&args[3]).unwrap();

    let mut input_privkeys: Vec<(SecretKey, bool)> = vec![];
    input_privkeys.push((privkey.inner, false));

    let sender_secret = calculate_partial_secret(&input_privkeys, &outpoints);

    let mut recipients_address: Vec<&str> = vec![];
    if let Some(addresses) = args.get(4) {}
    let recipient_pubkey = generate_recipient_pubkeys(args[4].clone(), sender_secret).unwrap();

    let spk =
        Script::new_v1_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(recipient_pubkey));
    let address = Address::from_script(&spk, bitcoin::Network::Signet).unwrap();

    println!(
        "Generated address {} for recipient {} to be used in tx that consumes {}:{}",
        address, args[4], args[1], args[2]
    );

    Ok(())
}
