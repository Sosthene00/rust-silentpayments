#![allow(non_snake_case)]
mod common;
#[cfg(test)]
mod tests {
    use bimap::BiMap;
    use bitcoin::consensus::serialize;
    use bitcoin::secp256k1::silentpayments::{
        silentpayments_recipient_create_label_tweak, silentpayments_recipient_create_labelled_spend_pubkey, silentpayments_recipient_create_output_pubkey, silentpayments_recipient_scan_outputs, silentpayments_sender_create_outputs, LabelTweakResult, SilentpaymentsPublicData, SilentpaymentsRecipient
    };
    use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, Keypair};
    use bitcoin::{XOnlyPublicKey, OutPoint, Txid};
    use silentpayments::utils::common::{label_lookup_callback, LabelsStore};
    use silentpayments::utils::SilentPaymentAddress;
    use silentpayments::utils::{
        receiving::{
            calculate_ecdh_shared_secret, calculate_tweak_data, get_pubkey_from_input, is_p2tr, is_eligible
        },
        common::Label,
        Network,
    };
    use std::{collections::HashSet, io::Cursor, str::FromStr};

    use crate::common::utils::get_smallest_outpoint;
    use crate::common::{
        structs::TestData,
        utils::{
            self, decode_outputs_to_check, decode_recipients, deser_string_vector,
            verify_and_calculate_signatures,
        },
    };

    const NETWORK: Network = Network::Mainnet;
    const VERSION: u8 = 0;

    #[test]
    fn test_with_test_vectors() {
        let testdata = utils::read_file();

        for test in testdata {
            process_test_case(test);
        }
    }

    fn process_test_case(test_case: TestData) {
        println!("test: {}", test_case.comment);
        let secp = Secp256k1::new();

        let mut sending_outputs: HashSet<String> = HashSet::new();

        for sendingtest in test_case.sending {
            let given = sendingtest.given;
            let expected = sendingtest.expected;
            let outpoints: Vec<(String, u32)> = given
                .vin
                .iter()
                .map(|vin| (vin.txid.clone(), vin.vout))
                .collect();
            let mut taproot_priv_keys: Vec<Keypair> = Vec::new();
            let mut plain_priv_keys: Vec<SecretKey> = Vec::new();
            for input in given.vin {
                let script_sig = hex::decode(&input.scriptSig).unwrap();
                let txinwitness_bytes = hex::decode(&input.txinwitness).unwrap();
                let mut cursor = Cursor::new(&txinwitness_bytes);
                let txinwitness = deser_string_vector(&mut cursor).unwrap();
                let script_pub_key = hex::decode(&input.prevout.scriptPubKey.hex).unwrap();

                match get_pubkey_from_input(&script_sig, &txinwitness, &script_pub_key) {
                    Ok(Some((_pubkey, is_p2tr))) => {
                        if is_p2tr {
                            taproot_priv_keys.push(Keypair::from_secret_key(&secp, &SecretKey::from_str(&input.private_key).unwrap()))
                        } else {
                            plain_priv_keys.push(SecretKey::from_str(&input.private_key).unwrap())
                        }
                    },
                    Ok(None) => (),
                    Err(e) => panic!("Problem parsing the input: {:?}", e),
                }
            }

            if taproot_priv_keys.is_empty() && plain_priv_keys.is_empty() {
                continue;
            }

            // we drop the amounts from the test here, since we don't work with amounts
            // the wallet should make sure the amount sent are correct

            // We look up the number of expected outputs for each address
            let recipients: Vec<SilentpaymentsRecipient> = decode_recipients(given.recipients);

            let smallest_outpoint = get_smallest_outpoint(outpoints).unwrap();

            let taproot_seckeys = taproot_priv_keys.iter().collect::<Vec<&Keypair>>();
            let plain_seckeys = plain_priv_keys.iter().collect::<Vec<&SecretKey>>();

            println!("recipients: {:?}", recipients);

            let outputs = silentpayments_sender_create_outputs(
                &secp, 
                recipients.iter().collect::<Vec<&SilentpaymentsRecipient>>().as_mut_slice(), 
                &smallest_outpoint, 
                Some(taproot_seckeys.as_slice()),
                Some(plain_seckeys.as_slice())
            ).unwrap();

            for output_pubkey in &outputs {
                sending_outputs.insert(hex::encode(output_pubkey.serialize()));
            }

            println!("sending_outputs: {:?}", sending_outputs);

            // if test_case.comment == "Multiple outputs: multiple outputs, multiple recipients" {
            //     assert!(false);
            // }
            
            assert!(expected.outputs.iter().any(|candidate_set| {
                println!("candidate_set: {:?}", candidate_set);
                sending_outputs
                    .iter()
                    .all(|output| candidate_set.contains(output))
            }));
        }

        for receivingtest in test_case.receiving {
            let given = receivingtest.given;
            let expected = receivingtest.expected;

            let b_scan = SecretKey::from_str(&given.key_material.scan_priv_key).unwrap();
            let b_spend = SecretKey::from_str(&given.key_material.spend_priv_key).unwrap();
            let B_spend = b_spend.public_key(&secp);
            let B_scan = b_scan.public_key(&secp);

            let change_label = silentpayments_recipient_create_label_tweak(&secp, &b_scan, 0).unwrap();
            let change_B_spend = silentpayments_recipient_create_labelled_spend_pubkey(&secp, &B_spend, &change_label.pubkey).unwrap();
            let change_address = SilentPaymentAddress::new(B_scan, change_B_spend, NETWORK, VERSION).unwrap();

            let outputs_to_check = decode_outputs_to_check(&given.outputs);

            let smallest_outpoint = get_smallest_outpoint(given.vin.iter().map(|vin| (vin.txid.clone(), vin.vout)).collect()).unwrap();

            let mut taproot_pubkeys: Vec<XOnlyPublicKey> = vec![];
            let mut legacy_pubkeys: Vec<PublicKey> = vec![];
            for input in given.vin {
                let script_sig = hex::decode(&input.scriptSig).unwrap();
                let txinwitness_bytes = hex::decode(&input.txinwitness).unwrap();
                let mut cursor = Cursor::new(&txinwitness_bytes);
                let txinwitness = deser_string_vector(&mut cursor).unwrap();
                let script_pub_key = hex::decode(&input.prevout.scriptPubKey.hex).unwrap();

                match get_pubkey_from_input(&script_sig, &txinwitness, &script_pub_key) {
                    Ok(Some((pubkey, is_p2tr))) => {
                        if is_p2tr {
                            taproot_pubkeys.push(pubkey.x_only_public_key().0);
                        } else {
                            legacy_pubkeys.push(pubkey);
                        }
                    }
                    Ok(None) => (),
                    Err(e) => panic!("Problem parsing the input: {:?}", e),
                }
            }

            let xonly_pubkeys = taproot_pubkeys.iter().collect::<Vec<&XOnlyPublicKey>>();
            let plain_pubkeys = legacy_pubkeys.iter().collect::<Vec<&PublicKey>>();

            if xonly_pubkeys.is_empty() && plain_pubkeys.is_empty() {
                continue;
            }

            let mut labels: BiMap<PublicKey, [u8; 32]> = BiMap::new();

            for label_int in &given.labels {
                let label = silentpayments_recipient_create_label_tweak(&secp, &b_scan, *label_int).unwrap();
                labels.insert(label.pubkey, label.label_tweak);
            }

            let mut receiving_addresses: HashSet<String> = HashSet::new();
            // get receiving address for no label
            receiving_addresses.insert(SilentPaymentAddress::new(B_scan, B_spend, NETWORK, VERSION).unwrap().to_string());

            // get receiving addresses for every label
            for (label, tweak) in &labels {
                let labelled_B_spend = silentpayments_recipient_create_labelled_spend_pubkey(&secp, &B_spend, label).unwrap();
                let labelled_address = SilentPaymentAddress::new(B_scan, labelled_B_spend, NETWORK, VERSION).unwrap();
                receiving_addresses
                    .insert(labelled_address.to_string());
            }

            if !&given.labels.iter().any(|l| *l == 0) {
                receiving_addresses.remove(&change_address.to_string());
            }

            let set1: HashSet<_> = receiving_addresses.iter().collect();
            let set2: HashSet<_> = expected.addresses.iter().collect();

            // check that the receiving addresses generated are equal
            // to the expected addresses
            assert_eq!(set1, set2);

            // let tweak_data = calculate_tweak_data(&input_pub_keys, &outpoints).unwrap();
            // let ecdh_shared_secret = calculate_ecdh_shared_secret(&tweak_data, &b_scan);
            let public_data = SilentpaymentsPublicData::create(
                &secp, 
                &smallest_outpoint, 
                Some(xonly_pubkeys.as_slice()), 
                Some(plain_pubkeys.as_slice())
            ).unwrap();

            let labels_store = LabelsStore::new(labels);
            let scanned_outputs_received = silentpayments_recipient_scan_outputs(
                &secp, 
                outputs_to_check.iter().collect::<Vec<&XOnlyPublicKey>>().as_slice(), 
                &b_scan, 
                &public_data, 
                &B_spend, 
                label_lookup_callback, 
                labels_store
            ).unwrap();

            let key_tweaks: Vec<[u8; 32]> = scanned_outputs_received
                .into_iter()
                .map(|output| {
                    output.get_tweak()
                })
                .collect();


            println!("key_tweaks: {:?}", key_tweaks);

            let res = verify_and_calculate_signatures(key_tweaks, b_spend).unwrap();
            assert!(expected.outputs.len() == res.len());
            assert!(res.iter().all(|output| expected.outputs.contains(output)));
        }
    }
}
