use std::str::FromStr;

use bitcoin::hashes::{ripemd160, Hash};
use bitcoin::util::base58::check_encode_slice;
use bitcoin::util::base58::from_check;
use bitcoin::util::taproot::TapTweakHash;
use bitcoin_bech32::{u5, WitnessProgram};
use hex_utilities::{decode_hex, encode_hex};
use secp256k1::{Scalar, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy)]
pub enum Network {
    Mainnet,
    Testnet,
}

#[derive(Copy, Clone)]
pub enum AddressType {
    /// Pay to pubkey hash.
    P2PKH,
    /// Pay to script hash.
    P2SH,
    // TODO: ADD P2WSH
    //P2wsh,/// Pay to witness script hash.
    // This should probably be named "Segwit<Something>", to differenciate from a bech32 taproot
    // address. Maybe?
    P2WPKH,
    P2TR,
}
// TODO: Does this belong in this libarary?
pub fn concat_u8(first: &[u8], second: &[u8]) -> Vec<u8> {
    [first, second].concat()
}

pub fn sha256_hex(hex_to_hash: &String) -> String {
    let hex_byte_array = decode_hex(&hex_to_hash).unwrap();
    let mut hasher = Sha256::new();
    // write input message
    hasher.update(&hex_byte_array);
    // read hash digest and consume hasher
    let sha256_result = hasher.finalize();
    let sha256_result_array = sha256_result.to_vec();
    let hex_result = encode_hex(&sha256_result_array);
    hex_result
}
pub fn double_sha256_hex(hex_to_hash: &String) -> String {
    let hex_byte_array = decode_hex(&hex_to_hash).unwrap();
    let mut hasher = Sha256::new();
    // write input message
    hasher.update(&hex_byte_array);
    // read hash digest and consume hasher
    let sha256_result = hasher.finalize();
    let sha256_result_array = sha256_result.to_vec();

    let hex_byte_array_2 = sha256_result_array;
    let mut hasher_2 = Sha256::new();
    // write input message
    hasher_2.update(&hex_byte_array_2);
    // read hash digest and consume hasher
    let sha256_result_2 = hasher_2.finalize();
    let sha256_result_array_2 = sha256_result_2.to_vec();
    encode_hex(&sha256_result_array_2)
}
pub fn get_compressed_public_key_from_private_key(private_key: &str) -> String {
    // Create 512 bit public key
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_str(private_key).unwrap();
    // We're getting the NEWER compressed version of the public key:
    //    Source: https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    let public_key_uncompressed = secret_key.public_key(&secp).serialize();
    encode_hex(&public_key_uncompressed)
}
pub fn get_wif_from_private_key(
    private_key: &String,
    network: Network,
    should_compress: bool,
) -> String {
    // 0x80 is used for the version/application byte
    // https://river.com/learn/terms/w/wallet-import-format-wif/#:~:text=WIF%20format%20adds%20a%20prefix,should%20use%20compressed%20SEC%20format.
    let version_application_byte_for_mainnet = "80";
    let version_application_byte_for_testnet = "ef";

    let version_application_byte = match network {
        Network::Mainnet => version_application_byte_for_mainnet,
        Network::Testnet => version_application_byte_for_testnet,
    };

    let private_key_hex = decode_hex(&private_key).unwrap();
    let version_array = decode_hex(version_application_byte).unwrap();
    // What does check encodings do?
    //   - does a sha25 twice, then gets the first 4 bytes of that Result
    //   - takes those first four bites and appends them to the original (version + hex array)
    //   - Read "Ecoding a private key" section here: https://en.bitcoin.it/wiki/Base58Check_encoding
    let end = "01";
    let end_array = decode_hex(end).unwrap();
    let combined_version_and_private_key_hex = concat_u8(&version_array, &private_key_hex);
    let combined_version_and_private_key_hex_with_end_array = if should_compress {
        concat_u8(&combined_version_and_private_key_hex, &end_array)
    } else {
        combined_version_and_private_key_hex
    };
    // TODO: THIS IS ONLY FOR COMPRESSED. How would we do uncompressed?
    let wif_private_key = check_encode_slice(&combined_version_and_private_key_hex_with_end_array);
    wif_private_key
}
pub fn get_p2sh_address_from_script_hash(script_hash: &String, network: Network) -> String {
    // https://bitcoin.stackexchange.com/questions/111483/parsing-p2sh-address-from-output-script
    let p2sh_version_application_byte = "05";
    let p2sh_testnet_version_application_byte = "c4";
    let version_byte = match network {
        Network::Mainnet => decode_hex(p2sh_version_application_byte).unwrap(),
        Network::Testnet => decode_hex(p2sh_testnet_version_application_byte).unwrap(),
    };
    let script_hash_bytes = decode_hex(&script_hash).unwrap();
    let script_hash_with_version_byte = concat_u8(&version_byte, &script_hash_bytes);
    let address = check_encode_slice(&script_hash_with_version_byte);
    address
}
pub fn get_p2sh_address_from_pubkey_hash(public_key_hash: &String, network: Network) -> String {
    // https://bitcoin.stackexchange.com/questions/75910/how-to-generate-a-native-segwit-address-and-p2sh-segwit-address-from-a-standard
    let prefix_bytes = decode_hex("0014").unwrap();
    let public_key_hash_bytes = decode_hex(public_key_hash).unwrap();
    let redeem_script = concat_u8(&prefix_bytes, &public_key_hash_bytes);
    let redeem_script_sha256 = sha256::digest_bytes(&redeem_script);
    let redeem_script_sha256_as_hex_array = decode_hex(&redeem_script_sha256).unwrap();
    let redeem_script_ripemd160 = ripemd160::Hash::hash(&redeem_script_sha256_as_hex_array);
    let hash160 = redeem_script_ripemd160.to_string();
    return get_p2sh_address_from_script_hash(&hash160, network);
    // Extracted this into get_p2sh_address_from_script_hash(script_hash: &String, network: Network) -> String {
    // let hash160_bytes = decode_hex(&hash160).unwrap();
    // let p2sh_version_application_byte = "05";
    // let p2sh_testnet_version_application_byte = "c4";
    // let version_byte = match network {
    //     Network::Mainnet => decode_hex(p2sh_version_application_byte).unwrap(),
    //     Network::Testnet => decode_hex(p2sh_testnet_version_application_byte).unwrap(),
    // };
    // let hash160_with_version_byte = concat_u8(&version_byte, &hash160_bytes);
    // let address = check_encode_slice(&hash160_with_version_byte);
    // println!("{:#?}", hash160_with_version_byte);
    // address
}
pub fn get_p2pkh_address_from_pubkey_hash(public_key_hash: &String, network: Network) -> String {
    // SEE ALL VERSION APPLICATION CODES HERE: https://en.bitcoin.it/wiki/List_of_address_prefixes
    // TODO: ALL ALL TYPES OF ADDRESSES
    let p2pkh_version_application_byte = "00";
    let p2pkh_testnet_version_application_byte = "6f";

    let version_application_byte = match network {
        Network::Mainnet => p2pkh_version_application_byte,
        Network::Testnet => p2pkh_testnet_version_application_byte,
    };
    // AddressType::P2SH => match network {
    //     Network::Mainnet => p2sh_version_application_byte,
    //     Network::Testnet => p2sh_testnet_version_application_byte,
    // },

    // let hex_array = Vec::from_hex(public_key_hash).unwrap();
    let hex_array = decode_hex(&public_key_hash).unwrap();
    let version_array = decode_hex(version_application_byte).unwrap();
    let a = concat_u8(&version_array, &hex_array);
    // What does check encodings do?
    //   - does a sha25 twice, then gets the first 4 bytes of that Result
    //   - takes those first four bites and appends them to the original (version + hex array)
    //   - Read "Encoding a bitcoin address": https://en.bitcoin.it/wiki/Base58Check_encoding
    let address = check_encode_slice(&a);
    address
}
pub fn get_address_from_pub_key_hash(
    public_key_hash: &String,
    network: Network,
    address_type: AddressType,
) -> String {
    match address_type {
        AddressType::P2PKH => get_p2pkh_address_from_pubkey_hash(public_key_hash, network),
        AddressType::P2SH => get_p2sh_address_from_pubkey_hash(public_key_hash, network),
        AddressType::P2WPKH => get_p2wpkh_address_from_pubkey_hash(public_key_hash, network),
        AddressType::P2TR => {
            todo!("Not sure if you can get pub key hash from a taproot address. Instead, use get address from public key, not hash")
        }
    }
}

pub fn get_bech32_address_from_witness_program(
    witness_version: u8,
    program_hex: &String,
    network: Network,
) -> String {
    let network_for_bech32_library = match network {
        Network::Mainnet => bitcoin_bech32::constants::Network::Bitcoin,
        Network::Testnet => bitcoin_bech32::constants::Network::Testnet,
    };
    let byte_array = decode_hex(&program_hex).unwrap();
    let witness_program = WitnessProgram::new(
        u5::try_from_u8(witness_version).unwrap(),
        byte_array,
        network_for_bech32_library,
    )
    .unwrap();
    let address = witness_program.to_address();
    address
}

pub fn get_p2tr_address_from_pubkey(public_key_hex: &String, network: Network) -> String {
    // Helpful to check: https://slowli.github.io/bech32-buffer/
    // Current version is 00
    // Source: https://en.bitcoin.it/wiki/Bech32
    // Source: https://www.youtube.com/watch?v=YGAeMnN4O_k&t=631s
    //
    let witness_version = 1;
    let secp = Secp256k1::new();
    let tweaked_x_only_public_key = get_tweaked_x_only_public_key_from_public_key(public_key_hex);
    // let public_key =
    //     secp256k1::PublicKey::from_str(&public_key_hex).expect("statistically impossible to hit");
    // let (untweaked_x_only_public_key, _parity) = public_key.x_only_public_key();
    // let merkle_root = None;
    // let tweak =
    //     TapTweakHash::from_key_and_tweak(untweaked_x_only_public_key, merkle_root).to_scalar();
    // let (tweaked_x_only_public_key, _parity) = untweaked_x_only_public_key
    //     .add_tweak(&secp, &tweak)
    //     .expect("Tap tweak failed");
    let address = get_bech32_address_from_witness_program(
        witness_version,
        &tweaked_x_only_public_key.to_string(),
        network,
    );
    address
}

pub fn get_p2wpkh_address_from_pubkey_hash(pub_key_hash: &String, network: Network) -> String {
    // Helpful to check: https://slowli.github.io/bech32-buffer/
    // Current version is 00
    // Source: https://en.bitcoin.it/wiki/Bech32
    let witness_version = 0;
    // TODO: Implement the conversion from public_key to bech32 myself
    // We're using an external library
    let address = get_bech32_address_from_witness_program(
        witness_version,
        &pub_key_hash.to_string(),
        network,
    );
    address
}
pub fn get_tweaked_x_only_public_key_from_p2tr_address(address: &String) -> String {
    let witness = WitnessProgram::from_address(address).unwrap();
    encode_hex(&witness.program())
}
pub fn get_pubkey_hash_from_p2wpkh_address(address: &String) -> String {
    let witness = WitnessProgram::from_address(address).unwrap();
    encode_hex(&witness.program())
}

pub fn get_address_from_pub_key(
    pub_key: &String,
    network: Network,
    address_type: AddressType,
) -> String {
    match address_type {
        AddressType::P2PKH | AddressType::P2SH | AddressType::P2WPKH => {
            let pub_key_hash = get_public_key_hash_from_public_key(&pub_key);

            let address = get_address_from_pub_key_hash(&pub_key_hash, network, address_type);
            address
        }
        AddressType::P2TR => get_p2tr_address_from_pubkey(pub_key, network),
    }
}

pub fn get_public_key_from_wif(wif: &String) -> String {
    // Check: https://coinb.in/#verify
    let private_key = convert_wif_to_private_key(&wif);
    let public_key = get_public_key_from_private_key(&private_key, is_wif_compressed(&wif));
    public_key
}
pub fn is_wif_compressed(wif: &String) -> bool {
    // Source:https://en.bitcoin.it/wiki/Wallet_import_format
    let first_char_of_wif = wif.chars().nth(0).unwrap();
    let is_compressed_wif = first_char_of_wif == 'K'
        || first_char_of_wif == 'L'
        || first_char_of_wif == 'M'
        || first_char_of_wif == 'c';
    is_compressed_wif
}
pub fn get_public_key_from_private_key(private_key: &String, is_compressed: bool) -> String {
    // Create 512 bit public key
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_str(private_key).unwrap();
    // We're getting the OLDER uncompressed version of the public key:
    //    Source: https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    let public_key = if is_compressed {
        secret_key.public_key(&secp).serialize().to_vec()
    } else {
        secret_key
            .public_key(&secp)
            .serialize_uncompressed()
            .to_vec()
    };
    encode_hex(&public_key)
}

pub fn hash160_for_non_hex(non_hex_string_to_hash: &String) -> String {
    let string_as_array = non_hex_string_to_hash.as_bytes();
    let sha256 = sha256::digest_bytes(&string_as_array);
    let sha256_as_hex_array = sha256.as_bytes();
    let ripemd160 = ripemd160::Hash::hash(&sha256_as_hex_array);
    ripemd160.to_string()
}
pub fn hash160_for_hex(hex_to_hash: &String) -> String {
    let hex_array = decode_hex(hex_to_hash).unwrap();
    let sha256 = sha256_hex(hex_to_hash);
    let sha256_as_hex_array = decode_hex(&sha256).unwrap();
    let public_key_ripemd160 = ripemd160::Hash::hash(&sha256_as_hex_array);
    public_key_ripemd160.to_string()
}

pub fn get_tweaked_x_only_public_key_from_public_key(public_key_hex: &String) -> String {
    let secp = Secp256k1::new();
    let public_key =
        secp256k1::PublicKey::from_str(&public_key_hex).expect("statistically impossible to hit");
    let (untweaked_x_only_public_key, _parity) = public_key.x_only_public_key();
    let merkle_root = None;
    let tweak =
        TapTweakHash::from_key_and_tweak(untweaked_x_only_public_key, merkle_root).to_scalar();
    let (tweaked_x_only_public_key, _parity) = untweaked_x_only_public_key
        .add_tweak(&secp, &tweak)
        .expect("Tap tweak failed");
    tweaked_x_only_public_key.to_string()
}

pub fn get_public_key_hash_from_public_key(public_key: &String) -> String {
    hash160_for_hex(public_key)
}

pub fn get_script_hash_from_p2sh_address(address: &str) -> String {
    if bitcoin_address::is_p2sh(&address.to_string()) {
        let address_base58check_decoded = from_check(&address).unwrap();
        let address_base58check_decoded_without_first_byte =
            address_base58check_decoded.get(1..).unwrap();
        let script_hash = encode_hex(&address_base58check_decoded_without_first_byte);
        script_hash
    } else {
        panic!("Address is not p2sh: {}", address);
    }
}

pub fn get_public_key_hash_from_non_bech_32_address(address: &String) -> String {
    if bitcoin_address::is_legacy(&address.to_string()) {
        let address_base58check_decoded = from_check(&address).unwrap();
        let address_base58check_decoded_without_first_byte =
            address_base58check_decoded.get(1..).unwrap();
        let pub_key_hash = encode_hex(&address_base58check_decoded_without_first_byte);
        pub_key_hash
    } else {
        panic!("Address must be legacy: {}", address);
    }
}
pub fn get_public_key_hash_from_address(address: &String) -> String {
    // TODO: This should be exaustive and work for every address types
    // TODO: Implement taproot
    if bitcoin_address::is_legacy(address) {
        get_public_key_hash_from_non_bech_32_address(address)
    } else if bitcoin_address::is_segwit_native(address) {
        get_pubkey_hash_from_p2wpkh_address(address)
    } else if bitcoin_address::is_nested_segwit(address) {
        panic!(
            "Couldn't get public key hash from address ({}). Nested segwit addresses not supported. Instead, you should use get_script_hash_from_p2sh_address() function",
            address
        );
    } else {
        panic!("Couldn't get public key hash from address: {}", address);
    }
}
pub fn convert_wif_to_private_key(wif: &String) -> String {
    // Check: https://coinb.in/#verify
    // Source:https://en.bitcoin.it/wiki/Wallet_import_format
    // 1. decode the base58check

    let is_compressed_wif = is_wif_compressed(wif);
    let wif_base58check_decoded_result = from_check(&wif);
    let wif_base58check_decoded = from_check(&wif).unwrap();
    // 2. drop the fist byte
    // TODO: It's more complicated than this: "Drop the first byte (it should be 0x80, however
    // legacy Electrum[1][2] or some SegWit vanity address generators[3] may use 0x81-0x87). If
    // the private key corresponded to a compressed public key, also drop the last byte (it
    // should be 0x01). If it corresponded to a compressed public key, the WIF string will have
    // started with K or L (or M, if it's exported from legacy Electrum[1][2] etc[3]) instead
    // of 5 (or c instead of 9 on testnet). This is the private key."
    // Source: https://en.bitcoin.it/wiki/Wallet_import_format
    let wif_base58check_decoded_without_first_byte = wif_base58check_decoded.get(1..).unwrap();
    let wif_base58check_decoded_without_first_byte_and_adjusted_for_compression =
        if is_compressed_wif {
            wif_base58check_decoded_without_first_byte
                .get(..=(wif_base58check_decoded_without_first_byte.len() - 2))
                .unwrap()
        } else {
            wif_base58check_decoded_without_first_byte
        };
    let wif_base58check_decoded_without_first_byte_and_adjusted_for_compression_hex =
        encode_hex(wif_base58check_decoded_without_first_byte_and_adjusted_for_compression);
    wif_base58check_decoded_without_first_byte_and_adjusted_for_compression_hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        // let result = add(2, 2);
        // assert_eq!(result, 4);
    }
}
