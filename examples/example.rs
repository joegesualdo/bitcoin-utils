use bitcoin_utils::*;
fn main() {
    let s = "TapSighash";
    let a = sha256_non_hex(s);
    println!("{}", a)
}
