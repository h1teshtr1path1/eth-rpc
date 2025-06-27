use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use evm_rpc_types::{
    BlockTag, RpcError, RpcService, EthSepoliaService, RpcServices, RpcConfig, GetTransactionCountArgs
};
use hex;
use ic_cdk::api::call::call_with_payment128;
use ic_cdk::api::management_canister::ecdsa::{
    ecdsa_public_key, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument,
};
use ic_cdk::{call, export_candid};
use ic_cdk_macros::{query, update};
use num_traits::ToPrimitive;
use rlp::{Encodable, RlpStream};
use serde_json::Value;
use sha3::{Digest, Keccak256};

mod eth_extended_types;
use crate::eth_extended_types::{
    MultiGetTransactionCountResult, GetTransactionCountResult, MultiSendRawTransactionResult, SendRawTransactionResult, SendRawTransactionStatus
};


const EVM_RPC_CANISTER_ID: &str = "7hfb6-caaaa-aaaar-qadga-cai";

async fn get_gas_price() -> Result<u64, String> {
    let params = (
        RpcService::EthSepolia(EthSepoliaService::PublicNode),
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":null,\"id\":1}".to_string(),
        2048_u64,
    );

    // Compute the cycles required for the request
    let (cycles_result,): (Result<u128, RpcError>,) = ic_cdk::api::call::call(
        EVM_RPC_CANISTER_ID.parse().unwrap(),
        "requestCost",
        params.clone(),
    )
    .await
    .unwrap();
    let cycles = cycles_result
        .unwrap_or_else(|e| ic_cdk::trap(&format!("error in `request_cost`: {:?}", e)));

    let (response,): (Result<String, RpcError>,) = call_with_payment128(
        EVM_RPC_CANISTER_ID.parse().unwrap(),
        "request",
        params.clone(),
        cycles,
    )
    .await
    .map_err(|e| format!("Call to eth_gasPrice failed: {:?}", e))?;

    match response {
        Ok(json) => {
            let parsed: Value =
                serde_json::from_str(&json).map_err(|e| format!("Failed to parse JSON: {}", e))?;
            let hex_str = parsed
                .get("result")
                .and_then(|v| v.as_str())
                .ok_or("Missing 'result' field in response JSON")?;
            let value = u64::from_str_radix(hex_str.trim_start_matches("0x"), 16)
                .map_err(|e| format!("Failed to decode hex: {}", e))?;
            Ok(value)
        }
        Err(err) => ic_cdk::trap(&format!("error in `request` with cycles: {:?}", err)),
    }
}

async fn get_nonce(address: &str) -> Result<candid::Nat, String> {
    let services = RpcServices::EthSepolia(Some(vec![EthSepoliaService::PublicNode]));
    let args = (
        services,
        None::<RpcConfig>,
        GetTransactionCountArgs {
            address: address.parse().map_err(|e| format!("Invalid address: {:?}", e))?,
            block: BlockTag::Latest,
        },
    );

    let cycles: u128 = 6_000_000_000;

    let (result,): (MultiGetTransactionCountResult,) = call_with_payment128(
        EVM_RPC_CANISTER_ID.parse().unwrap(),
        "eth_getTransactionCount",
        args,
        cycles,
    )
    .await
    .map_err(|e| format!("Call to eth_getTransactionCount failed: {:?}", e))?;

    match result {
        MultiGetTransactionCountResult::Consistent(GetTransactionCountResult::Ok(nonce)) => Ok(nonce),
        MultiGetTransactionCountResult::Consistent(GetTransactionCountResult::Err(err)) => ic_cdk::trap(&format!("error in `request` with cycles: {:?}", err)),
        MultiGetTransactionCountResult::Inconsistent(_results) => ic_cdk::trap(&format!("error in `request`")),
    }
}

async fn get_eth_address() -> Result<String, String> {
    let key_id = EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: "test_key_1".to_string(),
    };

    let (pubkey_response,) = ecdsa_public_key(EcdsaPublicKeyArgument {
        canister_id: None,
        derivation_path: vec![],
        key_id,
    })
    .await
    .map_err(|e| format!("Failed to get public key: {:?}", e))?;

    let pubkey = &pubkey_response.public_key;

    // Ethereum address = last 20 bytes of Keccak256(pubkey[1..])
    let hash = Keccak256::digest(&pubkey[1..]);
    let eth_address = &hash[12..];

    Ok(format!("0x{}", hex::encode(eth_address)))
}

#[update]
async fn get_address_nonce_gas() -> String {
    let addr = match get_eth_address().await {
        Ok(addr) => addr,
        Err(e) => return format!("Error getting ETH address: {}", e),
    };

    let nonce = match get_nonce(&addr).await {
        Ok(nonce) => nonce,
        Err(e) => return format!("Error getting nonce: {}", e),
    };

    let gas_price = match get_gas_price().await {
        Ok(gas_price) => gas_price,
        Err(e) => return format!("Error getting gas price: {}", e),
    };

    format!("Address: {}\nNonce: {}\nGas price: {} wei", addr, nonce, gas_price)
}

#[update]
pub async fn send_signed_transfer() -> String {
    // 1. Get sender address
    let sender = match get_eth_address().await {
        Ok(addr) => addr,
        Err(e) => return format!("Error getting ETH address: {}", e),
    };
    // 2. Get nonce
    let nonce_nat = match get_nonce(&sender).await {
        Ok(nonce) => nonce,
        Err(e) => return format!("Error getting nonce: {}", e),
    };
    let nonce = nonce_nat.0.to_u64().unwrap_or(0);
    // 3. Get gas price
    let gas_price = match get_gas_price().await {
        Ok(gas_price) => gas_price,
        Err(e) => return format!("Error getting gas price: {}", e),
    };
    // 4. Prepare transaction fields
    let to = hex::decode("C40CCDDff12a8424e5826513aaA27d367de3E6d5").unwrap();
    let mut to_arr = [0u8; 20];
    to_arr.copy_from_slice(&to);
    let tx = LegacyTransaction {
        nonce,
        gas_price,
        gas_limit: 21_000,
        to: to_arr,
        value: 1_0_000_000_000_000u128, // 0.00001 ETH
        data: vec![],
        chain_id: 11155111,
    };
    // 5. RLP encode unsigned tx
    let rlp_unsigned = tx.rlp_encode_unsigned();
    // 6. Hash with keccak256
    let hash = keccak256(&rlp_unsigned);
    // 7. Sign with ECDSA
    let sig = match sign_with_ecdsa(hash.to_vec(), vec![]).await {
        Ok(sig) => sig,
        Err(e) => return format!("Error signing: {}", e),
    };
    // 8. Parse signature
    let (v, r, s) = parse_ecdsa_signature(&sig, 11155111);
    // 9. RLP encode signed tx
    let raw_tx = tx.rlp_encode_signed(v, &r, &s);
    let raw_tx_hex = format!("0x{}", hex::encode(raw_tx));
    // 10. Send raw transaction via EVM RPC canister using eth_sendRawTransaction endpoint
    let services = RpcServices::EthSepolia(Some(vec![EthSepoliaService::PublicNode]));
    let args = (services, None::<RpcConfig>, raw_tx_hex.clone());
    let cycles: u128 = 6_000_000_000;
    let (result,): (MultiSendRawTransactionResult,) = call_with_payment128(
        EVM_RPC_CANISTER_ID.parse().unwrap(),
        "eth_sendRawTransaction",
        args,
        cycles,
    )
    .await
    .map_err(|e| format!("Call to eth_sendRawTransaction failed: {:?}", e)).unwrap();
    match result {
        MultiSendRawTransactionResult::Consistent(SendRawTransactionResult::Ok(SendRawTransactionStatus::Ok(Some(tx_hash)))) => format!("Transaction hash: {}", tx_hash),
        MultiSendRawTransactionResult::Consistent(SendRawTransactionResult::Ok(SendRawTransactionStatus::Ok(None))) => "Transaction sent, but no hash returned".to_string(),
        MultiSendRawTransactionResult::Consistent(SendRawTransactionResult::Ok(SendRawTransactionStatus::NonceTooLow)) => "Error: Nonce too low".to_string(),
        MultiSendRawTransactionResult::Consistent(SendRawTransactionResult::Ok(SendRawTransactionStatus::NonceTooHigh)) => "Error: Nonce too high".to_string(),
        MultiSendRawTransactionResult::Consistent(SendRawTransactionResult::Ok(SendRawTransactionStatus::InsufficientFunds)) => "Error: Insufficient funds".to_string(),
        MultiSendRawTransactionResult::Consistent(SendRawTransactionResult::Err(e)) => format!("Error sending transaction: {:?}", e),
        MultiSendRawTransactionResult::Inconsistent(results) => format!("Inconsistent results"),
    }
}

#[query]
pub fn get_cycle_balance() -> u64 {
    ic_cdk::api::canister_balance() as u64
}

pub struct LegacyTransaction {
    pub nonce: u64,
    pub gas_price: u64,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
    pub chain_id: u64,
}

impl LegacyTransaction {
    /// RLP encode for signing (with empty v, r, s)
    pub fn rlp_encode_unsigned(&self) -> Vec<u8> {
        let mut stream = RlpStream::new_list(9);
        stream.append(&self.nonce);
        stream.append(&self.gas_price);
        stream.append(&self.gas_limit);
        stream.append(&self.to.as_ref());
        stream.append(&self.value);
        stream.append(&self.data);
        stream.append(&self.chain_id);
        stream.append(&0u8); // empty r
        stream.append(&0u8); // empty s
        stream.out().to_vec()
    }

    /// RLP encode for signed transaction (with v, r, s)
    pub fn rlp_encode_signed(&self, v: u64, r: &[u8], s: &[u8]) -> Vec<u8> {
        let mut stream = RlpStream::new_list(9);
        stream.append(&self.nonce);
        stream.append(&self.gas_price);
        stream.append(&self.gas_limit);
        stream.append(&self.to.as_ref());
        stream.append(&self.value);
        stream.append(&self.data);
        stream.append(&v);
        stream.append(&r);
        stream.append(&s);
        stream.out().to_vec()
    }
}

/// Parse r, s, v from a 64-byte ECDSA signature and set v for Ethereum (EIP-155)
pub fn parse_ecdsa_signature(sig: &[u8], chain_id: u64) -> (u64, [u8; 32], [u8; 32]) {
    assert_eq!(sig.len(), 64, "Signature must be 64 bytes");
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig[0..32]);
    s.copy_from_slice(&sig[32..64]);
    // Management canister does not provide recovery id, so try v = 35 + 2 * chain_id
    let v = 35 + 2 * chain_id;
    (v, r, s)
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[derive(Debug, CandidType, Deserialize)]
pub struct SignWithEcdsaArgs {
    pub message_hash: Vec<u8>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: KeyId,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct KeyId {
    pub curve: EcdsaCurve,
    pub name: String,
}

#[derive(Debug, CandidType, Deserialize)]
pub struct SignWithEcdsaResponse {
    pub signature: Vec<u8>,
}

pub async fn sign_with_ecdsa(message_hash: Vec<u8>, derivation_path: Vec<Vec<u8>>) -> Result<Vec<u8>, String> {
    let args = SignWithEcdsaArgs {
        message_hash,
        derivation_path,
        key_id: KeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "test_key_1".to_string(),
        },
    };
    let cycles : u128 = 20_000_000_000;
    let (response,): (SignWithEcdsaResponse,) = call_with_payment128(
        Principal::management_canister(),
        "sign_with_ecdsa",
        (args,),
        cycles
    ).await.map_err(|e| format!("sign_with_ecdsa failed: {:?}", e))?;
    Ok(response.signature)
}

