use candid::{CandidType, Deserialize, Principal};
use evm_rpc_types::{
    BlockTag, RpcError, RpcService, EthSepoliaService, RpcServices, RpcConfig, GetTransactionCountArgs
};
use ic_cdk::api::call::call_with_payment128;
use ic_cdk::api::management_canister::ecdsa::{
    ecdsa_public_key, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument,
};
// use ic_cdk::{call, export_candid};
use ic_cdk_macros::{query, update};
use num_traits::{ToPrimitive};
use serde_json::Value;
use ethers_core::types::{Eip1559TransactionRequest, Signature as EthersSignature, Address, U256, NameOrAddress};
use ethers_core::utils::{keccak256, hex};

mod eth_extended_types;
use crate::eth_extended_types::{
    MultiGetTransactionCountResult, GetTransactionCountResult, MultiSendRawTransactionResult
};
mod fees;
pub mod conversions;
use crate::fees::estimate_transaction_fees;


const EVM_RPC_CANISTER_ID: &str = "7hfb6-caaaa-aaaar-qadga-cai";

async fn get_gas_price() -> Result<u64, String> {
    let params = (
        RpcService::EthSepolia(EthSepoliaService::Ankr),
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
    let services = RpcServices::EthSepolia(Some(vec![EthSepoliaService::Ankr]));
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
    let hash = keccak256(&pubkey[1..]);
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
pub async fn send_signed_transfer() -> Result<MultiSendRawTransactionResult, String> {
    // 1. Get sender address
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
    .expect("failed to get public key");

    let pubkey = &pubkey_response.public_key;

    // Ethereum address = last 20 bytes of Keccak256(pubkey[1..])
    let hash = keccak256(&pubkey[1..]);
    let eth_address = &hash[12..];
    let sender = format!("0x{}", hex::encode(eth_address));

    // Convert sender address to Address type
    let ecdsa_pub_key = pubkey_response.public_key.clone();

    let sender_address = match sender.strip_prefix("0x") {
        Some(addr) => addr,
        None => sender.as_str(),
    };
    // 2. Get nonce
    let nonce_nat = match get_nonce(&sender).await {
        Ok(nonce) => nonce,
        Err(e) => return Err(format!("Error getting nonce: {}", e)),
    };
    let nonce = nonce_nat.0.to_u64().unwrap_or(0);
    // 3. Get fee estimates (EIP-1559)
    let rpc_services = RpcServices::EthSepolia(Some(vec![EthSepoliaService::Ankr]));
    let fee_estimates = estimate_transaction_fees(9, rpc_services).await;
    let max_fee_per_gas = fee_estimates.max_fee_per_gas;
    let max_priority_fee_per_gas = fee_estimates.max_priority_fee_per_gas;
    // 4. Prepare EIP-1559 transaction fields
    let value = U256::from(10000000000000000u128); // 0.01 ETH
    let gas_limit = U256::from(60_000u64);
    let to = NameOrAddress::Address(Address::from_slice(&hex::decode("C40CCDDff12a8424e5826513aaA27d367de3E6d5").unwrap()));

    // Ensure max_fee_per_gas >= max_priority_fee_per_gas
    // let max_fee_per_gas = if max_fee_per_gas < max_priority_fee_per_gas {
    //     max_priority_fee_per_gas
    // } else {
    //     max_fee_per_gas
    // };


    let chain_id = 11155111u64;
    let tx_req = Eip1559TransactionRequest {
        from: None,
        to: Some(to),
        value: Some(value),
        data: Default::default(),
        nonce: Some(nonce.into()),
        gas: Some(gas_limit),
        max_fee_per_gas: Some(max_fee_per_gas),
        max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
        chain_id: Some(chain_id.into()),
        access_list: Default::default(),
    };

    const EIP1559_TX_ID: u8 = 2;
    let mut unsigned_tx_bytes = tx_req.rlp().to_vec();
    unsigned_tx_bytes.insert(0, EIP1559_TX_ID);

    let txhash = keccak256(&unsigned_tx_bytes);
    // 6. Sign with ECDSA 
    let sig = match sign_with_ecdsa(txhash.to_vec(), vec![]).await {
        Ok(sig) => sig,
        Err(e) => return Err(format!("Error signing: {}", e)),
    };
    let signature = EthersSignature {
        v: y_parity(&txhash, &sig, &ecdsa_pub_key),
        r: U256::from_big_endian(&sig[0..32]),
        s: U256::from_big_endian(&sig[32..64]),
    };

    // 7. Serialize signed transaction
    let mut signed_tx_bytes = tx_req.rlp_signed(&signature).to_vec();
    signed_tx_bytes.insert(0, EIP1559_TX_ID);

    let signed_raw_tx_hex = format!("0x{}", hex::encode(signed_tx_bytes));

    // 8. Send raw transaction via EVM RPC canister using eth_sendRawTransaction endpoint
    let services = RpcServices::EthSepolia(Some(vec![EthSepoliaService::Ankr]));
    let args = (services, None::<RpcConfig>, signed_raw_tx_hex.clone());
    let cycles: u128 = 6_000_000_000;
    let (result,): (MultiSendRawTransactionResult,) = call_with_payment128(
        EVM_RPC_CANISTER_ID.parse().unwrap(),
        "eth_sendRawTransaction",
        args,
        cycles,
    )
    .await
    .map_err(|e| format!("Call to eth_sendRawTransaction failed: {:?}", e)).unwrap();

    return Ok(result);
    // match result {
    //     MultiSendRawTransactionResult::Consistent(SendRawTransactionResult::Ok(SendRawTransactionStatus::Ok(Some(tx_hash)))) => format!("Transaction hash: {}", tx_hash),
    //     MultiSendRawTransactionResult::Consistent(SendRawTransactionResult::Ok(SendRawTransactionStatus::Ok(None))) => "Transaction sent, but no hash returned".to_string(),
    //     MultiSendRawTransactionResult::Consistent(SendRawTransactionResult::Ok(SendRawTransactionStatus::NonceTooLow)) => "Error: Nonce too low".to_string(),
    //     MultiSendRawTransactionResult::Consistent(SendRawTransactionResult::Ok(SendRawTransactionStatus::NonceTooHigh)) => "Error: Nonce too high".to_string(),
    //     MultiSendRawTransactionResult::Consistent(SendRawTransactionResult::Ok(SendRawTransactionStatus::InsufficientFunds)) => "Error: Insufficient funds".to_string(),
    //     MultiSendRawTransactionResult::Consistent(SendRawTransactionResult::Err(e)) => format!("Error sending transaction: {:?}", e),
    //     MultiSendRawTransactionResult::Inconsistent(_results) => format!("Inconsistent results"),
    // }
}

#[query]
pub fn get_cycle_balance() -> u64 {
    ic_cdk::api::canister_balance() as u64
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

fn y_parity(prehash: &[u8], sig: &[u8], pubkey: &[u8]) -> u64 {
    use ethers_core::k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    let orig_key = VerifyingKey::from_sec1_bytes(pubkey).expect("failed to parse the pubkey");
    let signature = Signature::try_from(sig).unwrap();
    for parity in [0u8, 1] {
        let recid = RecoveryId::try_from(parity).unwrap();
        let recovered_key = VerifyingKey::recover_from_prehash(prehash, &signature, recid)
            .expect("failed to recover key");
        if recovered_key == orig_key {
            return parity as u64;
        }
    }

    panic!(
        "failed to recover the parity bit from a signature; sig: {}, pubkey: {}",
        hex::encode(sig),
        hex::encode(pubkey)
    )
}

