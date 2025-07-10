use candid::{CandidType, Deserialize, Principal};
use evm_rpc_types::{
    BlockTag, EthSepoliaService, GetTransactionCountArgs, RpcConfig, RpcService, RpcServices,
};
use ic_cdk::api::call::call_with_payment128;
use ic_cdk::api::management_canister::ecdsa::{
    ecdsa_public_key, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument,
};
// use ic_cdk::{call, export_candid};
use ethers_core::types::{
    Address, Eip1559TransactionRequest, NameOrAddress, Signature as EthersSignature, U256,
};
use ethers_core::utils::{hex, keccak256};
use ic_cdk_macros::{query, update};
use num_traits::ToPrimitive;
use serde_json::Value;

mod eth_extended_types;
use crate::eth_extended_types::{
    GetTransactionCountResult, MultiGetTransactionCountResult, MultiSendRawTransactionResult,
    RpcError, SendRawTransactionResult, SendRawTransactionStatus,
};
pub mod conversions;
mod fees;
use crate::fees::estimate_transaction_fees;

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
            address: address
                .parse()
                .map_err(|e| format!("Invalid address: {:?}", e))?,
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
        MultiGetTransactionCountResult::Consistent(GetTransactionCountResult::Ok(nonce)) => {
            Ok(nonce)
        }
        MultiGetTransactionCountResult::Consistent(GetTransactionCountResult::Err(err)) => {
            ic_cdk::trap(&format!("error in `request` with cycles: {:?}", err))
        }
        MultiGetTransactionCountResult::Inconsistent(_results) => {
            ic_cdk::trap(&format!("error in `request`"))
        }
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

    format!(
        "Address: {}\nNonce: {}\nGas price: {} wei",
        addr, nonce, gas_price
    )
}

#[update]
pub async fn send_signed_transfer() -> Result<String, String> {
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

    // 2. Get nonce
    let nonce_nat = match get_nonce(&sender).await {
        Ok(nonce) => nonce,
        Err(e) => return Err(format!("Error getting nonce: {}", e)),
    };
    let nonce = nonce_nat.0.to_u64().unwrap_or(0);
    // 3. Get fee estimates (EIP-1559)
    let rpc_services = RpcServices::EthSepolia(Some(vec![EthSepoliaService::PublicNode]));
    let fee_estimates = estimate_transaction_fees(9, rpc_services).await;
    let max_fee_per_gas = fee_estimates.max_fee_per_gas;
    let max_priority_fee_per_gas = fee_estimates.max_priority_fee_per_gas;
    // 4. Prepare EIP-1559 transaction fields
    let value = U256::from(10000000000000000u128); // 0.01 ETH
    let gas_limit = U256::from(60_000u64);
    // Use a plain hex string for the recipient address
    let to = Some("0xC40CCDDff12a8424e5826513aaA27d367de3E6d5".to_string());

    let chain_id = 11155111u64;
    // For RLP encoding (local only)
    let rlp_tx_req = Eip1559TransactionRequest {
        from: None,
        to: to.clone().map(|s| {
            NameOrAddress::from(Address::from_slice(
                &hex::decode(&s.trim_start_matches("0x")).unwrap(),
            ))
        }),
        value: Some(value),
        data: Default::default(),
        nonce: Some(nonce.into()),
        gas: Some(gas_limit),
        max_fee_per_gas: Some(max_fee_per_gas),
        max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
        chain_id: Some(chain_id.into()),
        access_list: Default::default(),
    };
    // RLP encoding helpers
    fn rlp_encode_bytes(bytes: &[u8]) -> Vec<u8> {
        if bytes.is_empty() {
            vec![0x80] // RLP for empty string
        } else if bytes.len() == 1 && bytes[0] < 0x80 {
            bytes.to_vec()
        } else if bytes.len() < 56 {
            let mut out = vec![0x80 + bytes.len() as u8];
            out.extend_from_slice(bytes);
            out
        } else {
            let len_bytes = int_to_be_bytes(bytes.len());
            let mut out = vec![0xb7 + len_bytes.len() as u8];
            out.extend_from_slice(&len_bytes);
            out.extend_from_slice(bytes);
            out
        }
    }

    // Helper to strip leading zeros
    fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
        let first_nonzero = bytes.iter().position(|&b| b != 0);
        match first_nonzero {
            Some(idx) => &bytes[idx..],
            None => &[],
        }
    }

    fn rlp_encode_uint(u: &U256) -> Vec<u8> {
        let mut bytes = [0u8; 32];
        u.to_big_endian(&mut bytes);
        let stripped = strip_leading_zeros(&bytes);
        if stripped.is_empty() {
            vec![0x80] // RLP for zero
        } else {
            rlp_encode_bytes(stripped)
        }
    }

    fn rlp_encode_nat(n: &candid::Nat) -> Vec<u8> {
        let bytes = n.0.to_bytes_be();
        let stripped = strip_leading_zeros(&bytes);
        if stripped.is_empty() {
            vec![0x80] // RLP for zero
        } else {
            rlp_encode_bytes(stripped)
        }
    }

    fn rlp_encode_list(list: Vec<Vec<u8>>) -> Vec<u8> {
        let payload: Vec<u8> = list.into_iter().flatten().collect();
        if payload.len() < 56 {
            let mut out = vec![0xc0 + payload.len() as u8];
            out.extend_from_slice(&payload);
            out
        } else {
            let len_bytes = int_to_be_bytes(payload.len());
            let mut out = vec![0xf7 + len_bytes.len() as u8];
            out.extend_from_slice(&len_bytes);
            out.extend_from_slice(&payload);
            out
        }
    }

    fn int_to_be_bytes(n: usize) -> Vec<u8> {
        let mut bytes = vec![];
        let mut n = n;
        while n > 0 {
            bytes.insert(0, (n & 0xff) as u8);
            n >>= 8;
        }
        if bytes.is_empty() {
            bytes.push(0);
        }
        bytes
    }

    // EIP-1559 RLP encoding 
    fn rlp_encode_eip1559_tx(tx: &Eip1559TransactionRequest) -> Vec<u8> {
        let mut fields = vec![
            rlp_encode_nat(&candid::Nat::from(tx.chain_id.unwrap_or_default().as_u64())),
            rlp_encode_nat(&candid::Nat::from(tx.nonce.unwrap_or_default().as_u128())),
            rlp_encode_nat(&candid::Nat::from(
                tx.max_priority_fee_per_gas.unwrap_or_default().as_u128(),
            )),
            rlp_encode_nat(&candid::Nat::from(
                tx.max_fee_per_gas.unwrap_or_default().as_u128(),
            )),
            rlp_encode_nat(&candid::Nat::from(tx.gas.unwrap_or_default().as_u128())),
        ];
        // To
        if let Some(NameOrAddress::Address(addr)) = &tx.to {
            fields.push(rlp_encode_bytes(&addr.0));
        } else {
            fields.push(rlp_encode_bytes(&[]));
        }
        // Value
        fields.push(rlp_encode_nat(&candid::Nat::from(
            tx.value.unwrap_or_default().as_u128(),
        )));
        // Data
        fields.push(rlp_encode_bytes(tx.data.as_deref().unwrap_or(&[])));
        // Access List (empty for now)
        fields.push(rlp_encode_list(vec![]));
        rlp_encode_list(fields)
    }

    fn rlp_encode_eip1559_signed_tx(
        tx: &Eip1559TransactionRequest,
        sig: &EthersSignature,
    ) -> Vec<u8> {
        let mut fields = vec![
            rlp_encode_nat(&candid::Nat::from(tx.chain_id.unwrap_or_default().as_u64())),
            rlp_encode_nat(&candid::Nat::from(tx.nonce.unwrap_or_default().as_u128())),
            rlp_encode_nat(&candid::Nat::from(
                tx.max_priority_fee_per_gas.unwrap_or_default().as_u128(),
            )),
            rlp_encode_nat(&candid::Nat::from(
                tx.max_fee_per_gas.unwrap_or_default().as_u128(),
            )),
            rlp_encode_nat(&candid::Nat::from(tx.gas.unwrap_or_default().as_u128())),
        ];
        // To
        if let Some(NameOrAddress::Address(addr)) = &tx.to {
            fields.push(rlp_encode_bytes(&addr.0));
        } else {
            fields.push(rlp_encode_bytes(&[]));
        }
        // Value
        fields.push(rlp_encode_nat(&candid::Nat::from(
            tx.value.unwrap_or_default().as_u128(),
        )));
        // Data
        fields.push(rlp_encode_bytes(tx.data.as_deref().unwrap_or(&[])));
        // Access List (empty for now)
        fields.push(rlp_encode_list(vec![]));
        // Signature fields
        let mut sig_fields = vec![
            rlp_encode_nat(&candid::Nat::from(sig.v)),
            rlp_encode_uint(&sig.r),
            rlp_encode_uint(&sig.s),
        ];
        fields.append(&mut sig_fields);
        rlp_encode_list(fields)
    }

    fn rpc_error_to_string(err: &RpcError) -> String {
        match err {
            RpcError::ProviderError(e) => format!("ProviderError: {}", e),
            RpcError::HttpOutcallError(e) => format!("HttpOutcallError: {}", e),
            RpcError::JsonRpcError(e) => {
                format!("JSON-RPC Error (code: {}): {}", e.code, e.message)
            }
            RpcError::ValidationError(e) => format!("Validation error: {}", e),
        }
    }

    // Commented out ethers_core RLP encoding:
    // let mut unsigned_tx_bytes = tx_req.rlp().to_vec();
    let mut unsigned_tx_bytes = rlp_encode_eip1559_tx(&rlp_tx_req);

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

    // Commented out ethers_core RLP encoding for signed tx:
    // let mut signed_tx_bytes = tx_req.rlp_signed(&signature).to_vec();
    let signed_tx_bytes = rlp_encode_eip1559_signed_tx(&rlp_tx_req, &signature);

    // Insert EIP-1559 transaction type byte (0x02) at the start
    let mut tx_bytes_with_type = vec![0x02];
    tx_bytes_with_type.extend_from_slice(&signed_tx_bytes);
    let signed_raw_tx_hex = format!("0x{}", hex::encode(tx_bytes_with_type));

    // 8. Send raw transaction via EVM RPC canister using eth_sendRawTransaction endpoint
    let services = RpcServices::EthSepolia(Some(vec![EthSepoliaService::PublicNode]));
    let args = (services, None::<RpcConfig>, signed_raw_tx_hex.clone());
    let cycles: u128 = 6_000_000_000;
    let (result,): (MultiSendRawTransactionResult,) = call_with_payment128(
        EVM_RPC_CANISTER_ID.parse().unwrap(),
        "eth_sendRawTransaction",
        args,
        cycles,
    )
    .await
    .map_err(|e| format!("Call failed: {:?}", e))?;

    // 9. Handle the result
    match result {
        MultiSendRawTransactionResult::Consistent(inner) => match inner {
            SendRawTransactionResult::Ok(status) => match status {
                SendRawTransactionStatus::Ok(Some(tx_hash)) => {
                    Ok(format!("Transaction sent. Hash: {}", tx_hash))
                }
                SendRawTransactionStatus::Ok(None) => {
                    Ok("Transaction sent, but no hash returned.".to_string())
                }
                SendRawTransactionStatus::NonceTooLow => Err("Nonce too low.".to_string()),
                SendRawTransactionStatus::NonceTooHigh => Err("Nonce too high.".to_string()),
                SendRawTransactionStatus::InsufficientFunds => {
                    Err("Insufficient funds.".to_string())
                }
            },
            SendRawTransactionResult::Err(e) => {
                Err(format!("RPC Error: {}", rpc_error_to_string(&e)))
            }
        },
        MultiSendRawTransactionResult::Inconsistent(results) => {
            let messages = results
                .iter()
                .map(|(_, res)| {
                    let msg = match res {
                        SendRawTransactionResult::Ok(status) => match status {
                            SendRawTransactionStatus::Ok(Some(tx_hash)) => {
                                format!("Hash: {}", tx_hash)
                            }
                            SendRawTransactionStatus::Ok(None) => "No hash returned.".to_string(),
                            SendRawTransactionStatus::NonceTooLow => "Nonce too low.".to_string(),
                            SendRawTransactionStatus::NonceTooHigh => "Nonce too high.".to_string(),
                            SendRawTransactionStatus::InsufficientFunds => {
                                "Insufficient funds.".to_string()
                            }
                        },
                        SendRawTransactionResult::Err(e) => rpc_error_to_string(e),
                    };
                    format!("{}", msg)
                })
                .collect::<Vec<_>>()
                .join("\n");
            Err(format!("Inconsistent results:\n{}", messages))
        }
    }
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

pub async fn sign_with_ecdsa(
    message_hash: Vec<u8>,
    derivation_path: Vec<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    let args = SignWithEcdsaArgs {
        message_hash,
        derivation_path,
        key_id: KeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "test_key_1".to_string(),
        },
    };
    let cycles: u128 = 20_000_000_000;
    let (response,): (SignWithEcdsaResponse,) = call_with_payment128(
        Principal::management_canister(),
        "sign_with_ecdsa",
        (args,),
        cycles,
    )
    .await
    .map_err(|e| format!("sign_with_ecdsa failed: {:?}", e))?;
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
