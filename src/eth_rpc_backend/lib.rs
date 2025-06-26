use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use evm_rpc_types::{
    Block, BlockTag, EthMainnetService, Hex32, MultiRpcResult, ProviderError, RpcError, RpcService, EthSepoliaService, RpcServices
};
use hex;
use ic_cdk::api::call::call_with_payment128;
use ic_cdk::api::management_canister::ecdsa::{
    ecdsa_public_key, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument,
};
use ic_cdk::{call, export_candid};
use ic_cdk_macros::{query, update};
use serde_json::Value;
use sha3::{Digest, Keccak256};

// Manually implement Debug for RpcError if not available
struct RpcErrorWrapper(pub RpcError);

impl std::fmt::Debug for RpcErrorWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RpcError (Debug not implemented, displaying as opaque)")
    }
}

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
async fn send_transfer_transaction() -> String {
    let addr = match get_eth_address().await {
        Ok(addr) => addr,
        Err(e) => return format!("Error getting ETH address: {}", e),
    };

    // let nonce = match get_nonce(addr.clone()).await {
    //     Ok(nonce) => nonce,
    //     Err(e) => return format!("Error getting nonce: {}", e),
    // };

    let gas_price = match get_gas_price().await {
        Ok(gas_price) => gas_price,
        Err(e) => return format!("Error getting gas price: {}", e),
    };
    format!("Address: {}\nGas price: {} wei", addr, gas_price)
}

export_candid!();

