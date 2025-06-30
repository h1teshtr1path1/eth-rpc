//! This module provides functions for estimating transaction fees and getting the fee history.
use candid::Nat;
use ethers_core::types::U256;
use evm_rpc_types::{
    BlockTag, RpcError, RpcService, RpcServices, RpcConfig,
};
use ic_cdk::api::call::call_with_payment128;
use serde_bytes::ByteBuf;
use std::ops::Add;

use crate::conversions::nat_to_u256;
use candid::{self, CandidType, Deserialize, Principal};

/// The minimum suggested maximum priority fee per gas.
const MIN_SUGGEST_MAX_PRIORITY_FEE_PER_GAS: u32 = 1_500_000_000;
const EVM_RPC_CANISTER_ID: &str = "7hfb6-caaaa-aaaar-qadga-cai";

#[derive(CandidType, Deserialize)]
pub struct FeeHistoryArgs {
  pub blockCount: candid::Nat,
  pub newestBlock: BlockTag,
  pub rewardPercentiles: Option<serde_bytes::ByteBuf>,
}

#[derive(CandidType, Deserialize)]
pub struct FeeHistory {
  pub reward: Vec<Vec<candid::Nat>>,
  pub gasUsedRatio: Vec<f64>,
  pub oldestBlock: candid::Nat,
  pub baseFeePerGas: Vec<candid::Nat>,
}

#[derive(CandidType, Deserialize)]
pub enum FeeHistoryResult { Ok(FeeHistory), Err(RpcError) }

#[derive(CandidType, Deserialize)]
pub enum MultiFeeHistoryResult {
  Consistent(FeeHistoryResult),
  Inconsistent(Vec<(RpcService,FeeHistoryResult,)>),
}

/// Calls the EVM RPC canister directly to get fee history.
pub async fn fee_history(
    block_count: Nat,
    newest_block: BlockTag,
    reward_percentiles: Option<Vec<u8>>,
    rpc_services: RpcServices,
) -> FeeHistory {
    let fee_history_args = FeeHistoryArgs {
        blockCount: block_count,
        newestBlock: newest_block,
        rewardPercentiles: reward_percentiles.map(ByteBuf::from),
    };
    let cycles = 10_000_000_000u128;
    let evm_rpc_canister_id = EVM_RPC_CANISTER_ID.parse::<Principal>().unwrap();
    let args = (
        rpc_services,
        None::<RpcConfig>,
        fee_history_args,
    );
    let (res,): (MultiFeeHistoryResult,) = call_with_payment128(
        evm_rpc_canister_id,
        "eth_feeHistory",
        args,
        cycles,
    )
    .await
    .unwrap();
    match res {
        MultiFeeHistoryResult::Consistent(fee_history) => match fee_history {
            FeeHistoryResult::Ok(fee_history) => fee_history,
            FeeHistoryResult::Err(e) => {
                ic_cdk::trap(format!("Error: {:?}", e).as_str());
            }
        },
        MultiFeeHistoryResult::Inconsistent(_) => {
            ic_cdk::trap("Fee history is inconsistent");
        }
    }
}

/// Represents the fee estimates.
pub struct FeeEstimates {
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
}

/// Gets the median index.
///
/// # Arguments
///
/// * `length` - The length of the array.
///
/// # Returns
///
/// The median index.
fn median_index(length: usize) -> usize {
    if length == 0 {
        panic!("Cannot find a median index for an array of length zero.");
    }
    (length - 1) / 2
}

/// Estimates the transaction fees.
///
/// # Arguments
///
/// * `block_count` - The number of historical blocks to base the fee estimates on.
/// * `rpc_services` - The RPC services used to interact with the EVM.
/// * `evm_rpc` - The EVM RPC canister.
pub async fn estimate_transaction_fees(
    block_count: u8,
    rpc_services: RpcServices,
) -> FeeEstimates {
    // we are setting the `max_priority_fee_per_gas` based on this article:
    // https://docs.alchemy.com/docs/maxpriorityfeepergas-vs-maxfeepergas
    // following this logic, the base fee will be derived from the block history automatically
    // and we only specify the maximum priority fee per gas (tip).
    // the tip is derived from the fee history of the last 9 blocks, more specifically
    // from the 95th percentile of the tip.
    let fee_history = fee_history(
        Nat::from(block_count),
        BlockTag::Latest,
        Some(vec![95]),
        rpc_services,
    )
    .await;

    let median_index = median_index(block_count.into());

    // baseFeePerGas
    let base_fee_per_gas = fee_history.baseFeePerGas.last().unwrap().clone();

    // obtain the 95th percentile of the tips for the past 9 blocks
    let mut percentile_95: Vec<Nat> = fee_history
        .reward
        .into_iter()
        .flat_map(|x| x.into_iter())
        .collect();
    // sort the tips in ascending order
    percentile_95.sort_unstable();
    // get the median by accessing the element in the middle
    // set tip to 0 if there are not enough blocks in case of a local testnet
    let median_reward = percentile_95
        .get(median_index)
        .unwrap_or(&Nat::from(0_u8))
        .clone();

    let max_priority_fee_per_gas = median_reward
        .clone()
        .add(base_fee_per_gas)
        .max(Nat::from(MIN_SUGGEST_MAX_PRIORITY_FEE_PER_GAS));

    FeeEstimates {
        max_fee_per_gas: nat_to_u256(&max_priority_fee_per_gas),
        max_priority_fee_per_gas: nat_to_u256(&median_reward),
    }
}