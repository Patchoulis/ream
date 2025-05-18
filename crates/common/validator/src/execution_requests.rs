use alloy_primitives::{Address, Bytes, B256};
use ream_consensus::{
    consolidation_request::ConsolidationRequest, constants::{CONSOLIDATION_REQUEST_TYPE, DEPOSIT_REQUEST_TYPE, WITHDRAWAL_REQUEST_TYPE}, deposit_request::DepositRequest, execution_engine, execution_payload::PayloadAttributesV3, execution_requests::ExecutionRequests, fork_choice, withdrawal::Withdrawal, withdrawal_request::WithdrawalRequest
};
use ream_consensus::electra::beacon_state::BeaconState;
use ssz_types::VariableList;
use ssz::Decode;
use anyhow::{ Result, anyhow };
use execution_engine::ExecutionEngine;

fn get_execution_requests(execution_requests_list: Vec<Bytes>) -> Result<ExecutionRequests> {
    let mut deposits: Vec<DepositRequest> = vec![];
    let mut withdrawals: Vec<WithdrawalRequest> = vec![];
    let mut consolidations: Vec<ConsolidationRequest> = vec![];

    let mut prev_req_type: Option<u8> = None;
    for request_bytes in execution_requests_list.into_iter() {
        let request: &[u8] = request_bytes.as_ref();
        if request.len() >= 2 {
            let req_type: u8 = request[0];
            let request_data: &[u8] = &request[1..];

            if let Some(prev_type_unwrapped) = prev_req_type {
                if prev_type_unwrapped >= req_type {
                    return Err(anyhow!("Invalid request type order"));
                }
            }
            prev_req_type = Some(req_type);
            if req_type == DEPOSIT_REQUEST_TYPE[0] {
                match DepositRequest::from_ssz_bytes(request_data) {
                    Ok(deposit) => deposits.push(deposit),
                    Err(e) => return Err(anyhow!("Failed to deserialize DepositRequest: {:?}", e)),
                }
            } else if req_type == WITHDRAWAL_REQUEST_TYPE[0] {
                match WithdrawalRequest::from_ssz_bytes(request_data) {
                    Ok(withdrawal) => withdrawals.push(withdrawal),
                    Err(e) => return Err(anyhow!("Failed to deserialize WithdrawalRequest: {:?}", e)),
                }
            } else if req_type == CONSOLIDATION_REQUEST_TYPE[0] {
                match ConsolidationRequest::from_ssz_bytes(request_data) {
                    Ok(consolidation) => consolidations.push(consolidation),
                    Err(e) => return Err(anyhow!("Failed to deserialize ConsolidationRequest: {:?}", e)),
                }
            }
        } else {
            return Err(anyhow!("Invalid request length"));
        }
    }
    Ok(ExecutionRequests { deposits: VariableList::from(deposits), withdrawals: VariableList::from(withdrawals), consolidations: VariableList::from(consolidations) })
}

fn async prepare_execution_payload(state: BeaconState,
                              safe_block_hash: B256,
                              finalized_block_hash: B256,
                              suggested_fee_recipient: Address,
                              execution_engine: ExecutionEngine) -> Result<Option<B64>> {
    let parent_hash: B256 = state.latest_execution_payload_header.block_hash;
    let execution_requests_list: Vec<Withdrawal> = state.get_expected_withdrawals()?.0;
    let payload_attributes: PayloadAttributesV3 = PayloadAttributesV3 {
        timestamp: state.compute_timestamp_at_slot(state.slot),
        prev_randao: state.get_randao_mix(state.get_current_epoch()),
        suggested_fee_recipient: suggested_fee_recipient,
        withdrawals: VariableList::from(execution_requests_list),
        parent_beacon_block_root: state.latest_block_header.tree_hash_root(),
    };
    let fork_choice_state = ForkchoiceStateV1 {
        head_block_hash: parent_hash,
        safe_block_hash: safe_block_hash,
        finalized_block_hash: finalized_block_hash,
    };
    return execution_engine.engine_forkchoice_updated_v3(
        fork_choice_state,
        Some(payload_attributes)
    )
}