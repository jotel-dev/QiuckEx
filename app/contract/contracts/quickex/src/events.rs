use soroban_sdk::{contractevent, Address, BytesN, Env};

/// Current schema version for all contract events.
///
/// v1: Initial schema with non-standardised field names.
/// v2: Standardised field names (depositor, recipient, actor) and explicit versioning.
pub const EVENT_SCHEMA_VERSION: u32 = 2;

/*
MIGRATION PLAN (Schema v1 -> v2):
1. Detect version: All Schema v2 events include a `version: u32 = 2` field in the data map.
2. Field Renaming:
   - PrivacyToggledEvent: `owner` -> `account`
   - EscrowWithdrawnEvent: `owner` -> `recipient`
   - EscrowDepositedEvent: `owner` -> `depositor`
   - EscrowRefundedEvent: `owner` -> `depositor`
   - ContractPausedEvent: `admin` -> `actor`
   - ContractUpgradedEvent: `admin` -> `actor`
3. New Events:
   - PauseFlagsChanged: Triggered when granular pause flags are updated. Includes `enabled` and `disabled` bitmasks.
4. Payload Changes:
   - EphemeralKeyRegisteredEvent: Now includes `depositor: Address` to identify the funding account.
*/

#[contractevent(topics = ["TOPIC_PRIVACY", "PrivacyToggled"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyToggledEvent {
    #[topic]
    pub account: Address,

    pub enabled: bool,
    pub timestamp: u64,
    pub version: u32,
}

#[contractevent(topics = ["TOPIC_ESCROW", "EscrowWithdrawn"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowWithdrawnEvent {
    #[topic]
    pub escrow_id: BytesN<32>,

    #[topic]
    pub recipient: Address,

    pub token: Address,
    pub amount: i128,
    pub fee: i128,
    pub timestamp: u64,
    pub version: u32,
}

#[contractevent(topics = ["TOPIC_ESCROW", "EscrowDeposited"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowDepositedEvent {
    #[topic]
    pub escrow_id: BytesN<32>,

    #[topic]
    pub depositor: Address,

    pub token: Address,
    pub amount: i128,
    pub expires_at: u64,
    pub timestamp: u64,
    pub version: u32,
}

pub(crate) fn publish_privacy_toggled(env: &Env, account: Address, enabled: bool) {
    PrivacyToggledEvent {
        account,
        enabled,
        timestamp: env.ledger().timestamp(),
        version: EVENT_SCHEMA_VERSION,
    }
    .publish(env);
}

#[allow(dead_code)]
#[contractevent(topics = ["TOPIC_ADMIN", "ContractPaused"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractPausedEvent {
    #[topic]
    pub actor: Address,

    pub paused: bool,
    pub timestamp: u64,
    pub version: u32,
}

#[allow(dead_code)]
pub(crate) fn publish_contract_paused(env: &Env, actor: Address, paused: bool) {
    ContractPausedEvent {
        actor,
        paused,
        timestamp: env.ledger().timestamp(),
        version: EVENT_SCHEMA_VERSION,
    }
    .publish(env);
}

#[allow(dead_code)]
#[contractevent(topics = ["TOPIC_ADMIN", "AdminChanged"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminChangedEvent {
    #[topic]
    pub old_admin: Address,

    #[topic]
    pub new_admin: Address,

    pub timestamp: u64,
    pub version: u32,
}

#[allow(dead_code)]
pub(crate) fn publish_admin_changed(env: &Env, old_admin: Address, new_admin: Address) {
    AdminChangedEvent {
        old_admin,
        new_admin,
        timestamp: env.ledger().timestamp(),
        version: EVENT_SCHEMA_VERSION,
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_ADMIN", "ContractUpgraded"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractUpgradedEvent {
    #[topic]
    pub new_wasm_hash: BytesN<32>,

    #[topic]
    pub actor: Address,

    pub timestamp: u64,
    pub version: u32,
}

pub(crate) fn publish_contract_upgraded(env: &Env, new_wasm_hash: BytesN<32>, actor: &Address) {
    ContractUpgradedEvent {
        new_wasm_hash,
        actor: actor.clone(),
        timestamp: env.ledger().timestamp(),
        version: EVENT_SCHEMA_VERSION,
    }
    .publish(env);
}

pub(crate) fn publish_escrow_withdrawn(
    env: &Env,
    commitment: BytesN<32>,
    recipient: Address,
    token: Address,
    amount: i128,
    fee: i128,
) {
    EscrowWithdrawnEvent {
        escrow_id: commitment,
        recipient,
        token,
        amount,
        fee,
        timestamp: env.ledger().timestamp(),
        version: EVENT_SCHEMA_VERSION,
    }
    .publish(env);
}

pub(crate) fn publish_escrow_deposited(
    env: &Env,
    commitment: BytesN<32>,
    depositor: Address,
    token: Address,
    amount: i128,
    expires_at: u64,
) {
    EscrowDepositedEvent {
        escrow_id: commitment,
        depositor,
        token,
        amount,
        expires_at,
        timestamp: env.ledger().timestamp(),
        version: EVENT_SCHEMA_VERSION,
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_ESCROW", "EscrowRefunded"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowRefundedEvent {
    #[topic]
    pub escrow_id: BytesN<32>,

    #[topic]
    pub depositor: Address,

    pub token: Address,
    pub amount: i128,
    pub timestamp: u64,
    pub version: u32,
}

#[contractevent(topics = ["TOPIC_ESCROW", "EscrowDisputed"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowDisputedEvent {
    #[topic]
    pub escrow_id: BytesN<32>,

    #[topic]
    pub arbiter: Address,

    pub timestamp: u64,
    pub version: u32,
}

pub(crate) fn publish_escrow_disputed(env: &Env, commitment: BytesN<32>, arbiter: Address) {
    EscrowDisputedEvent {
        escrow_id: commitment,
        arbiter,
        timestamp: env.ledger().timestamp(),
        version: EVENT_SCHEMA_VERSION,
    }
    .publish(env);
}

pub(crate) fn publish_escrow_refunded(
    env: &Env,
    depositor: Address,
    commitment: BytesN<32>,
    token: Address,
    amount: i128,
) {
    EscrowRefundedEvent {
        escrow_id: commitment,
        depositor,
        token,
        amount,
        timestamp: env.ledger().timestamp(),
        version: EVENT_SCHEMA_VERSION,
    }
    .publish(env);
}

// ---------------------------------------------------------------------------
// Stealth address events (Privacy v2 – Issue #157)
// ---------------------------------------------------------------------------

#[contractevent(topics = ["TOPIC_STEALTH", "EphemeralKeyRegistered"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EphemeralKeyRegisteredEvent {
    /// One-time stealth address (indexed for scanning).
    #[topic]
    pub stealth_address: BytesN<32>,

    /// Sender's ephemeral public key (indexed so recipient can scan).
    #[topic]
    pub eph_pub: BytesN<32>,

    /// Account that deposited the funds.
    #[topic]
    pub depositor: Address,

    pub token: Address,
    pub amount: i128,
    pub expires_at: u64,
    pub timestamp: u64,
    pub version: u32,
}

pub(crate) fn publish_ephemeral_key_registered(
    env: &Env,
    stealth_address: BytesN<32>,
    eph_pub: BytesN<32>,
    depositor: Address,
    token: Address,
    amount: i128,
    expires_at: u64,
) {
    EphemeralKeyRegisteredEvent {
        stealth_address,
        eph_pub,
        depositor,
        token,
        amount,
        expires_at,
        timestamp: env.ledger().timestamp(),
        version: EVENT_SCHEMA_VERSION,
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_STEALTH", "StealthWithdrawn"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StealthWithdrawnEvent {
    /// One-time stealth address (indexed).
    #[topic]
    pub stealth_address: BytesN<32>,

    /// Recipient's real address – only revealed at withdrawal time.
    #[topic]
    pub recipient: Address,

    pub token: Address,
    pub amount: i128,
    pub timestamp: u64,
    pub version: u32,
}

pub(crate) fn publish_stealth_withdrawn(
    env: &Env,
    stealth_address: BytesN<32>,
    recipient: Address,
    token: Address,
    amount: i128,
) {
    StealthWithdrawnEvent {
        stealth_address,
        recipient,
        token,
        amount,
        timestamp: env.ledger().timestamp(),
        version: EVENT_SCHEMA_VERSION,
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_ADMIN", "FeeConfigChanged"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeConfigChangedEvent {
    pub fee_bps: u32,
    pub timestamp: u64,
    pub version: u32,
}

pub(crate) fn publish_fee_config_changed(env: &Env, fee_bps: u32) {
    FeeConfigChangedEvent {
        fee_bps,
        timestamp: env.ledger().timestamp(),
        version: EVENT_SCHEMA_VERSION,
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_ADMIN", "PlatformWalletChanged"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformWalletChangedEvent {
    #[topic]
    pub wallet: Address,
    pub timestamp: u64,
    pub version: u32,
}

pub(crate) fn publish_platform_wallet_changed(env: &Env, wallet: Address) {
    PlatformWalletChangedEvent {
        wallet,
        timestamp: env.ledger().timestamp(),
        version: EVENT_SCHEMA_VERSION,
    }
    .publish(env);
}

#[contractevent(topics = ["TOPIC_ADMIN", "PauseFlagsChanged"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseFlagsChangedEvent {
    #[topic]
    pub actor: Address,
    pub enabled: u64,
    pub disabled: u64,
    pub timestamp: u64,
    pub version: u32,
}

pub(crate) fn publish_pause_flags_changed(env: &Env, actor: Address, enabled: u64, disabled: u64) {
    PauseFlagsChangedEvent {
        actor,
        enabled,
        disabled,
        timestamp: env.ledger().timestamp(),
        version: EVENT_SCHEMA_VERSION,
    }
    .publish(env);
}
