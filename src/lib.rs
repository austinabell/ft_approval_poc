use near_contract_standards::fungible_token::metadata::{
    FungibleTokenMetadata, FungibleTokenMetadataProvider, FT_METADATA_SPEC,
};
use near_contract_standards::fungible_token::receiver::ext_ft_receiver;
use near_contract_standards::fungible_token::FungibleToken;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LazyOption, LookupMap};
use near_sdk::json_types::U128;
use near_sdk::{
    env, log, near_bindgen, require, AccountId, Balance, BorshStorageKey, Gas, PanicOnDefault,
    Promise, PromiseOrValue, PublicKey,
};
use serde::{Deserialize, Serialize};

const ERR_ATOMIC_UPDATE: &str = "Invalid current approval value. Failed to do atomic update";

// TODO
#[derive(Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
#[serde(tag = "type", content = "value")]
pub enum AccountIdOrKey {
    Account(AccountId),
    Key(PublicKey),
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct Contract {
    token: FungibleToken,
    metadata: LazyOption<FungibleTokenMetadata>,

    /// Approval standard state
    approvals: LookupMap<(AccountId, AccountIdOrKey), Balance>,
}

const DATA_IMAGE_SVG_NEAR_ICON: &str = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 288 288'%3E%3Cg id='l' data-name='l'%3E%3Cpath d='M187.58,79.81l-30.1,44.69a3.2,3.2,0,0,0,4.75,4.2L191.86,103a1.2,1.2,0,0,1,2,.91v80.46a1.2,1.2,0,0,1-2.12.77L102.18,77.93A15.35,15.35,0,0,0,90.47,72.5H87.34A15.34,15.34,0,0,0,72,87.84V201.16A15.34,15.34,0,0,0,87.34,216.5h0a15.35,15.35,0,0,0,13.08-7.31l30.1-44.69a3.2,3.2,0,0,0-4.75-4.2L96.14,186a1.2,1.2,0,0,1-2-.91V104.61a1.2,1.2,0,0,1,2.12-.77l89.55,107.23a15.35,15.35,0,0,0,11.71,5.43h3.13A15.34,15.34,0,0,0,216,201.16V87.84A15.34,15.34,0,0,0,200.66,72.5h0A15.35,15.35,0,0,0,187.58,79.81Z'/%3E%3C/g%3E%3C/svg%3E";

#[derive(BorshSerialize, BorshStorageKey)]
enum StorageKey {
    FungibleToken,
    Metadata,
    Approval,
}

#[near_bindgen]
impl Contract {
    /// Initializes the contract with the given total supply owned by the given `owner_id` with
    /// default metadata (for example purposes only).
    #[init]
    pub fn new_default_meta(owner_id: AccountId, total_supply: U128) -> Self {
        Self::new(
            owner_id,
            total_supply,
            FungibleTokenMetadata {
                spec: FT_METADATA_SPEC.to_string(),
                name: "Example NEAR fungible token".to_string(),
                symbol: "EXAMPLE".to_string(),
                icon: Some(DATA_IMAGE_SVG_NEAR_ICON.to_string()),
                reference: None,
                reference_hash: None,
                decimals: 24,
            },
        )
    }

    /// Initializes the contract with the given total supply owned by the given `owner_id` with
    /// the given fungible token metadata.
    #[init]
    pub fn new(owner_id: AccountId, total_supply: U128, metadata: FungibleTokenMetadata) -> Self {
        require!(!env::state_exists(), "Already initialized");
        metadata.assert_valid();
        let mut this = Self {
            token: FungibleToken::new(StorageKey::FungibleToken),
            metadata: LazyOption::new(StorageKey::Metadata, Some(&metadata)),
            approvals: LookupMap::new(StorageKey::Approval),
        };
        this.token.internal_register_account(&owner_id);
        this.token.internal_deposit(&owner_id, total_supply.into());
        this
    }

    fn on_account_closed(&mut self, account_id: AccountId, balance: Balance) {
        log!("Closed @{} with {}", account_id, balance);
    }

    fn on_tokens_burned(&mut self, account_id: AccountId, amount: Balance) {
        log!("Account @{} burned {}", account_id, amount);
    }

    // ---- Approval standard -----

    /// Approve the passed address to spend the specified amount of tokens on behalf of
    /// `env::predecessor_account_id`.
    ///
    /// Arguments:
    /// * `spender` The address which will spend the funds.
    /// * `current_value` The amount of tokens currently allowed. This is used to ensure atomicity.
    /// * `value` The amount of tokens to be spent.
    #[payable]
    pub fn ft_approve(&mut self, spender: AccountIdOrKey, current_value: U128, value: U128) {
        let attached_deposit = env::attached_deposit();
        // Assert that there is a deposit for the transaction for security.
        // This deposit is used for access key allowance if approving using a key.
        require!(attached_deposit >= 1);

        let predecessor = env::predecessor_account_id();
        match &spender {
            AccountIdOrKey::Account(a) => {
                // Ensure that the approval is not given to the same account as the owner.
                require!(a != &predecessor);
            }
            AccountIdOrKey::Key(k) => {
                let current_account = env::current_account_id();
                // TODO this can be optimized by avoiding Promise API.
                Promise::new(current_account.clone()).add_access_key(
                    k.clone(),
                    attached_deposit,
                    current_account,
                    "ft_transfer_from_key,ft_transfer_call_from_key".to_string(),
                );
            }
        }

        let lookup = (predecessor, spender);
        let prev = self.approvals.get(&lookup);

        // Compare previous value before updating.
        require!(
            prev.unwrap_or_default() == current_value.0,
            ERR_ATOMIC_UPDATE
        );

        // Update allowance to new value.
        self.approvals.insert(&lookup, &value.0);

        // TODO remove temp log
        log!("Approved {:?} for {}", lookup.1, lookup.0);
        // TODO emit approval event
    }

    // // TODO docs
    // pub fn ft_approve_key(
    //     &mut self,
    //     key: PublicKey,
    //     allowance: U128,
    //     current_value: U128,
    //     value: U128,
    // ) {
    // }

    // TODO see if a way to avoid requiring multiple fns
    // TODO docs
    pub fn ft_transfer_from_account(
        &mut self,
        from: AccountId,
        to: AccountId,
        amount: U128,
        memo: Option<String>,
    ) {
        self.ft_transfer_from(
            AccountIdOrKey::Account(env::predecessor_account_id()),
            from,
            to,
            amount,
            memo,
        )
    }

    // TODO docs
    pub fn ft_transfer_from_key(
        &mut self,
        from: AccountId,
        to: AccountId,
        amount: U128,
        memo: Option<String>,
    ) {
        self.ft_transfer_from(
            AccountIdOrKey::Key(env::signer_account_pk()),
            from,
            to,
            amount,
            memo,
        )
    }

    // TODO docs
    pub fn ft_transfer_call_from_account(
        &mut self,
        from: AccountId,
        to: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128> {
        self.ft_transfer_call_from(
            AccountIdOrKey::Account(env::predecessor_account_id()),
            from,
            to,
            amount,
            memo,
            msg,
        )
    }

    // TODO docs
    pub fn ft_transfer_call_from_key(
        &mut self,
        from: AccountId,
        to: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128> {
        self.ft_transfer_call_from(
            AccountIdOrKey::Key(env::signer_account_pk()),
            from,
            to,
            amount,
            memo,
            msg,
        )
    }

    #[private]
    // TODO docs
    /// Callback function for `ft_transfer_call_from`.
    pub fn ft_resolve_transfer_from(
        &mut self,
        spender: AccountIdOrKey,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
    ) -> U128 {
        let (used_amount, burned_amount) =
            self.token
                .internal_ft_resolve_transfer(&sender_id, receiver_id, amount);

        let lookup = (sender_id, spender);
        let approval_amount = self.approvals.get(&lookup).unwrap_or_default();
        // This recalculation is redundant, since we have it in internal_ft_resolve_transfer.
        let unused_amount = amount
            .0
            .checked_sub(used_amount)
            .expect("used gas amount more than total");

        // Doing saturating add to avoid being able to manually trigger overflow on resolve
        // by increasing allowance and having a refund which sum to > u128::MAX.
        let approval_amount = approval_amount.saturating_add(unused_amount);

        // TODO actually, do we want this at all? What about the case where the approval amount
        // TODO is updated before the resolve transfer finalizes?
        // Increase approval amount by the unused amount.
        // TODO we probably want to remove if 0 rather than updating to 0
        self.approvals.insert(&lookup, &approval_amount);

        if burned_amount > 0 {
            self.on_tokens_burned(lookup.0, burned_amount);
            // TODO do we actually want to keep the allowance when we notice a deleted account/burn?
            // Option 1: we keep the allowance
            // Option 2: We remove only the allowance from the key/account we are resolving
            // Option 3: Use nested maps to clear all allowances when a delete is noticed (seems like this is bad incentives)
        }

        U128(used_amount)
    }

    // TODO docs
    pub fn ft_allowance(&self, owner: AccountId, spender: AccountIdOrKey) -> U128 {
        U128(self.approvals.get(&(owner, spender)).unwrap_or_default())
    }

    fn ft_transfer_from(
        &mut self,
        spender: AccountIdOrKey,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
    ) {
        // Check to ensure sufficient allowance and update with subtracted value.
        let lookup = (sender_id.clone(), spender);
        let allowed_amount = self.approvals.get(&lookup).unwrap();
        let new_allowance = allowed_amount
            .checked_sub(amount.0)
            .unwrap_or_else(|| env::panic_str("insufficient allownance for transfer"));
        self.approvals.insert(&lookup, &new_allowance);

        // Perform token transfer.
        self.token
            .internal_transfer(&sender_id, &receiver_id, amount.0, memo);
    }

    fn ft_transfer_call_from(
        &mut self,
        spender: AccountIdOrKey,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128> {
        const GAS_FOR_RESOLVE_TRANSFER: Gas = Gas(5_000_000_000_000);
        // TODO Could be a better estimation to avoid using unnecessary gas.
        require!(
            env::prepaid_gas() > GAS_FOR_RESOLVE_TRANSFER,
            "More gas is required"
        );

        let lookup = (sender_id, spender);
        let allowed_amount = self.approvals.get(&lookup).unwrap();
        let new_allowance = allowed_amount
            .checked_sub(amount.0)
            .unwrap_or_else(|| env::panic_str("insufficient allownance for transfer"));
        self.approvals.insert(&lookup, &new_allowance);
        let (sender_id, spender) = lookup;

        let amount: Balance = amount.0;
        self.token
            .internal_transfer(&sender_id, &receiver_id, amount, memo);

        // Initiating receiver's call and the callback
        ext_ft_receiver::ext(receiver_id.clone())
            // TODO decide what weight of gas makes sense
            .with_unused_gas_weight(2)
            .ft_on_transfer(sender_id.clone(), amount.into(), msg)
            .then(
                Self::ext(env::current_account_id())
                    // TODO figure out reasonable static gas to ensure callback succeeds
                    .with_static_gas(GAS_FOR_RESOLVE_TRANSFER)
                    .ft_resolve_transfer_from(spender, sender_id, receiver_id, amount.into()),
            )
            .into()
    }
}

near_contract_standards::impl_fungible_token_core!(Contract, token, on_tokens_burned);
near_contract_standards::impl_fungible_token_storage!(Contract, token, on_account_closed);

#[near_bindgen]
impl FungibleTokenMetadataProvider for Contract {
    fn ft_metadata(&self) -> FungibleTokenMetadata {
        self.metadata.get().unwrap()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::{testing_env, Balance};

    const TOTAL_SUPPLY: Balance = 1_000_000_000_000_000;

    fn get_context(predecessor_account_id: AccountId) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder
            .current_account_id(accounts(0))
            .signer_account_id(predecessor_account_id.clone())
            .predecessor_account_id(predecessor_account_id);
        builder
    }

    #[test]
    fn test_new() {
        let mut context = get_context(accounts(1));
        testing_env!(context.build());
        let contract = Contract::new_default_meta(accounts(1).into(), TOTAL_SUPPLY.into());
        testing_env!(context.is_view(true).build());
        assert_eq!(contract.ft_total_supply().0, TOTAL_SUPPLY);
        assert_eq!(contract.ft_balance_of(accounts(1)).0, TOTAL_SUPPLY);
    }

    #[test]
    #[should_panic(expected = "The contract is not initialized")]
    fn test_default() {
        let context = get_context(accounts(1));
        testing_env!(context.build());
        let _contract = Contract::default();
    }

    #[test]
    fn test_transfer() {
        let mut context = get_context(accounts(2));
        testing_env!(context.build());
        let mut contract = Contract::new_default_meta(accounts(2).into(), TOTAL_SUPPLY.into());
        testing_env!(context
            .storage_usage(env::storage_usage())
            .attached_deposit(contract.storage_balance_bounds().min.into())
            .predecessor_account_id(accounts(1))
            .build());
        // Paying for account registration, aka storage deposit
        contract.storage_deposit(None, None);

        testing_env!(context
            .storage_usage(env::storage_usage())
            .attached_deposit(1)
            .predecessor_account_id(accounts(2))
            .build());
        let transfer_amount = TOTAL_SUPPLY / 3;
        contract.ft_transfer(accounts(1), transfer_amount.into(), None);

        testing_env!(context
            .storage_usage(env::storage_usage())
            .account_balance(env::account_balance())
            .is_view(true)
            .attached_deposit(0)
            .build());
        assert_eq!(
            contract.ft_balance_of(accounts(2)).0,
            (TOTAL_SUPPLY - transfer_amount)
        );
        assert_eq!(contract.ft_balance_of(accounts(1)).0, transfer_amount);
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod ws_tests {
    use std::future::IntoFuture;

    use super::AccountIdOrKey;
    use near_sdk::json_types::U128;
    use near_sdk::ONE_YOCTO;
    use near_units::parse_near;
    use workspaces::operations::Function;
    use workspaces::result::ValueOrReceiptId;
    use workspaces::types::{KeyType, SecretKey};
    use workspaces::{Account, AccountId, Contract, DevNetwork, Worker};

    async fn register_user(contract: &Contract, account_id: &AccountId) -> anyhow::Result<()> {
        let res = contract
            .call("storage_deposit")
            .args_json((account_id, Option::<bool>::None))
            .max_gas()
            .deposit(near_sdk::env::storage_byte_cost() * 125)
            .transact()
            .await?;
        assert!(res.is_success());

        Ok(())
    }

    async fn create_and_register_user(
        contract: &Contract,
        worker: &Worker<impl DevNetwork>,
    ) -> anyhow::Result<Account> {
        let account = worker.dev_create_account().await?;
        register_user(contract, account.id()).await?;
        Ok(account)
    }

    async fn init(
        worker: &Worker<impl DevNetwork>,
        initial_balance: U128,
    ) -> anyhow::Result<Contract> {
        let ft_contract = worker
            .dev_deploy(&workspaces::compile_project("./").await?)
            .await?;

        let res = ft_contract
            .call("new_default_meta")
            .args_json((ft_contract.id(), initial_balance))
            .max_gas()
            .transact()
            .await?;
        assert!(res.is_success());

        return Ok(ft_contract);
    }

    async fn init_defi_contract(
        worker: &Worker<impl DevNetwork>,
        ft_id: &AccountId,
    ) -> anyhow::Result<Contract> {
        let contract = worker
            .dev_deploy(&workspaces::compile_project("./test-contract-defi").await?)
            .await?;

        let res = contract
            .call("new")
            .args_json((ft_id,))
            .max_gas()
            .transact()
            .await?;
        assert!(res.is_success());
        Ok(contract)
    }

    #[tokio::test]
    async fn test_total_supply() -> anyhow::Result<()> {
        let initial_balance = U128(10000);
        let worker = workspaces::sandbox().await?;
        let contract = init(&worker, initial_balance).await?;

        let res = contract.call("ft_total_supply").view().await?;
        assert_eq!(res.json::<U128>()?, initial_balance);

        Ok(())
    }

    #[tokio::test]
    async fn test_simple_transfer() -> anyhow::Result<()> {
        let initial_balance = U128(10000);
        let transfer_amount = U128(100);
        let worker = workspaces::sandbox().await?;
        let contract = init(&worker, initial_balance).await?;
        let alice = create_and_register_user(&contract, &worker).await?;

        let res = contract
            .call("ft_transfer")
            .args_json((alice.id(), transfer_amount, Option::<bool>::None))
            .max_gas()
            .deposit(ONE_YOCTO)
            .transact()
            .await?;
        assert!(res.is_success());

        let root_balance = contract
            .call("ft_balance_of")
            .args_json((contract.id(),))
            .view()
            .await?
            .json::<U128>()?;
        let alice_balance = contract
            .call("ft_balance_of")
            .args_json((alice.id(),))
            .view()
            .await?
            .json::<U128>()?;
        assert_eq!(initial_balance.0 - transfer_amount.0, root_balance.0);
        assert_eq!(transfer_amount.0, alice_balance.0);

        Ok(())
    }

    #[tokio::test]
    async fn test_close_account_empty_balance() -> anyhow::Result<()> {
        let initial_balance = U128(10000);
        let worker = workspaces::sandbox().await?;
        let contract = init(&worker, initial_balance).await?;
        let alice = create_and_register_user(&contract, &worker).await?;

        let res = alice
            .call(contract.id(), "storage_unregister")
            .args_json((Option::<bool>::None,))
            .max_gas()
            .deposit(ONE_YOCTO)
            .transact()
            .await?;
        assert!(res.json::<bool>()?);

        Ok(())
    }

    #[tokio::test]
    async fn test_close_account_non_empty_balance() -> anyhow::Result<()> {
        let initial_balance = U128(10000);
        let worker = workspaces::sandbox().await?;
        let contract = init(&worker, initial_balance).await?;

        let res = contract
            .call("storage_unregister")
            .args_json((Option::<bool>::None,))
            .max_gas()
            .deposit(ONE_YOCTO)
            .transact()
            .await;
        assert!(format!("{:?}", res)
            .contains("Can't unregister the account with the positive balance without force"));

        let res = contract
            .call("storage_unregister")
            .args_json((Some(false),))
            .max_gas()
            .deposit(ONE_YOCTO)
            .transact()
            .await;
        assert!(format!("{:?}", res)
            .contains("Can't unregister the account with the positive balance without force"));

        Ok(())
    }

    #[tokio::test]
    async fn test_close_account_force_non_empty_balance() -> anyhow::Result<()> {
        let initial_balance = U128(10000);
        let worker = workspaces::sandbox().await?;
        let contract = init(&worker, initial_balance).await?;

        let res = contract
            .call("storage_unregister")
            .args_json((Some(true),))
            .max_gas()
            .deposit(ONE_YOCTO)
            .transact()
            .await?;
        assert!(res.is_success());

        let res = contract.call("ft_total_supply").view().await?;
        assert_eq!(res.json::<U128>()?.0, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_transfer_call_with_burned_amount() -> anyhow::Result<()> {
        let initial_balance = U128(10000);
        let transfer_amount = U128(100);
        let worker = workspaces::sandbox().await?;
        let contract = init(&worker, initial_balance).await?;
        let defi_contract = init_defi_contract(&worker, contract.id()).await?;

        // defi contract must be registered as a FT account
        register_user(&contract, defi_contract.id()).await?;

        // root invests in defi by calling `ft_transfer_call`
        let res = contract
            .batch()
            .call(
                Function::new("ft_transfer_call")
                    .args_json((
                        defi_contract.id(),
                        transfer_amount,
                        Option::<String>::None,
                        "10",
                    ))
                    .deposit(ONE_YOCTO)
                    .gas(300_000_000_000_000 / 2),
            )
            .call(
                Function::new("storage_unregister")
                    .args_json((Some(true),))
                    .deposit(ONE_YOCTO)
                    .gas(300_000_000_000_000 / 2),
            )
            .transact()
            .await?;
        assert!(res.is_success());

        let logs = res.logs();
        let expected = format!("Account @{} burned {}", contract.id(), 10);
        assert!(logs.len() >= 2);
        assert!(logs.contains(&"The account of the sender was deleted"));
        assert!(logs.contains(&(expected.as_str())));

        match res.receipt_outcomes()[5].clone().into_result()? {
            ValueOrReceiptId::Value(val) => {
                let used_amount: U128 = val.json()?;
                assert_eq!(used_amount, transfer_amount);
            }
            _ => panic!("Unexpected receipt id"),
        }
        assert!(res.json::<bool>()?);

        let res = contract.call("ft_total_supply").view().await?;
        assert_eq!(res.json::<U128>()?.0, transfer_amount.0 - 10);
        let defi_balance = contract
            .call("ft_balance_of")
            .args_json((defi_contract.id(),))
            .view()
            .await?
            .json::<U128>()?;
        assert_eq!(defi_balance.0, transfer_amount.0 - 10);

        Ok(())
    }

    #[tokio::test]
    async fn test_transfer_call_with_immediate_return_and_no_refund() -> anyhow::Result<()> {
        let initial_balance = U128(10000);
        let transfer_amount = U128(100);
        let worker = workspaces::sandbox().await?;
        let contract = init(&worker, initial_balance).await?;
        let defi_contract = init_defi_contract(&worker, contract.id()).await?;

        // defi contract must be registered as a FT account
        register_user(&contract, defi_contract.id()).await?;

        // root invests in defi by calling `ft_transfer_call`
        let res = contract
            .call("ft_transfer_call")
            .args_json((
                defi_contract.id(),
                transfer_amount,
                Option::<String>::None,
                "take-my-money",
            ))
            .max_gas()
            .deposit(ONE_YOCTO)
            .transact()
            .await?;
        assert!(res.is_success());

        let root_balance = contract
            .call("ft_balance_of")
            .args_json((contract.id(),))
            .view()
            .await?
            .json::<U128>()?;
        let defi_balance = contract
            .call("ft_balance_of")
            .args_json((defi_contract.id(),))
            .view()
            .await?
            .json::<U128>()?;
        assert_eq!(initial_balance.0 - transfer_amount.0, root_balance.0);
        assert_eq!(transfer_amount.0, defi_balance.0);

        Ok(())
    }

    #[tokio::test]
    async fn test_transfer_call_when_called_contract_not_registered_with_ft() -> anyhow::Result<()>
    {
        let initial_balance = U128(10000);
        let transfer_amount = U128(100);
        let worker = workspaces::sandbox().await?;
        let contract = init(&worker, initial_balance).await?;
        let defi_contract = init_defi_contract(&worker, contract.id()).await?;

        // call fails because DEFI contract is not registered as FT user
        let res = contract
            .call("ft_transfer_call")
            .args_json((
                defi_contract.id(),
                transfer_amount,
                Option::<String>::None,
                "take-my-money",
            ))
            .max_gas()
            .deposit(ONE_YOCTO)
            .transact()
            .await?;
        assert!(res.is_failure());

        // balances remain unchanged
        let root_balance = contract
            .call("ft_balance_of")
            .args_json((contract.id(),))
            .view()
            .await?
            .json::<U128>()?;
        let defi_balance = contract
            .call("ft_balance_of")
            .args_json((defi_contract.id(),))
            .view()
            .await?
            .json::<U128>()?;
        assert_eq!(initial_balance.0, root_balance.0);
        assert_eq!(0, defi_balance.0);

        Ok(())
    }

    #[tokio::test]
    async fn test_transfer_call_with_promise_and_refund() -> anyhow::Result<()> {
        let initial_balance = U128(10000);
        let refund_amount = U128(50);
        let transfer_amount = U128(100);
        let worker = workspaces::sandbox().await?;
        let contract = init(&worker, initial_balance).await?;
        let defi_contract = init_defi_contract(&worker, contract.id()).await?;

        // defi contract must be registered as a FT account
        register_user(&contract, defi_contract.id()).await?;

        let res = contract
            .call("ft_transfer_call")
            .args_json((
                defi_contract.id(),
                transfer_amount,
                Option::<String>::None,
                refund_amount.0.to_string(),
            ))
            .max_gas()
            .deposit(ONE_YOCTO)
            .transact()
            .await?;
        assert!(res.is_success());

        let root_balance = contract
            .call("ft_balance_of")
            .args_json((contract.id(),))
            .view()
            .await?
            .json::<U128>()?;
        let defi_balance = contract
            .call("ft_balance_of")
            .args_json((defi_contract.id(),))
            .view()
            .await?
            .json::<U128>()?;
        assert_eq!(
            initial_balance.0 - transfer_amount.0 + refund_amount.0,
            root_balance.0
        );
        assert_eq!(transfer_amount.0 - refund_amount.0, defi_balance.0);

        Ok(())
    }

    #[tokio::test]
    async fn test_transfer_call_promise_panics_for_a_full_refund() -> anyhow::Result<()> {
        let initial_balance = U128(10000);
        let transfer_amount = U128(100);
        let worker = workspaces::sandbox().await?;
        let contract = init(&worker, initial_balance).await?;
        let defi_contract = init_defi_contract(&worker, contract.id()).await?;

        // defi contract must be registered as a FT account
        register_user(&contract, defi_contract.id()).await?;

        // root invests in defi by calling `ft_transfer_call`
        let res = contract
            .call("ft_transfer_call")
            .args_json((
                defi_contract.id(),
                transfer_amount,
                Option::<String>::None,
                "no parsey as integer big panic oh no".to_string(),
            ))
            .max_gas()
            .deposit(ONE_YOCTO)
            .transact()
            .await?;
        assert!(res.is_success());

        let promise_failures = res.receipt_failures();
        assert_eq!(promise_failures.len(), 1);
        let failure = promise_failures[0].clone().into_result();
        if let Err(err) = failure {
            assert!(err.to_string().contains("ParseIntError"));
        } else {
            unreachable!();
        }

        // balances remain unchanged
        let root_balance = contract
            .call("ft_balance_of")
            .args_json((contract.id(),))
            .view()
            .await?
            .json::<U128>()?;
        let defi_balance = contract
            .call("ft_balance_of")
            .args_json((defi_contract.id(),))
            .view()
            .await?
            .json::<U128>()?;
        assert_eq!(initial_balance, root_balance);
        assert_eq!(0, defi_balance.0);

        Ok(())
    }

    // ----- END ported tests ----

    #[tokio::test]
    async fn test_approve_compare() -> anyhow::Result<()> {
        let worker = workspaces::sandbox().await?;
        let contract = init(&worker, U128(1000)).await?;

        let spender_account: AccountId = "test.near".parse().unwrap();
        let account_json = AccountIdOrKey::Account(spender_account.as_str().parse().unwrap());

        let res = contract
            .call("ft_approve")
            .args_json((&account_json, "0", "100"))
            .deposit(ONE_YOCTO)
            .transact()
            .await?;
        assert!(res.is_success());

        // Invalid current value.
        let res = contract
            .call("ft_approve")
            .args_json((&account_json, "0", "80"))
            .deposit(ONE_YOCTO)
            .transact()
            .await?;
        assert!(res
            .into_result()
            .unwrap_err()
            .to_string()
            .contains(super::ERR_ATOMIC_UPDATE));

        let allowance = contract
            .call("ft_allowance")
            .args_json((contract.id(), &account_json))
            .view()
            .await?
            .json::<U128>()?;
        assert_eq!(allowance.0, 100);

        let res = contract
            .call("ft_approve")
            .args_json((
                AccountIdOrKey::Account(spender_account.as_str().parse().unwrap()),
                "100",
                "80",
            ))
            .deposit(ONE_YOCTO)
            .transact()
            .await?;
        assert!(res.is_success());

        let allowance = contract
            .call("ft_allowance")
            .args_json((contract.id(), &account_json))
            .view()
            .await?
            .json::<U128>()?;
        assert_eq!(allowance.0, 80);

        Ok(())
    }

    #[tokio::test]
    async fn test_approve() -> anyhow::Result<()> {
        let initial_balance = U128(10000);
        let alice_amount = U128(100);
        let approve_amount = U128(50);
        let approve_transfer_amount = U128(20);
        let worker = workspaces::sandbox().await?;
        let contract = init(&worker, initial_balance).await?;
        let alice = create_and_register_user(&contract, &worker).await?;

        let res = contract
            .call("ft_transfer")
            .args_json((alice.id(), alice_amount, Option::<bool>::None))
            .max_gas()
            .deposit(ONE_YOCTO)
            .transact_async()
            .await?;
        assert!(res.status().await.is_ok());

        let new_account = worker.dev_create_account().await?;
        let new_account_json = AccountIdOrKey::Account(new_account.id().as_str().parse().unwrap());

        let f1 = alice
            .call(contract.id(), "ft_approve")
            .args_json((&new_account_json, "0", approve_amount))
            .deposit(ONE_YOCTO)
            .transact_async()
            .await?;

        let access_pk = SecretKey::from_random(KeyType::ED25519);
        let access_pk_json = serde_json::json!({"type": "Key", "value": access_pk.public_key()});

        let f2 = alice
            .call(contract.id(), "ft_approve")
            .args_json((&access_pk_json, "0", approve_amount))
            // TODO play with deposit
            .deposit(parse_near!("1 N"))
            .transact_async()
            .await?;
        let (r1, r2) = tokio::join!(f1.into_future(), f2.into_future());
        r1?.into_result()?;
        r2?.into_result()?;

        // Ensure balances have not changed from approvals
        let root_balance = contract
            .call("ft_balance_of")
            .args_json((contract.id(),))
            .view()
            .await?
            .json::<U128>()?;
        let alice_balance = contract
            .call("ft_balance_of")
            .args_json((alice.id(),))
            .view()
            .await?
            .json::<U128>()?;
        assert_eq!(initial_balance.0 - alice_amount.0, root_balance.0);
        assert_eq!(alice_amount.0, alice_balance.0);

        // Check allowance amounts
        let key_allowance = contract
            .call("ft_allowance")
            .args_json((alice.id(), &access_pk_json))
            .view()
            .await?
            .json::<U128>()?;
        let account_allowance = contract
            .call("ft_allowance")
            .args_json((alice.id(), &new_account_json))
            .view()
            .await?
            .json::<U128>()?;
        assert_eq!(account_allowance.0, approve_amount.0);
        assert_eq!(key_allowance.0, approve_amount.0);

        let access_signer = Account::from_secret_key(contract.id().clone(), access_pk, &worker);

        let receiver_account = create_and_register_user(&contract, &worker).await?;

        access_signer
            .call(contract.id(), "ft_transfer_from_key")
            .args_json((
                alice.id(),
                receiver_account.id(),
                approve_transfer_amount,
                "test memo",
            ))
            .transact()
            .await?
            .into_result()?;

        new_account
            .call(contract.id(), "ft_transfer_from_account")
            .args_json((
                alice.id(),
                receiver_account.id(),
                approve_transfer_amount,
                "test acc",
            ))
            .transact()
            .await?
            .into_result()?;

        let alice_balance = contract
            .call("ft_balance_of")
            .args_json((alice.id(),))
            .view()
            .await?
            .json::<U128>()?;
        let receiver_balance = contract
            .call("ft_balance_of")
            .args_json((receiver_account.id(),))
            .view()
            .await?
            .json::<U128>()?;
        assert_eq!(
            alice_amount.0 - (approve_transfer_amount.0 * 2),
            alice_balance.0
        );
        assert_eq!(approve_transfer_amount.0 * 2, receiver_balance.0);

        Ok(())
    }

    #[tokio::test]
    async fn test_transfer_call_from_with_burned_amount() -> anyhow::Result<()> {
        let initial_balance = U128(10000);
        let transfer_amount = U128(100);
        let worker = workspaces::sandbox().await?;
        let contract = init(&worker, initial_balance).await?;
        let defi_contract = init_defi_contract(&worker, contract.id()).await?;

        // defi contract must be registered as a FT account
        register_user(&contract, defi_contract.id()).await?;

        // TODO could use key in future, async calls are bugged in workspaces though
        let spender = worker.dev_create_account().await?;
        let spender_json = AccountIdOrKey::Account(spender.id().as_str().parse().unwrap());

        let approve_tx = contract
            .call("ft_approve")
            .args_json((&spender_json, "0", transfer_amount))
            .deposit(ONE_YOCTO)
            .transact_async()
            .await?;
        assert!(approve_tx.status().await.is_ok());

        let transfer_tx = spender
            .call(contract.id(), "ft_transfer_call_from_account")
            .args_json((
                contract.id(),
                defi_contract.id(),
                transfer_amount,
                Option::<String>::None,
                "10",
            ))
            .max_gas()
            // TODO do we need the deposit for transferring from another
            // .deposit(ONE_YOCTO)
            .transact_async()
            .await?;

        // Unregister storage before all transfer_call_from receipts finalize
        // TODO this timeout is janky, but we don't have a way to listen to new block event.
        // TODO this could also be removed if fast forward processed receipts, which it doesn't
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let res = contract
            .call("storage_unregister")
            .args_json((Some(true),))
            .deposit(ONE_YOCTO)
            .gas(300_000_000_000_000 / 2)
            .transact()
            .await?;
        assert!(res.is_success());
        assert!(res.json::<bool>()?);

        let res = transfer_tx.await?;
        let logs = res.logs();
        assert!(&logs.contains(&"The account of the sender was deleted"));
        let expected = format!("Account @{} burned {}", contract.id(), 10);
        assert!(logs.contains(&(expected.as_str())));

        match res.receipt_outcomes()[5].clone().into_result()? {
            ValueOrReceiptId::Value(val) => {
                let used_amount: U128 = val.json()?;
                assert_eq!(used_amount, transfer_amount);
            }
            _ => panic!("Unexpected receipt id"),
        }

        let res = contract.call("ft_total_supply").view().await?;
        assert_eq!(res.json::<U128>()?.0, transfer_amount.0 - 10);
        let defi_balance = contract
            .call("ft_balance_of")
            .args_json((defi_contract.id(),))
            .view()
            .await?
            .json::<U128>()?;
        assert_eq!(defi_balance.0, transfer_amount.0 - 10);

        let allowance = contract
            .call("ft_allowance")
            .args_json((contract.id(), &spender_json))
            .view()
            .await?
            .json::<U128>()?;
        assert_eq!(allowance.0, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_transfer_call_from_with_immediate_return_and_no_refund() -> anyhow::Result<()> {
        let initial_balance = U128(10000);
        let transfer_amount = U128(100);
        let worker = workspaces::sandbox().await?;
        let contract = init(&worker, initial_balance).await?;
        let defi_contract = init_defi_contract(&worker, contract.id()).await?;

        // defi contract must be registered as a FT account
        register_user(&contract, defi_contract.id()).await?;

        // TODO could use key in future, async calls are bugged in workspaces though
        let spender = worker.dev_create_account().await?;
        let spender_json = AccountIdOrKey::Account(spender.id().as_str().parse().unwrap());

        let approve_tx = contract
            .call("ft_approve")
            .args_json((&spender_json, "0", transfer_amount))
            .deposit(ONE_YOCTO)
            .transact_async()
            .await?;
        assert!(approve_tx.status().await.is_ok());

        spender
            .call(contract.id(), "ft_transfer_call_from_account")
            .args_json((
                contract.id(),
                defi_contract.id(),
                transfer_amount,
                Option::<String>::None,
                "take-my-money",
            ))
            .max_gas()
            // TODO do we need the deposit for transferring from another
            // .deposit(ONE_YOCTO)
            .transact()
            .await?
            .into_result()?;

        let root_balance = contract
            .call("ft_balance_of")
            .args_json((contract.id(),))
            .view()
            .await?
            .json::<U128>()?;
        let defi_balance = contract
            .call("ft_balance_of")
            .args_json((defi_contract.id(),))
            .view()
            .await?
            .json::<U128>()?;
        assert_eq!(initial_balance.0 - transfer_amount.0, root_balance.0);
        assert_eq!(transfer_amount.0, defi_balance.0);

        let allowance = contract
            .call("ft_allowance")
            .args_json((contract.id(), &spender_json))
            .view()
            .await?
            .json::<U128>()?;
        assert_eq!(allowance.0, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_transfer_call_from_when_called_contract_not_registered_with_ft(
    ) -> anyhow::Result<()> {
        let initial_balance = U128(10000);
        let transfer_amount = U128(100);
        let worker = workspaces::sandbox().await?;
        let contract = init(&worker, initial_balance).await?;
        let defi_contract = init_defi_contract(&worker, contract.id()).await?;

        // TODO could use key in future, async calls are bugged in workspaces though
        let spender = worker.dev_create_account().await?;
        let spender_json = AccountIdOrKey::Account(spender.id().as_str().parse().unwrap());

        let approve_tx = contract
            .call("ft_approve")
            .args_json((&spender_json, "0", transfer_amount))
            .deposit(ONE_YOCTO)
            .transact_async()
            .await?;
        assert!(approve_tx.status().await.is_ok());

        // call fails because DEFI contract is not registered as FT user
        let res = spender
            .call(contract.id(), "ft_transfer_call_from_account")
            .args_json((
                contract.id(),
                defi_contract.id(),
                transfer_amount,
                Option::<String>::None,
                "take-my-money",
            ))
            .max_gas()
            // TODO do we need the deposit for transferring from another
            // .deposit(ONE_YOCTO)
            .transact()
            .await?;
        assert!(res
            .into_result()
            .unwrap_err()
            .to_string()
            .contains(&format!("{} is not registered", defi_contract.id())));

        // balances remain unchanged
        let root_balance = contract
            .call("ft_balance_of")
            .args_json((contract.id(),))
            .view()
            .await?
            .json::<U128>()?;
        let defi_balance = contract
            .call("ft_balance_of")
            .args_json((defi_contract.id(),))
            .view()
            .await?
            .json::<U128>()?;
        assert_eq!(initial_balance.0, root_balance.0);
        assert_eq!(0, defi_balance.0);

        let allowance = contract
            .call("ft_allowance")
            .args_json((contract.id(), &spender_json))
            .view()
            .await?
            .json::<U128>()?;
        assert_eq!(allowance.0, transfer_amount.0);

        Ok(())
    }

    #[tokio::test]
    async fn test_transfer_call_from_with_promise_and_refund() -> anyhow::Result<()> {
        let initial_balance = U128(10000);
        let refund_amount = U128(50);
        let transfer_amount = U128(100);
        let worker = workspaces::sandbox().await?;
        let contract = init(&worker, initial_balance).await?;
        let defi_contract = init_defi_contract(&worker, contract.id()).await?;

        // defi contract must be registered as a FT account
        register_user(&contract, defi_contract.id()).await?;

        let spender = worker.dev_create_account().await?;
        let spender_json = AccountIdOrKey::Account(spender.id().as_str().parse().unwrap());

        let approve_tx = contract
            .call("ft_approve")
            .args_json((&spender_json, "0", transfer_amount))
            .deposit(ONE_YOCTO)
            .transact_async()
            .await?;
        assert!(approve_tx.status().await.is_ok());

        let res = spender
            .call(contract.id(), "ft_transfer_call_from_account")
            .args_json((
                contract.id(),
                defi_contract.id(),
                transfer_amount,
                Option::<String>::None,
                refund_amount,
            ))
            .max_gas()
            .transact()
            .await?;
        res.into_result()?;

        let root_balance = contract
            .call("ft_balance_of")
            .args_json((contract.id(),))
            .view()
            .await?
            .json::<U128>()?;
        let defi_balance = contract
            .call("ft_balance_of")
            .args_json((defi_contract.id(),))
            .view()
            .await?
            .json::<U128>()?;
        assert_eq!(
            initial_balance.0 - transfer_amount.0 + refund_amount.0,
            root_balance.0
        );
        assert_eq!(transfer_amount.0 - refund_amount.0, defi_balance.0);

        // Allowance should be increased to the refund amount.
        let allowance = contract
            .call("ft_allowance")
            .args_json((contract.id(), &spender_json))
            .view()
            .await?
            .json::<U128>()?;
        assert_eq!(allowance.0, refund_amount.0);

        Ok(())
    }

    // TODO
    #[tokio::test]
    async fn test_transfer_call_from_promise_panics_for_a_full_refund() -> anyhow::Result<()> {
        let initial_balance = U128(10000);
        let transfer_amount = U128(100);
        let worker = workspaces::sandbox().await?;
        let contract = init(&worker, initial_balance).await?;
        let defi_contract = init_defi_contract(&worker, contract.id()).await?;

        // defi contract must be registered as a FT account
        register_user(&contract, defi_contract.id()).await?;

        // root invests in defi by calling `ft_transfer_call`
        let res = contract
            .call("ft_transfer_call")
            .args_json((
                defi_contract.id(),
                transfer_amount,
                Option::<String>::None,
                "no parsey as integer big panic oh no".to_string(),
            ))
            .max_gas()
            .deposit(ONE_YOCTO)
            .transact()
            .await?;
        assert!(res.is_success());

        let promise_failures = res.receipt_failures();
        assert_eq!(promise_failures.len(), 1);
        let failure = promise_failures[0].clone().into_result();
        let err = failure.unwrap_err();
        assert!(err.to_string().contains("ParseIntError"));

        // balances remain unchanged
        let root_balance = contract
            .call("ft_balance_of")
            .args_json((contract.id(),))
            .view()
            .await?
            .json::<U128>()?;
        let defi_balance = contract
            .call("ft_balance_of")
            .args_json((defi_contract.id(),))
            .view()
            .await?
            .json::<U128>()?;
        assert_eq!(initial_balance, root_balance);
        assert_eq!(0, defi_balance.0);

        Ok(())
    }
}
