use near_contract_standards::fungible_token::metadata::{
    FungibleTokenMetadata, FungibleTokenMetadataProvider, FT_METADATA_SPEC,
};
use near_contract_standards::fungible_token::FungibleToken;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LazyOption, LookupMap};
use near_sdk::json_types::U128;
use near_sdk::{
    env, log, near_bindgen, require, AccountId, Balance, BorshStorageKey, PanicOnDefault,
    PromiseOrValue,
};

// TODO
type AccountIdOrKey = AccountId;

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
    use near_sdk::json_types::U128;
    use near_sdk::ONE_YOCTO;
    use near_units::parse_near;
    use workspaces::operations::Function;
    use workspaces::result::ValueOrReceiptId;
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

    async fn init(
        worker: &Worker<impl DevNetwork>,
        initial_balance: U128,
    ) -> anyhow::Result<(Contract, Account, Contract)> {
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

        let defi_contract = worker
            .dev_deploy(&workspaces::compile_project("./test-contract-defi").await?)
            .await?;

        let res = defi_contract
            .call("new")
            .args_json((ft_contract.id(),))
            .max_gas()
            .transact()
            .await?;
        assert!(res.is_success());

        let alice = ft_contract
            .as_account()
            .create_subaccount("alice")
            .initial_balance(parse_near!("10 N"))
            .transact()
            .await?
            .into_result()?;
        register_user(&ft_contract, alice.id()).await?;

        let res = ft_contract
            .call("storage_deposit")
            .args_json((alice.id(), Option::<bool>::None))
            .deposit(near_sdk::env::storage_byte_cost() * 125)
            .max_gas()
            .transact()
            .await?;
        assert!(res.is_success());

        return Ok((ft_contract, alice, defi_contract));
    }

    #[tokio::test]
    async fn test_total_supply() -> anyhow::Result<()> {
        let initial_balance = U128::from(parse_near!("10000 N"));
        let worker = workspaces::sandbox().await?;
        let (contract, _, _) = init(&worker, initial_balance).await?;

        let res = contract.call("ft_total_supply").view().await?;
        assert_eq!(res.json::<U128>()?, initial_balance);

        Ok(())
    }

    #[tokio::test]
    async fn test_simple_transfer() -> anyhow::Result<()> {
        let initial_balance = U128::from(parse_near!("10000 N"));
        let transfer_amount = U128::from(parse_near!("100 N"));
        let worker = workspaces::sandbox().await?;
        let (contract, alice, _) = init(&worker, initial_balance).await?;

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
        let initial_balance = U128::from(parse_near!("10000 N"));
        let worker = workspaces::sandbox().await?;
        let (contract, alice, _) = init(&worker, initial_balance).await?;

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
        let initial_balance = U128::from(parse_near!("10000 N"));
        let worker = workspaces::sandbox().await?;
        let (contract, _, _) = init(&worker, initial_balance).await?;

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
    async fn simulate_close_account_force_non_empty_balance() -> anyhow::Result<()> {
        let initial_balance = U128::from(parse_near!("10000 N"));
        let worker = workspaces::sandbox().await?;
        let (contract, _, _) = init(&worker, initial_balance).await?;

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
    async fn simulate_transfer_call_with_burned_amount() -> anyhow::Result<()> {
        let initial_balance = U128::from(parse_near!("10000 N"));
        let transfer_amount = U128::from(parse_near!("100 N"));
        let worker = workspaces::sandbox().await?;
        let (contract, _, defi_contract) = init(&worker, initial_balance).await?;

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

        // TODO: replace the following manual value extraction when workspaces
        // resolves https://github.com/near/workspaces-rs/issues/201
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
    async fn simulate_transfer_call_with_immediate_return_and_no_refund() -> anyhow::Result<()> {
        let initial_balance = U128::from(parse_near!("10000 N"));
        let transfer_amount = U128::from(parse_near!("100 N"));
        let worker = workspaces::sandbox().await?;
        let (contract, _, defi_contract) = init(&worker, initial_balance).await?;

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
    async fn simulate_transfer_call_when_called_contract_not_registered_with_ft(
    ) -> anyhow::Result<()> {
        let initial_balance = U128::from(parse_near!("10000 N"));
        let transfer_amount = U128::from(parse_near!("100 N"));
        let worker = workspaces::sandbox().await?;
        let (contract, _, defi_contract) = init(&worker, initial_balance).await?;

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
    async fn simulate_transfer_call_with_promise_and_refund() -> anyhow::Result<()> {
        let initial_balance = U128::from(parse_near!("10000 N"));
        let refund_amount = U128::from(parse_near!("50 N"));
        let transfer_amount = U128::from(parse_near!("100 N"));
        let worker = workspaces::sandbox().await?;
        let (contract, _, defi_contract) = init(&worker, initial_balance).await?;

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
    async fn simulate_transfer_call_promise_panics_for_a_full_refund() -> anyhow::Result<()> {
        let initial_balance = U128::from(parse_near!("10000 N"));
        let transfer_amount = U128::from(parse_near!("100 N"));
        let worker = workspaces::sandbox().await?;
        let (contract, _, defi_contract) = init(&worker, initial_balance).await?;

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
}
