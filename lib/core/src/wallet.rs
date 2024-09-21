use std::io::Write;
use std::{str::FromStr, sync::Arc};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use boltz_client::ElementsAddress;
use lwk_common::{Multisig, Signer};
use lwk_common::{singlesig_desc, Singlesig};
use lwk_signer::{AnySigner, SwSigner};
use lwk_wollet::elements::pset::PartiallySignedTransaction;
use lwk_wollet::elements_miniscript::descriptor::checksum::desc_checksum;
use lwk_wollet::{
    elements::{Address, Transaction, bitcoin::bip32},
    ElectrumClient, ElectrumUrl, ElementsNetwork, FsPersister, Tip, WalletTx, Wollet,
    WolletDescriptor,
};
use sdk_common::bitcoin::hashes::{sha256, Hash};
use sdk_common::bitcoin::secp256k1::{Message, PublicKey, Secp256k1};
use sdk_common::bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey};
use sdk_common::lightning::util::message_signing::verify;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{
    ensure_sdk,
    error::PaymentError,
    model::{Config, LiquidNetwork},
};

static LN_MESSAGE_PREFIX: &[u8] = b"Lightning Signed Message:";

#[async_trait]
pub trait OnchainWallet: Send + Sync {
    /// List all transactions in the wallet
    async fn transactions(&self) -> Result<Vec<WalletTx>, PaymentError>;

    /// Build a transaction to send funds to a recipient
    async fn build_tx(
        &self,
        fee_rate_sats_per_kvb: Option<f32>,
        recipient_address: &str,
        amount_sat: u64,
    ) -> Result<PartiallySignedTransaction, PaymentError>;

    /// Builds a drain tx.
    ///
    /// ### Arguments
    /// - `fee_rate_sats_per_kvb`: custom drain tx feerate
    /// - `recipient_address`: drain tx recipient
    /// - `enforce_amount_sat`: if set, the drain tx will only be built if the amount transferred is
    ///   this amount, otherwise it will fail with a validation error
    async fn build_drain_tx(
        &self,
        fee_rate_sats_per_kvb: Option<f32>,
        recipient_address: &str,
        enforce_amount_sat: Option<u64>,
    ) -> Result<PartiallySignedTransaction, PaymentError>;

    async fn finalize_tx(&self, pset: &mut PartiallySignedTransaction) -> Result<Transaction, PaymentError>;

    /// Get the next unused address in the wallet
    async fn next_unused_address(&self) -> Result<Address, PaymentError>;

    /// Get the current tip of the blockchain the wallet is aware of
    async fn tip(&self) -> Tip;

    /// Get the public key of the wallet
    fn pubkey(&self) -> String;

    fn derive_bip32_key(&self, path: Vec<ChildNumber>) -> Result<ExtendedPrivKey, PaymentError>;

    /// Sign given message with the wallet private key. Returns a zbase
    /// encoded signature.
    fn sign_message(&self, msg: &str) -> Result<String>;

    /// Check whether given message was signed by the given
    /// pubkey and the signature (zbase encoded) is valid.
    fn check_message(&self, message: &str, pubkey: &str, signature: &str) -> Result<bool>;

    /// Perform a full scan of the wallet
    async fn full_scan(&self) -> Result<(), PaymentError>;
}

pub(crate) struct LiquidOnchainWallet {
    wallet: Arc<Mutex<Wollet>>,
    config: Config,
    pub(crate) lwk_signer: SwSigner,
}

pub use crate::sdk::Key;

fn fmt_path(path: &bip32::DerivationPath) -> String {
    path.to_string().replace("m/", "").replace('\'', "h")
}

fn multisig_desc(
    threshold: u32,
    xpubs: Vec<(Option<bip32::KeySource>, bip32::Xpub)>,
    script_variant: Multisig,
) -> Result<String, String> {
    if threshold == 0 {
        return Err("Threshold cannot be 0".into());
    } else if threshold as usize > xpubs.len() {
        return Err("Threshold cannot be greater than the number of xpubs".into());
    }

    let (prefix, suffix) = match script_variant {
        Multisig::Wsh => ("elwsh(multi", ")"),
    };

    let mut engine = sha256::HashEngine::default();
    for (source, xpub) in &xpubs {
        let fp = if let Some(source) = source {
            source.0
        } else {
            xpub.fingerprint()
        };

        engine.write_all(fp.as_bytes()).unwrap();
    }
    let hashed_msg = sha256::Hash::from_engine(engine);

    use sdk_common::bitcoin::hashes::hex::ToHex;
    let blinding_key = format!("slip77({})", hashed_msg.to_hex());

    let xpubs = xpubs
        .iter()
        .map(|(keyorigin, xpub)| {
            let prefix = if let Some((fingerprint, path)) = keyorigin {
                format!("[{fingerprint}/{}]", fmt_path(path))
            } else {
                "".to_string()
            };
            format!("{prefix}{xpub}/<0;1>/*")
        })
        .collect::<Vec<_>>()
        .join(",");
    let desc = format!("ct({blinding_key},{prefix}({threshold},{xpubs}){suffix})");
    let checksum = desc_checksum(&desc).map_err(|e| format!("{:?}", e))?;
    Ok(format!("{desc}#{checksum}"))
}

impl LiquidOnchainWallet {
    pub(crate) fn new(mnemonic: String, keys: Vec<Key>, config: Config) -> Result<Self> {
        let is_mainnet = config.network == LiquidNetwork::Mainnet;
        let lwk_signer = SwSigner::new(&mnemonic, is_mainnet)?;
        let xpubs = keys.into_iter().map(|k| match k {
            Key::Private => (None, lwk_signer.xpub()),
            Key::Public(xpub) => (None, xpub)
        }).collect();
        let descriptor = LiquidOnchainWallet::get_descriptor(xpubs)?;
        log::info!("{}", descriptor);
        let elements_network: ElementsNetwork = config.network.into();

        let lwk_persister = FsPersister::new(
            config.get_wallet_working_dir(&lwk_signer)?,
            elements_network,
            &descriptor,
        )?;
        let wollet = Wollet::new(elements_network, lwk_persister, descriptor)?;
        Ok(Self {
            wallet: Arc::new(Mutex::new(wollet)),
            lwk_signer,
            config,
        })
    }

    fn get_descriptor(
        xpubs: Vec<(Option<bip32::KeySource>, bip32::Xpub)>,
    ) -> Result<WolletDescriptor, PaymentError> {
        let descriptor_str = multisig_desc(2, xpubs, Multisig::Wsh)
            .map_err(|e| anyhow!("Invalid descriptor: {e}"))?;
        Ok(descriptor_str.parse()?)
    }
}

#[async_trait]
impl OnchainWallet for LiquidOnchainWallet {
    /// List all transactions in the wallet
    async fn transactions(&self) -> Result<Vec<WalletTx>, PaymentError> {
        let wallet = self.wallet.lock().await;
        wallet.transactions().map_err(|e| PaymentError::Generic {
            err: format!("Failed to fetch wallet transactions: {e:?}"),
        })
    }

    /// Build a transaction to send funds to a recipient
    async fn build_tx(
        &self,
        fee_rate_sats_per_kvb: Option<f32>,
        recipient_address: &str,
        amount_sat: u64,
    ) -> Result<PartiallySignedTransaction, PaymentError> {
        let lwk_wollet = self.wallet.lock().await;
        let mut pset = lwk_wollet::TxBuilder::new(self.config.network.into())
            .add_lbtc_recipient(
                &ElementsAddress::from_str(recipient_address).map_err(|e| {
                    PaymentError::Generic {
                        err: format!(
                      "Recipient address {recipient_address} is not a valid ElementsAddress: {e:?}"
                  ),
                    }
                })?,
                amount_sat,
            )?
            .fee_rate(fee_rate_sats_per_kvb)
            .finish(&lwk_wollet)?;
        let signer = AnySigner::Software(self.lwk_signer.clone());
        signer.sign(&mut pset)?;
        Ok(pset)
    }

    async fn build_drain_tx(
        &self,
        fee_rate_sats_per_kvb: Option<f32>,
        recipient_address: &str,
        enforce_amount_sat: Option<u64>,
    ) -> Result<PartiallySignedTransaction, PaymentError> {
        let lwk_wollet = self.wallet.lock().await;

        let address =
            ElementsAddress::from_str(recipient_address).map_err(|e| PaymentError::Generic {
                err: format!(
                    "Recipient address {recipient_address} is not a valid ElementsAddress: {e:?}"
                ),
            })?;
        let mut pset = lwk_wollet
            .tx_builder()
            .drain_lbtc_wallet()
            .drain_lbtc_to(address)
            .fee_rate(fee_rate_sats_per_kvb)
            .finish()?;

        if let Some(enforce_amount_sat) = enforce_amount_sat {
            let pset_details = lwk_wollet.get_details(&pset)?;
            let pset_balance_sat = pset_details
                .balance
                .balances
                .get(&lwk_wollet.policy_asset())
                .unwrap_or(&0);
            let pset_fees = pset_details.balance.fee;

            ensure_sdk!(
                (*pset_balance_sat * -1) as u64 - pset_fees == enforce_amount_sat,
                PaymentError::Generic {
                    err: format!("Drain tx amount {pset_balance_sat} sat doesn't match enforce_amount_sat {enforce_amount_sat} sat")
                }
            );
        }

        let signer = AnySigner::Software(self.lwk_signer.clone());
        signer.sign(&mut pset)?;
        Ok(pset)
    }

    async fn finalize_tx(&self, pset: &mut PartiallySignedTransaction) -> Result<Transaction, PaymentError> {
        let lwk_wollet = self.wallet.lock().await;
        Ok(lwk_wollet.finalize(pset)?)
    }

    /// Get the next unused address in the wallet
    async fn next_unused_address(&self) -> Result<Address, PaymentError> {
        Ok(self.wallet.lock().await.address(None)?.address().clone())
    }

    /// Get the current tip of the blockchain the wallet is aware of
    async fn tip(&self) -> Tip {
        self.wallet.lock().await.tip()
    }

    /// Get the public key of the wallet
    fn pubkey(&self) -> String {
        self.lwk_signer.xpub().public_key.to_string()
    }

    /// Perform a full scan of the wallet
    async fn full_scan(&self) -> Result<(), PaymentError> {
        let mut wallet = self.wallet.lock().await;
        let mut electrum_client = ElectrumClient::new(&ElectrumUrl::new(
            &self.config.liquid_electrum_url,
            true,
            true,
        ))?;
        lwk_wollet::full_scan_with_electrum_client(&mut wallet, &mut electrum_client)?;
        Ok(())
    }

    fn derive_bip32_key(&self, path: Vec<ChildNumber>) -> Result<ExtendedPrivKey, PaymentError> {
        let seed = self.lwk_signer.seed().ok_or(PaymentError::SignerError {
            err: "Could not get signer seed".to_string(),
        })?;

        let bip32_xpriv = ExtendedPrivKey::new_master(self.config.network.into(), &seed)?
            .derive_priv(&Secp256k1::new(), &path)?;
        Ok(bip32_xpriv)
    }

    fn sign_message(&self, message: &str) -> Result<String> {
        let seed = self
            .lwk_signer
            .seed()
            .ok_or(anyhow!("Could not get signer seed"))?;
        let secp = Secp256k1::new();
        let keypair = ExtendedPrivKey::new_master(self.config.network.into(), &seed)
            .map_err(|e| anyhow!("Could not get signer keypair: {e}"))?
            .to_keypair(&secp);
        // Prefix and double hash message
        let mut engine = sha256::HashEngine::default();
        engine.write_all(LN_MESSAGE_PREFIX)?;
        engine.write_all(message.as_bytes())?;
        let hashed_msg = sha256::Hash::from_engine(engine);
        let double_hashed_msg = Message::from(sha256::Hash::hash(&hashed_msg));
        // Get message signature and encode to zbase32
        let recoverable_sig =
            secp.sign_ecdsa_recoverable(&double_hashed_msg, &keypair.secret_key());
        let (recovery_id, sig) = recoverable_sig.serialize_compact();
        let mut complete_signature = vec![31 + recovery_id.to_i32() as u8];
        complete_signature.extend_from_slice(&sig);
        Ok(zbase32::encode_full_bytes(&complete_signature))
    }

    fn check_message(&self, message: &str, pubkey: &str, signature: &str) -> Result<bool> {
        let pk = PublicKey::from_str(pubkey)?;
        Ok(verify(message.as_bytes(), signature, &pk))
    }
}
