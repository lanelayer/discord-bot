use serenity::all::*;
use serenity::async_trait;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};

use anyhow::Context as AnyhowContext;
use alloy_primitives::{Address, Bytes, U256};
use alloy_signer_local::PrivateKeySigner;
use alloy_network::TxSigner;
use alloy_consensus::{TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_provider::fillers::{FillProvider, JoinFill, GasFiller, BlobGasFiller, NonceFiller, ChainIdFiller};
use alloy_provider::RootProvider;
use alloy_network::Ethereum;
use s3::creds::Credentials;
use s3::{Bucket, Region};
use std::str::FromStr;

type OnboardingState = Arc<RwLock<HashMap<u64, (Option<String>, Option<String>)>>>;
type AlloyProvider = FillProvider<
    JoinFill<
        alloy_provider::Identity,
        JoinFill<
            GasFiller,
            JoinFill<
                BlobGasFiller,
                JoinFill<
                    NonceFiller,
                    ChainIdFiller
                >
            >
        >
    >,
    RootProvider<Ethereum>
>;

#[derive(Clone)]
enum FundingBackend {
    Memory(Arc<RwLock<HashSet<u64>>>),
    S3 { bucket: Bucket },
}

#[derive(Clone)]
struct FundingStore {
    backend: FundingBackend,
}

impl FundingStore {
    async fn new_from_env() -> anyhow::Result<Self> {
        let backend = std::env::var("FUNDING_BACKEND").unwrap_or_else(|_| "memory".to_string());
        if backend.eq_ignore_ascii_case("s3") {
            let bucket_name =
                std::env::var("S3_BUCKET").context("S3_BUCKET required when FUNDING_BACKEND=s3")?;
            let region_name =
                std::env::var("S3_REGION").context("S3_REGION required when FUNDING_BACKEND=s3")?;
            let endpoint = std::env::var("S3_ENDPOINT")
                .context("S3_ENDPOINT required when FUNDING_BACKEND=s3")?;
            let access_key = std::env::var("S3_ACCESS_KEY")
                .context("S3_ACCESS_KEY required when FUNDING_BACKEND=s3")?;
            let secret_key = std::env::var("S3_SECRET_KEY")
                .context("S3_SECRET_KEY required when FUNDING_BACKEND=s3")?;

            let region = Region::Custom {
                region: region_name,
                endpoint,
            };
            let credentials =
                Credentials::new(Some(&access_key), Some(&secret_key), None, None, None)?;
            let mut bucket = Bucket::new(&bucket_name, region, credentials)
                .map_err(|e| anyhow::anyhow!("Failed to create S3 bucket: {}", e))?;
            bucket.set_path_style();

            Ok(Self {
                backend: FundingBackend::S3 { bucket },
            })
        } else {
            Ok(Self {
                backend: FundingBackend::Memory(Arc::new(RwLock::new(HashSet::new()))),
            })
        }
    }

    async fn has_funded(&self, discord_id: u64) -> anyhow::Result<bool> {
        match &self.backend {
            FundingBackend::Memory(set) => {
                let guard = set.read().await;
                Ok(guard.contains(&discord_id))
            }
            FundingBackend::S3 { bucket } => {
                let key = format!("funded/{}.json", discord_id);
                match bucket.head_object(&key).await {
                    Ok(_) => Ok(true),
                    Err(s3::error::S3Error::Http(404, _)) => Ok(false),
                    Err(e) => Err(anyhow::anyhow!("S3 error: {:?}", e)),
                }
            }
        }
    }

    async fn mark_funded(&self, discord_id: u64) -> anyhow::Result<()> {
        match &self.backend {
            FundingBackend::Memory(set) => {
                let mut guard = set.write().await;
                guard.insert(discord_id);
                Ok(())
            }
            FundingBackend::S3 { bucket } => {
                let key = format!("funded/{}.json", discord_id);
                let body = b"{\"funded\":true}";
                bucket
                    .put_object(&key, body)
                    .await
                    .map(|_| ())
                    .map_err(|e| anyhow::anyhow!(e))
            }
        }
    }
}

#[derive(Clone)]
struct Faucet {
    provider: AlloyProvider,
    signer: PrivateKeySigner,
    amount: U256,
    chain_id: u64,
    nonce_tracker: Arc<Mutex<Option<u64>>>, // Track last known nonce
}

impl Faucet {
    async fn new_from_env() -> anyhow::Result<Self> {
        let rpc_url_str =
            std::env::var("FAUCET_RPC_URL").context("FAUCET_RPC_URL is required for faucet")?;
        let provider_url = rpc_url_str
            .parse::<url::Url>()
            .context("FAUCET_RPC_URL must be a valid URL")?;
        let private_key = std::env::var("FAUCET_PRIVATE_KEY")
            .context("FAUCET_PRIVATE_KEY is required for faucet")?;
        let amount_str = std::env::var("FAUCET_AMOUNT_WEI")
            .context("FAUCET_AMOUNT_WEI is required for faucet")?;
        let amount = U256::from_str_radix(&amount_str, 10)
            .context("FAUCET_AMOUNT_WEI must be a decimal number")?;
        let chain_id = std::env::var("FAUCET_CHAIN_ID")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1281453634); // Default to Core Lane chain ID

        let signer = PrivateKeySigner::from_str(&private_key)
            .context("Invalid FAUCET_PRIVATE_KEY")?;

        // Create Alloy provider
        let provider = ProviderBuilder::new()
            .connect_http(provider_url);

        Ok(Self {
            provider,
            signer,
            amount,
            chain_id,
            nonce_tracker: Arc::new(Mutex::new(None)),
        })
    }


    async fn send_funds(&self, to_addr: &str) -> anyhow::Result<alloy_primitives::B256> {
        let to: Address = to_addr.parse().context("Invalid Core Lane address")?;
        let from = self.signer.address();

        println!("Faucet: Checking balance for {:?}", from);
        let balance = self.provider.get_balance(from).await
            .map_err(|e| anyhow::anyhow!("Failed to get balance: {}", e))?;
        println!("Faucet: Current balance: {} wei", balance);

        // Calculate required amount: transfer amount + gas (21000 * gas_price)
        let gas_limit = 21000u64;
        let gas_price = self.provider.get_gas_price().await
            .map_err(|e| anyhow::anyhow!("Failed to get gas price: {}", e))?;
        let gas_cost = U256::from(gas_limit) * U256::from(gas_price);
        let total_required = self.amount + gas_cost;

        if balance < total_required {
            return Err(anyhow::anyhow!(
                "Insufficient balance: have {} wei, need {} wei (amount: {} + gas: {})",
                balance, total_required, self.amount, gas_cost
            ));
        }

        // Use configured chain ID (Core Lane: 1281453634)
        let chain_id = self.chain_id;

        // Get nonce with proper management using Alloy and our tracker
        // We track nonces of transactions we've sent to ensure sequential ordering
        let nonce = {
            let tracker = self.nonce_tracker.lock().await;

            // Get on-chain nonce using Alloy provider
            let on_chain_nonce = self.provider.get_transaction_count(from).await
                .map_err(|e| anyhow::anyhow!("Failed to get transaction count: {}", e))?;

            // Determine the next nonce to use
            let next_nonce = if let Some(tracked) = *tracker {
                // We have sent transactions before - use tracked + 1
                // But ensure it's at least as high as on-chain (safety check)
                std::cmp::max(tracked + 1, on_chain_nonce)
            } else {
                // First transaction - use on-chain nonce
                on_chain_nonce
            };

            println!("Faucet: Using nonce {} (on-chain: {}, tracked: {:?})",
                next_nonce, on_chain_nonce, *tracker);
            next_nonce
        };

        // For EIP-1559, use gas price as max_fee_per_gas and 10% as max_priority_fee_per_gas
        let max_fee_per_gas = gas_price;
        let max_priority_fee_per_gas = gas_price / 10;

        println!("Faucet: Sending {} wei to {:?} with gas price {} wei", self.amount, to, gas_price);

        // Build the EIP-1559 transaction
        let mut tx = TxEip1559 {
            chain_id,
            nonce,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            gas_limit: 21000, // Standard transfer
            to: alloy_primitives::TxKind::Call(to),
            value: self.amount,
            input: Bytes::new(),
            access_list: Default::default(),
        };

        // Sign the transaction
        let signature = self
            .signer
            .sign_transaction(&mut tx)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to sign transaction: {}", e))?;

        // Create signed transaction envelope
        let signed_tx = TxEnvelope::Eip1559(
            alloy_consensus::Signed::new_unchecked(tx, signature, Default::default()),
        );

        // Encode the transaction
        let mut encoded = Vec::new();
        signed_tx.encode_2718(&mut encoded);
        let tx_bytes = Bytes::from(encoded);

        println!("Faucet: Broadcasting transaction...");
        // Send the raw transaction using Alloy provider
        let pending_tx = match self.provider.send_raw_transaction(&tx_bytes).await {
            Ok(tx) => tx,
            Err(e) => {
                // Transaction send failed - don't update nonce tracker
                // The nonce we calculated is still available for retry
                return Err(anyhow::anyhow!("Failed to send transaction: {}", e));
            }
        };

        let tx_hash = *pending_tx.tx_hash();
        println!("Faucet: Transaction broadcast: {:?}", tx_hash);

        // Get initial balance of recipient to verify later if needed
        let initial_balance = self.provider.get_balance(to).await
            .map_err(|e| anyhow::anyhow!("Failed to get initial balance: {}", e))?;
        println!("Faucet: Recipient initial balance: {} wei", initial_balance);

        // Update nonce tracker now that we've successfully sent the transaction
        // This ensures we track all sent transactions for proper nonce sequencing
        // Even if the transaction later fails on-chain, we've used this nonce
        {
            let mut tracker = self.nonce_tracker.lock().await;
            *tracker = Some(nonce);
            println!("Faucet: Updated nonce tracker to {} after successful send", nonce);
        }

        // Wait for transaction confirmation (increased timeout to 1200 seconds for slow networks)
        println!("Faucet: Waiting for transaction confirmation...");
        let mut confirmed = false;
        for i in 0..1200 {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            if let Ok(Some(receipt)) = self.provider.get_transaction_receipt(tx_hash).await {
                let status_ok = receipt.status();
                println!("Faucet: Transaction receipt received, status: {}", if status_ok { "success" } else { "failed" });
                if status_ok {
                    println!("Faucet: Transaction confirmed successfully!");
                    confirmed = true;
                    // Nonce tracker was already updated when we sent the transaction
                    break;
                } else {
                    return Err(anyhow::anyhow!("Transaction failed on-chain"));
                }
            }
            // Log progress every 60 seconds
            if (i + 1) % 60 == 0 {
                println!("Faucet: Still waiting for confirmation... ({} seconds elapsed)", i + 1);
            }
        }

        if !confirmed {
            // Transaction not confirmed within timeout - check balance to see if funds were actually received
            println!("Faucet: Transaction not confirmed within timeout, checking balance to verify...");
            match self.provider.get_balance(to).await {
                Ok(current_balance) => {
                    println!("Faucet: Recipient balance after timeout: {} wei (initial: {} wei)", current_balance, initial_balance);
                    // Check if balance increased by at least the expected amount (allowing for some variance)
                    // We use >= to handle cases where they might have received other funds
                    let balance_increase = current_balance.saturating_sub(initial_balance);
                    if balance_increase >= self.amount {
                        println!("Faucet: Balance verification successful! Balance increased by {} wei (expected: {} wei)", balance_increase, self.amount);
                        println!("Faucet: Transaction likely succeeded even though receipt wasn't received in time");
                        // Consider it successful based on balance check
                        confirmed = true;
                    } else {
                        println!("Faucet: Balance did not increase sufficiently. Increase: {} wei, Expected: {} wei", balance_increase, self.amount);
                    }
                }
                Err(e) => {
                    println!("Faucet: Could not verify balance after timeout: {:?}", e);
                }
            }
        }

        if !confirmed {
            // Transaction not confirmed and balance check didn't verify success
            // Return error with tx_hash for manual verification
            return Err(anyhow::anyhow!(
                "Transaction not confirmed within timeout period. Transaction hash: {:?}. The transaction may still be pending. Please verify manually.",
                tx_hash
            ));
        }

        Ok(tx_hash)
    }
}

struct Handler {
    member_role_id: RoleId,
    onboarding_channel_id: Option<ChannelId>,
    admin_channel_id: Option<ChannelId>,
    funding_store: FundingStore,
    faucet: Option<Faucet>,
    faucet_init_error: Option<String>,
    _state: OnboardingState,
}

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, ctx: Context, ready: Ready) {
        println!("Bot is ready! Logged in as: {}", ready.user.name);

        // Verify configuration
        if self.onboarding_channel_id.is_none() {
            eprintln!("WARNING: ONBOARDING_CHANNEL_ID not set - onboarding will not work");
        }
        if self.admin_channel_id.is_none() {
            eprintln!("WARNING: ADMIN_CHANNEL_ID not set - admins will not see onboarding responses");
        }

        // Ensure pinned welcome message exists
        if let Some(onboarding_channel) = self.onboarding_channel_id {
            let bot_id = ready.user.id;
            let welcome_message = "Welcome!\n\nPlease click the button below to start the onboarding process. You'll need to fill out a form with:\n1. Why you joined\n2. Your Core Lane address\n\nOnce complete, you'll get access to all channels!";

            // Check pinned messages for an exact bot-authored welcome message with components
            let mut has_welcome_message = false;
            if let Ok(pins) = onboarding_channel.pins(&ctx.http).await {
                for msg in &pins {
                    if msg.author.id == bot_id
                        && msg.content == welcome_message
                        && !msg.components.is_empty()
                    {
                        has_welcome_message = true;
                        println!("Found existing pinned welcome message (ID: {})", msg.id);
                        break;
                    }
                }
            }

            // Create welcome message if it doesn't exist
            if !has_welcome_message {
            let components = vec![CreateActionRow::Buttons(vec![
                CreateButton::new("start_onboarding")
                    .label("Start Onboarding")
                    .style(ButtonStyle::Primary),
            ])];

            let message = CreateMessage::new()
                .content(welcome_message)
                .components(components);

            match onboarding_channel.send_message(&ctx.http, message).await {
                Ok(msg) => {
                        println!("Posted welcome message (ID: {})", msg.id);
                        if let Err(e) = msg.pin(&ctx.http).await {
                            eprintln!("Could not pin welcome message: {:?}", e);
                        } else {
                            println!("Pinned welcome message");
                        }
                    }
                    Err(e) => {
                        eprintln!("Could not send welcome message: {:?}", e);
                        eprintln!("Make sure the bot has 'Send Messages' permission in the onboarding channel");
                    }
                }
            }
        }
    }


    async fn interaction_create(&self, ctx: Context, interaction: Interaction) {
        // Handle button clicks
        if let Some(component) = interaction.clone().message_component() {
            if component.data.custom_id == "start_onboarding" {
                let user_id = component.user.id.get();

                // Check if user has already received laneBTC - if so, they've completed onboarding
                let has_received_funding = match self.funding_store.has_funded(user_id).await {
                    Ok(true) => true,
                    Ok(false) => false,
                    Err(e) => {
                        eprintln!("Error checking funding status for user {}: {:?}", user_id, e);
                        false // Fail open - allow them to proceed if check fails
                    }
                };

                if has_received_funding {
                    // User has already received laneBTC - they've completed onboarding
                    let message = "ℹ️ **You have already completed onboarding!**\n\nYou've already received your laneBTC. Please check your laneBTC balance in MetaMask. If you don't have it, please contact an admin.";

                    let response = CreateInteractionResponse::Message(
                        CreateInteractionResponseMessage::new()
                            .content(message)
                            .ephemeral(true),
                    );

                    if let Err(e) = component.create_response(&ctx.http, response).await {
                        eprintln!("Error responding to already-funded user: {:?}", e);
                    }
                    return;
                }

                // Show form modal with both questions
                // Note: The first parameter is the custom_id, second is the label
                let why_input = CreateInputText::new(
                    InputTextStyle::Paragraph,
                    "Why did you join our server?",  // This becomes the custom_id
                    "Why did you join our server?",  // This is the label
                )
                .required(true)
                .placeholder("Please tell us why you joined...")
                .max_length(500);

                let address_input = CreateInputText::new(
                    InputTextStyle::Short,
                    "Core Lane Address",  // This becomes the custom_id
                    "Core Lane Address",  // This is the label
                )
                .required(true)
                .placeholder("Enter your Core Lane address...")
                .max_length(100);

                let modal = CreateModal::new("onboarding_form", "Onboarding Form")
                    .components(vec![
                        CreateActionRow::InputText(why_input),
                        CreateActionRow::InputText(address_input),
                    ]);

                let response = CreateInteractionResponse::Modal(modal);

                if let Err(e) = component.create_response(&ctx.http, response).await {
                    eprintln!("Error showing form: {:?}", e);
                }
            }
            return;
        }

        // Handle form submission
        if let Some(modal) = interaction.modal_submit() {
            if modal.data.custom_id == "onboarding_form" {
                // Extract form data
                let mut why_joined = String::new();
                let mut address = String::new();

                for row in &modal.data.components {
                    for comp in &row.components {
                        if let ActionRowComponent::InputText(input) = comp {
                            if input.custom_id.contains("Why did you join") || input.custom_id == "why_joined" {
                                why_joined = input.value.as_ref().map(|s| s.clone()).unwrap_or_default();
                            } else if input.custom_id.contains("Core Lane Address") || input.custom_id == "corelane_address" {
                                address = input.value.as_ref().map(|s| s.clone()).unwrap_or_default();
                            }
                        }
                    }
                }

                // Sanitize input
                let why_joined = why_joined.trim().to_string();
                let address = address.trim().to_string();

                // RESPOND IMMEDIATELY to avoid Discord timeout (must be within 3 seconds)
                let initial_msg = "**Processing your onboarding...**\n\nPlease wait while we verify and set up your account.";
                let response = CreateInteractionResponse::Message(
                    CreateInteractionResponseMessage::new()
                        .content(initial_msg)
                        .ephemeral(true),
                );

                if let Err(e) = modal.create_response(&ctx.http, response).await {
                    eprintln!("Error responding to form: {:?}", e);
                    return;
                }

                // Now do all the work in the background
                if let Some(guild_id) = modal.guild_id {
                    let ctx_clone = ctx.clone();
                    let modal_clone = modal.clone();
                    let member_role_id = self.member_role_id;
                    let admin_channel_id = self.admin_channel_id;
                    let funding_store_clone = self.funding_store.clone();
                    let faucet_clone = self.faucet.clone();
                    let faucet_error_msg = self.faucet_init_error.clone();
                    let user_id = modal.user.id;
                    let why_joined_clone = why_joined.clone();
                    let address_clone = address.clone();

                    tokio::spawn(async move {
                        // Get the guild member
                        let member = match guild_id.member(&ctx_clone.http, user_id).await {
                            Ok(m) => m,
                            Err(e) => {
                                eprintln!("Error getting member: {:?}", e);
                                let _ = modal_clone.create_followup(
                                    &ctx_clone.http,
                                    CreateInteractionResponseFollowup::new()
                                        .content("❌ Error: Could not retrieve your member information. Please contact an administrator.")
                                        .ephemeral(true)
                                ).await;
                                return;
                            }
                        };

                        // Check if user already has the role
                        if member.roles.contains(&member_role_id) {
                            let _ = modal_clone.create_followup(
                                &ctx_clone.http,
                                CreateInteractionResponseFollowup::new()
                                    .content("You are already verified! You have access to all channels.")
                                    .ephemeral(true)
                            ).await;
                            return;
                        }

                        // Assign the role
                        match member.add_role(&ctx_clone.http, member_role_id).await {
                            Ok(_) => {
                                println!("Assigned role {} to {}", member_role_id, member.user.name);

                                // Log to admin channel
                                if let Some(admin_channel) = admin_channel_id {
                                    let admin_message = format!(
                                        "**New Member Onboarded**\n\
                                        **User:** {} ({})\n\
                                        **Why they joined:** {}\n\
                                        **Core Lane Address:** {}",
                                        member.user.name,
                                        member.user.id,
                                        if why_joined_clone.is_empty() { "Not provided" } else { &why_joined_clone },
                                        if address_clone.is_empty() { "Not provided" } else { &address_clone },
                                    );

                                    if let Err(e) = admin_channel.say(&ctx_clone.http, admin_message).await {
                                        eprintln!("Failed to send admin onboarding message: {:?}", e);
                                    }
                                }

                                // Handle faucet - check balance BEFORE showing "Processing" message
                                let mut faucet_tx_hash: Option<alloy_primitives::B256> = None;
                                let mut faucet_error: Option<String> = None;
                                #[allow(unused_assignments)]
                                let mut needs_funding = false; // Track if user actually needs funds

                                if let Some(faucet) = &faucet_clone {
                                    // First check funding store
                                    match funding_store_clone.has_funded(user_id.get()).await {
                                        Ok(true) => {
                                            println!(
                                                "Faucet: user {} already funded in store, skipping",
                                                user_id
                                            );
                                            needs_funding = false;
                                        }
                                        Ok(false) => {
                                            if address_clone.is_empty() {
                                                eprintln!(
                                                    "Faucet: no address provided, skipping for user {}",
                                                    user_id
                                                );
                                                faucet_error = Some("No address provided".to_string());
                                                needs_funding = false;
                                            } else {
                                                // Check if address already has sufficient balance BEFORE showing processing message
                                                match address_clone.parse::<Address>() {
                                                    Ok(address) => {
                                                        match faucet.provider.get_balance(address).await {
                                                            Ok(balance) => {
                                                                // Check if balance is at least the expected amount
                                                                if balance >= faucet.amount {
                                                                    println!(
                                                                        "Faucet: address {} already has balance {} wei (>= {} wei), marking as funded without sending",
                                                                        address_clone, balance, faucet.amount
                                                                    );
                                                                    // Mark as funded since they already have the funds
                                                                    if let Err(e) = funding_store_clone
                                                                        .mark_funded(user_id.get())
                                                                        .await
                                                                    {
                                                                        eprintln!(
                                                                            "Faucet: could not mark funded: {:?}",
                                                                            e
                                                                        );
                                                                    }
                                                                    needs_funding = false; // Don't send funds, they already have them
                                                                } else {
                                                                    // Balance is less than expected, they need funding
                                                                    println!(
                                                                        "Faucet: address {} has balance {} wei (< {} wei), will send funds",
                                                                        address_clone, balance, faucet.amount
                                                                    );
                                                                    needs_funding = true;
                                                                }
                                                            }
                                                            Err(e) => {
                                                                eprintln!(
                                                                    "Faucet: could not check balance for address {}: {:?}",
                                                                    address_clone, e
                                                                );
                                                                // If balance check fails, assume they need funding (fail open)
                                                                needs_funding = true;
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        eprintln!("Faucet: invalid address {}: {:?}", address_clone, e);
                                                        faucet_error = Some("Invalid Core Lane address".to_string());
                                                        needs_funding = false;
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("Faucet: could not check funding store: {:?}", e);
                                            faucet_error = Some("Failed to check funding status".to_string());
                                            needs_funding = false;
                                        }
                                    }

                                    // Now show appropriate message based on whether funding is needed
                                    if needs_funding {
                                        // User needs funds - show processing message and send
                                        let success_msg = "**Onboarding Successful!**\n\nWelcome! You have been verified and given access to all channels.\n\nProcessing laneBTC faucet...";
                                        let _ = modal_clone.edit_response(
                                            &ctx_clone.http,
                                            EditInteractionResponse::new().content(success_msg)
                                        ).await;

                                        // Send funds
                                        println!(
                                            "Faucet: sending laneBTC to {} for user {}",
                                            address_clone, user_id
                                        );
                                        match faucet.send_funds(&address_clone).await {
                                            Ok(tx) => {
                                                println!("Faucet sent: tx hash {:?}", tx);
                                                faucet_tx_hash = Some(tx);
                                                if let Err(e) = funding_store_clone
                                                    .mark_funded(user_id.get())
                                                    .await
                                                {
                                                    eprintln!(
                                                        "Faucet: could not mark funded: {:?}",
                                                        e
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                eprintln!(
                                                    "Faucet error for user {}: {:?}",
                                                    user_id, e
                                                );
                                                faucet_error = Some(format!("Failed to send laneBTC: {}", e));
                                            }
                                        }
                                    } else {
                                        // User already has funds - show success without processing message
                                        let success_msg = "**Onboarding Successful!**\n\nWelcome! You have been verified and given access to all channels.";
                                        let _ = modal_clone.edit_response(
                                            &ctx_clone.http,
                                            EditInteractionResponse::new().content(success_msg)
                                        ).await;
                                    }
                                } else {
                                    // No faucet configured - show success message
                                    let success_msg = "**Onboarding Successful!**\n\nWelcome! You have been verified and given access to all channels.";
                                    let _ = modal_clone.edit_response(
                                        &ctx_clone.http,
                                        EditInteractionResponse::new().content(success_msg)
                                    ).await;
                                }

                                // Build and send follow-up message only if there's something to report
                                // (transaction sent, error occurred, or faucet not configured)
                                // Don't send message if user already had funds
                                if faucet_tx_hash.is_some() || faucet_error.is_some() || faucet_error_msg.is_some() {
                                    let followup_msg = if let Some(tx_hash) = faucet_tx_hash {
                                        format!(
                                            "✅ **laneBTC sent!** Transaction: `{:?}`",
                                            tx_hash
                                        )
                                    } else if let Some(err) = faucet_error {
                                        format!("⚠️ **Faucet issue:** {}", err)
                                    } else if let Some(init_err) = faucet_error_msg {
                                        format!("⚠️ **Faucet not configured:** {}", init_err)
                                    } else {
                                        "ℹ️ Faucet not configured. Please check environment variables: FAUCET_RPC_URL, FAUCET_PRIVATE_KEY, FAUCET_AMOUNT_WEI".to_string()
                                    };

                                    // Send follow-up message
                                    if let Err(e) = modal_clone
                                        .create_followup(&ctx_clone.http, CreateInteractionResponseFollowup::new().content(followup_msg).ephemeral(true))
                                        .await
                                    {
                                        eprintln!("Error sending follow-up message: {:?}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Error assigning role: {:?}", e);
                                eprintln!("User: {} ({})", member.user.name, member.user.id);
                                eprintln!("Role ID: {}", member_role_id);

                                let error_msg = format!(
                                    "❌ **Error assigning role.** Please contact an administrator.\n\nError: {}",
                                    e
                                );

                                let _ = modal_clone.create_followup(
                                    &ctx_clone.http,
                                    CreateInteractionResponseFollowup::new()
                                        .content(error_msg)
                                        .ephemeral(true)
                                ).await;
                            }
                        }
                    });
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    // Load environment variables
    dotenv::dotenv().ok();

    let token = std::env::var("DISCORD_TOKEN")
        .expect("Expected DISCORD_TOKEN in the environment");

    let member_role_id = std::env::var("MEMBER_ROLE_ID")
        .expect("Expected MEMBER_ROLE_ID in the environment")
        .parse::<u64>()
        .expect("MEMBER_ROLE_ID must be a valid u64");

    // Onboarding channel ID (where new members can see and interact)
    let onboarding_channel_id = std::env::var("ONBOARDING_CHANNEL_ID")
        .ok()
        .and_then(|id| id.parse::<u64>().ok())
        .map(ChannelId::new);

    if let Some(channel_id) = onboarding_channel_id {
        println!("Onboarding channel ID configured: {}", channel_id);
    } else {
        println!("WARNING: ONBOARDING_CHANNEL_ID not set - onboarding will not work properly");
    }

    // Admin channel ID (for sending onboarding responses to admins)
    let admin_channel_id = std::env::var("ADMIN_CHANNEL_ID")
        .ok()
        .and_then(|id| id.parse::<u64>().ok())
        .map(ChannelId::new);

    if let Some(channel_id) = admin_channel_id {
        println!("Admin channel ID configured: {}", channel_id);
    } else {
        println!("WARNING: ADMIN_CHANNEL_ID not set - admins will not see onboarding responses");
    }

    let funding_store = FundingStore::new_from_env()
        .await
        .expect("Failed to initialise funding store (check FUNDING_BACKEND and S3 settings)");

    let (faucet, faucet_init_error) = match Faucet::new_from_env().await {
        Ok(f) => {
            println!("Faucet configured: using FAUCET_RPC_URL and FAUCET_AMOUNT_WEI");
            (Some(f), None)
        }
        Err(e) => {
            let error_msg = format!("{:?}", e);
            eprintln!(
                "Faucet not configured or invalid: {}. Faucet will be disabled.",
                error_msg
            );
            (None, Some(error_msg))
        }
    };

    let intents = GatewayIntents::GUILD_MEMBERS
        | GatewayIntents::GUILDS
        | GatewayIntents::MESSAGE_CONTENT
        | GatewayIntents::GUILD_MESSAGES;

    let handler = Handler {
        member_role_id: RoleId::new(member_role_id),
        onboarding_channel_id,
        admin_channel_id,
        funding_store,
        faucet,
        faucet_init_error,
        _state: Arc::new(RwLock::new(HashMap::new())),
    };

    let mut client = Client::builder(&token, intents)
        .event_handler(handler)
        .await
        .expect("Error creating client");

    if let Err(why) = client.start().await {
        println!("Client error: {why:?}");
    }
}
