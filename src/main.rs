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
use s3::creds::Credentials;
use s3::{Bucket, Region};
use std::str::FromStr;

type OnboardingState = Arc<RwLock<HashMap<u64, (Option<String>, Option<String>)>>>;

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
    provider_url: url::Url,
    signer: PrivateKeySigner,
    amount: U256,
    chain_id: u64,
    http_client: reqwest::Client,
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

        Ok(Self {
            provider_url,
            signer,
            amount,
            chain_id,
            http_client: reqwest::Client::new(),
            nonce_tracker: Arc::new(Mutex::new(None)),
        })
    }

    async fn rpc_call(&self, method: &str, params: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        });

        let response = self.http_client
            .post(self.provider_url.as_str())
            .json(&payload)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("RPC request failed: {}", e))?;

        let status = response.status();
        if !status.is_success() {
            return Err(anyhow::anyhow!("RPC error: HTTP {} with empty body", status));
        }

        let json: serde_json::Value = response.json().await
            .map_err(|e| anyhow::anyhow!("Failed to parse RPC response: {}", e))?;

        if let Some(error) = json.get("error") {
            return Err(anyhow::anyhow!("RPC error: {}", error));
        }

        json.get("result")
            .ok_or_else(|| anyhow::anyhow!("RPC response missing 'result' field"))
            .map(|v| v.clone())
    }

    async fn get_balance(&self, address: Address) -> anyhow::Result<U256> {
        let params = serde_json::json!([format!("{}", address), "latest"]);
        let result = self.rpc_call("eth_getBalance", params).await?;
        let balance_str = result.as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid balance response"))?;
        let balance = U256::from_str_radix(&balance_str[2..], 16)
            .map_err(|e| anyhow::anyhow!("Failed to parse balance: {}", e))?;
        Ok(balance)
    }

    async fn get_transaction_count(&self, address: Address) -> anyhow::Result<u64> {
        let params = serde_json::json!([format!("{}", address), "latest"]);
        let result = self.rpc_call("eth_getTransactionCount", params).await?;
        let nonce_str = result.as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid nonce response"))?;
        let nonce = u64::from_str_radix(&nonce_str[2..], 16)
            .map_err(|e| anyhow::anyhow!("Failed to parse nonce: {}", e))?;
        Ok(nonce)
    }

    async fn get_gas_price(&self) -> anyhow::Result<U256> {
        let result = self.rpc_call("eth_gasPrice", serde_json::json!([])).await?;
        let gas_str = result.as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid gas price response"))?;
        let gas = U256::from_str_radix(&gas_str[2..], 16)
            .map_err(|e| anyhow::anyhow!("Failed to parse gas price: {}", e))?;
        Ok(gas)
    }

    async fn send_raw_transaction(&self, tx_hex: &str) -> anyhow::Result<alloy_primitives::B256> {
        let params = serde_json::json!([tx_hex]);
        let result = self.rpc_call("eth_sendRawTransaction", params).await?;
        let tx_hash_str = result.as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid tx hash response"))?;
        let tx_hash = alloy_primitives::B256::from_str(&tx_hash_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse tx hash: {}", e))?;
        Ok(tx_hash)
    }

    async fn get_transaction_receipt(&self, tx_hash: &alloy_primitives::B256) -> anyhow::Result<Option<serde_json::Value>> {
        let params = serde_json::json!([format!("0x{}", hex::encode(tx_hash.as_slice()))]);
        let result = self.rpc_call("eth_getTransactionReceipt", params).await?;
        if result.is_null() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    async fn send_funds(&self, to_addr: &str) -> anyhow::Result<alloy_primitives::B256> {
        let to: Address = to_addr.parse().context("Invalid Core Lane address")?;
        let from = self.signer.address();

        println!("Faucet: Checking balance for {:?}", from);
        let balance = self.get_balance(from).await?;
        println!("Faucet: Current balance: {} wei", balance);

        // Calculate required amount: transfer amount + gas (21000 * gas_price)
        let gas_limit = U256::from(21000u64);
        let gas_price = self.get_gas_price().await?;
        let gas_cost = gas_limit * gas_price;
        let total_required = self.amount + gas_cost;

        if balance < total_required {
            return Err(anyhow::anyhow!(
                "Insufficient balance: have {} wei, need {} wei (amount: {} + gas: {})",
                balance, total_required, self.amount, gas_cost
            ));
        }

        // Use configured chain ID (Core Lane: 1281453634)
        let chain_id = self.chain_id;

        // Get nonce with proper management
        // Always use the on-chain nonce to avoid conflicts with pending transactions
        let nonce = {
            let on_chain_nonce = self.get_transaction_count(from).await
                .map_err(|e| anyhow::anyhow!("Failed to get transaction count: {}", e))?;

            // Check if we have a tracked nonce that's higher (shouldn't happen, but safety check)
            let tracker = self.nonce_tracker.lock().await;
            let next_nonce = if let Some(tracked) = *tracker {
                // Use the higher of on-chain or tracked+1, but prefer on-chain for safety
                if on_chain_nonce > tracked {
                    on_chain_nonce
                } else {
                    tracked + 1
                }
            } else {
                on_chain_nonce
            };

            println!("Faucet: Using nonce {} (on-chain: {}, tracked: {:?})",
                next_nonce, on_chain_nonce, *tracker);
            next_nonce
        };

        // For EIP-1559, use gas price as max_fee_per_gas and 10% as max_priority_fee_per_gas
        let max_fee_per_gas = gas_price.to::<u128>();
        let max_priority_fee_per_gas = (gas_price / U256::from(10)).to::<u128>();

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
        let tx_hex = format!("0x{}", hex::encode(&encoded));

        println!("Faucet: Broadcasting transaction...");
        // Send the raw transaction using direct RPC
        let tx_hash = self.send_raw_transaction(&tx_hex).await
            .map_err(|e| anyhow::anyhow!("Failed to send transaction: {}", e))?;

        println!("Faucet: Transaction broadcast: {:?}", tx_hash);

        // Wait for transaction confirmation
        println!("Faucet: Waiting for transaction confirmation...");
        let mut confirmed = false;
        for i in 0..30 {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            if let Ok(Some(receipt)) = self.get_transaction_receipt(&tx_hash).await {
                let status = receipt.get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");
                println!("Faucet: Transaction receipt received, status: {}", status);
                if status == "0x1" || status == "0x01" {
                    println!("Faucet: Transaction confirmed successfully!");
                    confirmed = true;
                    // Update nonce tracker only after successful confirmation
                    let mut tracker = self.nonce_tracker.lock().await;
                    *tracker = Some(nonce);
                    println!("Faucet: Updated nonce tracker to {}", nonce);
                    break;
                } else {
                    return Err(anyhow::anyhow!("Transaction failed on-chain: status {}", status));
                }
            }
            if i == 29 {
                println!("Faucet: Warning: Transaction not confirmed after 30 seconds");
            }
        }

        if !confirmed {
            return Err(anyhow::anyhow!("Transaction not confirmed within timeout period"));
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

                                // Update the initial message with success
                                let success_msg = "**Onboarding Successful!**\n\nWelcome! You have been verified and given access to all channels.\n\nProcessing laneBTC faucet...";
                                let _ = modal_clone.edit_response(
                                    &ctx_clone.http,
                                    EditInteractionResponse::new().content(success_msg)
                                ).await;

                                // Handle faucet
                                let mut faucet_tx_hash: Option<alloy_primitives::B256> = None;
                                let mut faucet_error: Option<String> = None;

                                if let Some(faucet) = &faucet_clone {
                                    match funding_store_clone.has_funded(user_id.get()).await {
                                        Ok(true) => {
                                            println!(
                                                "Faucet: user {} already funded, skipping",
                                                user_id
                                            );
                                        }
                                        Ok(false) => {
                                            if address_clone.is_empty() {
                                                eprintln!(
                                                    "Faucet: no address provided, skipping for user {}",
                                                    user_id
                                                );
                                                faucet_error = Some("No address provided".to_string());
                                            } else {
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
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("Faucet: could not check funding store: {:?}", e);
                                            faucet_error = Some("Failed to check funding status".to_string());
                                        }
                                    }
                                }

                                // Build follow-up message
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
