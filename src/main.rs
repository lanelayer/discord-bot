use serenity::all::*;
use serenity::async_trait;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

use anyhow::Context as AnyhowContext;
use ethers::prelude::*;
use ethers::providers::{Http, Provider};
use ethers::signers::Wallet;
use s3::creds::Credentials;
use s3::{Bucket, Region};

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
                    Err(s3::error::S3Error::Http(code, _)) if code == 404 => Ok(false),
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
    provider: Provider<Http>,
    wallet: Wallet<k256::ecdsa::SigningKey>,
    amount: U256,
}

impl Faucet {
    async fn new_from_env() -> anyhow::Result<Self> {
        let rpc_url =
            std::env::var("FAUCET_RPC_URL").context("FAUCET_RPC_URL is required for faucet")?;
        let private_key = std::env::var("FAUCET_PRIVATE_KEY")
            .context("FAUCET_PRIVATE_KEY is required for faucet")?;
        let amount_str = std::env::var("FAUCET_AMOUNT_WEI")
            .context("FAUCET_AMOUNT_WEI is required for faucet")?;
        let amount = U256::from_dec_str(&amount_str)
            .context("FAUCET_AMOUNT_WEI must be a decimal number")?;
        let chain_id = std::env::var("FAUCET_CHAIN_ID")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);

        let provider =
            Provider::<Http>::try_from(rpc_url.clone()).context("Invalid FAUCET_RPC_URL")?;
        let wallet = private_key
            .parse::<LocalWallet>()
            .context("Invalid FAUCET_PRIVATE_KEY")?;
        let wallet = if chain_id != 0 {
            wallet.with_chain_id(chain_id)
        } else {
            wallet
        };

        Ok(Self {
            provider,
            wallet,
            amount,
        })
    }

    async fn send_funds(&self, to_addr: &str) -> anyhow::Result<TxHash> {
        let to: H160 = to_addr.parse().context("Invalid Core Lane address")?;

        let client = SignerMiddleware::new(self.provider.clone(), self.wallet.clone());
        let pending = client
            .send_transaction(
                TransactionRequest::pay(Address::from(to), self.amount),
                None,
            )
            .await?;
        let receipt = pending.await?;
        receipt
            .map(|r| r.transaction_hash)
            .ok_or_else(|| anyhow::anyhow!("No transaction hash returned"))
    }
}

struct Handler {
    member_role_id: RoleId,
    onboarding_channel_id: Option<ChannelId>,
    admin_channel_id: Option<ChannelId>,
    funding_store: FundingStore,
    faucet: Option<Faucet>,
    _state: OnboardingState,
}

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, ctx: Context, ready: Ready) {
        println!("Bot is ready! Logged in as: {}", ready.user.name);

        if self.onboarding_channel_id.is_none() {
            eprintln!("WARNING: ONBOARDING_CHANNEL_ID not set - onboarding will not work");
        }
        if self.admin_channel_id.is_none() {
            eprintln!(
                "WARNING: ADMIN_CHANNEL_ID not set - admins will not see onboarding responses"
            );
        }

        // Ensure pinned welcome message exists
        if let Some(onboarding_channel) = self.onboarding_channel_id {
            let bot_id = ready.user.id;
            let welcome_message = "Welcome!\n\nPlease click the button below to start the onboarding process. You'll need to fill out a form with:\n1. Why you joined\n2. Your Core Lane address\n\nOnce complete, you'll get access to all channels!";

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

            if !has_welcome_message {
                let components = vec![CreateActionRow::Buttons(vec![CreateButton::new(
                    "start_onboarding",
                )
                .label("Start Onboarding")
                .style(ButtonStyle::Primary)])];

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
                let why_input = CreateInputText::new(
                    InputTextStyle::Paragraph,
                    "Why did you join our server?", // custom_id
                    "Why did you join our server?", // label
                )
                .required(true)
                .placeholder("Please tell us why you joined...")
                .max_length(500);

                let address_input = CreateInputText::new(
                    InputTextStyle::Short,
                    "Core Lane Address", // custom_id
                    "Core Lane Address", // label
                )
                .required(true)
                .placeholder("Enter your Core Lane address...")
                .max_length(100);

                let modal =
                    CreateModal::new("onboarding_form", "Onboarding Form").components(vec![
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
                let mut why_joined = String::new();
                let mut address = String::new();

                for row in &modal.data.components {
                    for comp in &row.components {
                        if let ActionRowComponent::InputText(input) = comp {
                            if input.custom_id.contains("Why did you join")
                                || input.custom_id == "why_joined"
                            {
                                why_joined =
                                    input.value.as_ref().map(|s| s.clone()).unwrap_or_default();
                            } else if input.custom_id.contains("Core Lane Address")
                                || input.custom_id == "corelane_address"
                            {
                                address =
                                    input.value.as_ref().map(|s| s.clone()).unwrap_or_default();
                            }
                        }
                    }
                }

                let why_joined = why_joined.trim().to_string();
                let address = address.trim().to_string();

                if let Some(guild_id) = modal.guild_id {
                    if let Ok(member) = guild_id.member(&ctx.http, modal.user.id).await {
                        if member.roles.contains(&self.member_role_id) {
                            let response = CreateInteractionResponse::Message(
                                CreateInteractionResponseMessage::new()
                                    .content("You are already verified! You have access to all channels.")
                                    .ephemeral(true),
                            );
                            if let Err(e) = modal.create_response(&ctx.http, response).await {
                                eprintln!("Error responding to already-verified user: {:?}", e);
                            }
                            return;
                        }

                        // Faucet: attempt only once per Discord account
                        if let Some(faucet) = &self.faucet {
                            match self.funding_store.has_funded(member.user.id.get()).await {
                                Ok(true) => {
                                    println!(
                                        "Faucet: user {} already funded, skipping",
                                        member.user.id
                                    );
                                }
                                Ok(false) => {
                                    if address.is_empty() {
                                        eprintln!(
                                            "Faucet: no address provided, skipping for user {}",
                                            member.user.id
                                        );
                                    } else {
                                        println!(
                                            "Faucet: sending to {} for user {}",
                                            address, member.user.id
                                        );
                                        match faucet.send_funds(&address).await {
                                            Ok(tx) => {
                                                println!("Faucet sent: tx hash {:?}", tx);
                                                if let Err(e) = self
                                                    .funding_store
                                                    .mark_funded(member.user.id.get())
                                                    .await
                                                {
                                                    eprintln!(
                                                        "Faucet: could not mark funded: {:?}",
                                                        e
                                                    );
                                                }
                                            }
                                            Err(e) => eprintln!(
                                                "Faucet error for user {}: {:?}",
                                                member.user.id, e
                                            ),
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Faucet: could not check funding store: {:?}", e)
                                }
                            }
                        }

                        // Assign the role
                        match member.add_role(&ctx.http, self.member_role_id).await {
                            Ok(_) => {
                                println!(
                                    "Assigned role {} to {}",
                                    self.member_role_id, member.user.name
                                );

                                if let Some(admin_channel) = self.admin_channel_id {
                                    let admin_message = format!(
                                        "**New Member Onboarded**\n\
                                        **User:** {} ({})\n\
                                        **Why they joined:** {}\n\
                                        **Core Lane Address:** {}",
                                        member.user.name,
                                        member.user.id,
                                        if why_joined.is_empty() {
                                            "Not provided"
                                        } else {
                                            &why_joined
                                        },
                                        if address.is_empty() {
                                            "Not provided"
                                        } else {
                                            &address
                                        },
                                    );

                                    if let Err(e) =
                                        admin_channel.say(&ctx.http, admin_message).await
                                    {
                                        eprintln!(
                                            "Failed to send admin onboarding message: {:?}",
                                            e
                                        );
                                    }
                                }

                                let response = CreateInteractionResponse::Message(
                                    CreateInteractionResponseMessage::new()
                                        .content("**Onboarding Successful!**\n\nWelcome! You have been verified and given access to all channels.")
                                        .ephemeral(true),
                                );

                                if let Err(e) = modal.create_response(&ctx.http, response).await {
                                    eprintln!("Error responding to form: {:?}", e);
                                }
                            }
                            Err(e) => {
                                eprintln!("Error assigning role: {:?}", e);
                                eprintln!("User: {} ({})", member.user.name, member.user.id);
                                eprintln!("Role ID: {}", self.member_role_id);

                                let error_msg = format!(
                                    "Error assigning role. Please contact an administrator.\n\nError: {}",
                                    e
                                );

                                let response = CreateInteractionResponse::Message(
                                    CreateInteractionResponseMessage::new()
                                        .content(error_msg)
                                        .ephemeral(true),
                                );

                                if let Err(send_err) =
                                    modal.create_response(&ctx.http, response).await
                                {
                                    eprintln!("Failed to send error message: {:?}", send_err);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    let token = std::env::var("DISCORD_TOKEN").expect("Expected DISCORD_TOKEN in the environment");

    let member_role_id = std::env::var("MEMBER_ROLE_ID")
        .expect("Expected MEMBER_ROLE_ID in the environment")
        .parse::<u64>()
        .expect("MEMBER_ROLE_ID must be a valid u64");

    let onboarding_channel_id = std::env::var("ONBOARDING_CHANNEL_ID")
        .ok()
        .and_then(|id| id.parse::<u64>().ok())
        .map(ChannelId::new);

    if let Some(channel_id) = onboarding_channel_id {
        println!("Onboarding channel ID configured: {}", channel_id);
    } else {
        println!("WARNING: ONBOARDING_CHANNEL_ID not set - onboarding will not work properly");
    }

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

    let faucet = match Faucet::new_from_env().await {
        Ok(f) => {
            println!("Faucet configured: using FAUCET_RPC_URL and FAUCET_AMOUNT_WEI");
            Some(f)
        }
        Err(e) => {
            eprintln!(
                "Faucet not configured or invalid: {:?}. Faucet will be disabled.",
                e
            );
            None
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
