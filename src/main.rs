use serenity::all::*;
use serenity::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// Store onboarding state: user_id -> (why_joined, corelane_address)
type OnboardingState = Arc<RwLock<HashMap<u64, (Option<String>, Option<String>)>>>;

struct Handler {
    onboarding_state: OnboardingState,
    member_role_id: RoleId,
    onboarding_channel_id: Option<ChannelId>,
    admin_channel_id: Option<ChannelId>,
}

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, ctx: Context, ready: Ready) {
        println!("✅ Bot is ready! Logged in as: {}", ready.user.name);

        // Clean up old bot messages in onboarding channel on startup
        if let Some(onboarding_channel) = self.onboarding_channel_id {
            let retriever = GetMessages::new().limit(100);
            if let Ok(messages) = onboarding_channel.messages(&ctx.http, retriever).await {
                let bot_id = ready.user.id;
                let mut deleted_count = 0;
                for msg in messages {
                    // Delete ALL messages from this bot
                    if msg.author.id == bot_id {
                        if let Err(e) = msg.delete(&ctx.http).await {
                            eprintln!("⚠️  Could not delete old message {}: {:?}", msg.id, e);
                        } else {
                            deleted_count += 1;
                        }
                    }
                }
                if deleted_count > 0 {
                    println!("🧹 Deleted {} old bot message(s) on startup", deleted_count);
                }
            }
        }
    }

    async fn guild_member_removal(&self, _ctx: Context, _guild_id: GuildId, user: User, _member: Option<Member>) {
        println!("Member left: {} ({})", user.name, user.id);

        // Clean up onboarding state
        {
            let mut state = self.onboarding_state.write().await;
            state.remove(&user.id.get());
        }
    }

    async fn guild_member_addition(&self, ctx: Context, new_member: Member) {
        println!("New member joined: {} ({})", new_member.user.name, new_member.user.id);

        // Always create onboarding thread - don't check for role
        // If they already have the role and complete onboarding, they'll just get it again (no harm)
        println!("✅ Proceeding with onboarding for {}", new_member.user.name);

        // Initialize onboarding state for this user
        {
            let mut state = self.onboarding_state.write().await;
            state.insert(new_member.user.id.get(), (None, None));
        }

        // Create welcome message with button in onboarding channel (generic, no @nickname)
        if let Some(onboarding_channel) = self.onboarding_channel_id {
            // Delete ALL old messages from this bot first (clean slate)
            let retriever = GetMessages::new().limit(100);
            if let Ok(messages) = onboarding_channel.messages(&ctx.http, retriever).await {
                let bot_id = ctx.cache.current_user().id;
                let mut deleted_count = 0;
                for msg in messages {
                    // Delete ALL messages from this bot
                    if msg.author.id == bot_id {
                        if let Err(e) = msg.delete(&ctx.http).await {
                            eprintln!("⚠️  Could not delete old message {}: {:?}", msg.id, e);
                        } else {
                            deleted_count += 1;
                        }
                    }
                }
                if deleted_count > 0 {
                    println!("🧹 Deleted {} old bot message(s) before creating new welcome message", deleted_count);
                }
            }

            // Create welcome message with button (generic, no @nickname)
            let components = vec![CreateActionRow::Buttons(vec![
                CreateButton::new("start_onboarding")
                    .label("Start Onboarding")
                    .style(ButtonStyle::Primary),
            ])];

            let welcome_message = "Welcome to the server! 👋\n\nPlease click the button below to start the onboarding process. You'll need to fill out a form with:\n1. Why you joined\n2. Your Corelane address\n\nOnce complete, you'll get access to all channels!";

            let message = CreateMessage::new()
                .content(welcome_message)
                .components(components);

            // Create the welcome message
            match onboarding_channel.send_message(&ctx.http, message).await {
                Ok(_) => {
                    println!("✅ Created welcome message in onboarding channel for new user");
                }
                Err(e) => {
                    eprintln!("❌ Could not create welcome message in onboarding channel: {:?}", e);
                    eprintln!("   Make sure the bot has 'Send Messages' permission");
                    eprintln!("   Channel ID: {}", onboarding_channel);
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
                    "Corelane Address",  // This becomes the custom_id
                    "Corelane Address",  // This is the label
                )
                .required(true)
                .placeholder("Enter your Corelane address...")
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
                // Note: Discord uses the label as custom_id, so we need to match by label text
                let mut why_joined = String::new();
                let mut address = String::new();

                for row in &modal.data.components {
                    for comp in &row.components {
                        if let ActionRowComponent::InputText(input) = comp {
                            // Discord sends the label as custom_id, so match by label text
                            if input.custom_id.contains("Why did you join") || input.custom_id == "why_joined" {
                                why_joined = input.value.as_ref().map(|s| s.clone()).unwrap_or_default();
                            } else if input.custom_id.contains("Corelane Address") || input.custom_id == "corelane_address" {
                                address = input.value.as_ref().map(|s| s.clone()).unwrap_or_default();
                            }
                        }
                    }
                }

                println!("Extracted - why_joined: '{}', address: '{}'", why_joined, address);

                // Store the data
                {
                    let mut state = self.onboarding_state.write().await;
                    state.insert(modal.user.id.get(), (Some(why_joined.clone()), Some(address.clone())));
                }

                // Get the guild and assign the role
                if let Some(guild_id) = modal.guild_id {
                    if let Ok(member) = guild_id.member(&ctx.http, modal.user.id).await {
                        match member.add_role(&ctx.http, self.member_role_id).await {
                            Ok(_) => {
                                println!("✅ Successfully assigned role {} to {}", self.member_role_id, member.user.name);

                                // Log onboarding data
                                println!("**New Member Onboarded**");
                                println!("   User: {} ({})", member.user.name, member.user.id);
                                println!("   Why joined: {}", if why_joined.is_empty() { "Not provided" } else { &why_joined });
                                println!("   Address: {}", address);

                                // Send onboarding data to admin channel so admins can see the responses
                                if let Some(admin_channel) = self.admin_channel_id {
                                    let admin_message = format!(
                                        "**New Member Onboarded**\n\
                                        **User:** {} ({})\n\
                                        **Why they joined:** {}\n\
                                        **Corelane Address:** {}",
                                        member.user.name,
                                        member.user.id,
                                        if why_joined.is_empty() { "Not provided" } else { &why_joined },
                                        address
                                    );

                                    match admin_channel.say(&ctx.http, admin_message).await {
                                        Ok(_) => println!("✅ Posted onboarding data to admin channel"),
                                        Err(e) => {
                                            eprintln!("❌ Error sending to admin channel {}: {:?}", admin_channel, e);
                                        }
                                    }
                                }

                                // Success response - simple confirmation like Cartesi bot
                                let response = CreateInteractionResponse::Message(
                                    CreateInteractionResponseMessage::new()
                                        .content(format!(
                                            "**Onboarding Successful!**\n\nWelcome to the server {}! You have been verified and given access to all channels.",
                                            member.user.mention()
                                        ))
                                        .ephemeral(true),
                                );

                                if let Err(e) = modal.create_response(&ctx.http, response).await {
                                    eprintln!("Error responding to form: {:?}", e);
                                }

                                // Clean up state
                                {
                                    let mut state = self.onboarding_state.write().await;
                                    state.remove(&modal.user.id.get());
                                }
                            }
                            Err(e) => {
                                eprintln!("❌ Error assigning role: {:?}", e);
                                eprintln!("   User: {} ({})", member.user.name, member.user.id);
                                eprintln!("   Role ID: {}", self.member_role_id);
                                eprintln!("   Make sure:");
                                eprintln!("   1. Bot has 'Manage Roles' permission");
                                eprintln!("   2. Bot's role is higher than the role being assigned");
                                eprintln!("   3. The role ID {} is correct", self.member_role_id);

                                let error_msg = format!(
                                    "❌ Error assigning role. Please contact an administrator.\n\nError: {}",
                                    e
                                );

                                let response = CreateInteractionResponse::Message(
                                    CreateInteractionResponseMessage::new()
                                        .content(error_msg)
                                        .ephemeral(true),
                                );

                                if let Err(send_err) = modal.create_response(&ctx.http, response).await {
                                    eprintln!("   Also failed to send error message: {:?}", send_err);
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
        println!("✅ Onboarding channel ID configured: {}", channel_id);
    } else {
        println!("⚠️  WARNING: ONBOARDING_CHANNEL_ID not set - onboarding will not work properly");
    }

    // Admin channel ID (for sending onboarding responses to admins)
    let admin_channel_id = std::env::var("ADMIN_CHANNEL_ID")
        .ok()
        .and_then(|id| id.parse::<u64>().ok())
        .map(ChannelId::new);

    if let Some(channel_id) = admin_channel_id {
        println!("✅ Admin channel ID configured: {}", channel_id);
    } else {
        println!("⚠️  WARNING: ADMIN_CHANNEL_ID not set - admins will not see onboarding responses");
    }

    let intents = GatewayIntents::GUILD_MEMBERS
        | GatewayIntents::GUILDS
        | GatewayIntents::MESSAGE_CONTENT
        | GatewayIntents::GUILD_MESSAGES;

    let handler = Handler {
        onboarding_state: Arc::new(RwLock::new(HashMap::new())),
        member_role_id: RoleId::new(member_role_id),
        onboarding_channel_id,
        admin_channel_id,
    };

    let mut client = Client::builder(&token, intents)
        .event_handler(handler)
        .await
        .expect("Error creating client");

    if let Err(why) = client.start().await {
        println!("Client error: {why:?}");
    }
}
