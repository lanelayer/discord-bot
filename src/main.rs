use serenity::all::*;
use serenity::async_trait;

struct Handler {
    member_role_id: RoleId,
    onboarding_channel_id: Option<ChannelId>,
    admin_channel_id: Option<ChannelId>,
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

                // Get the guild and check if user already has the role (idempotency guard)
                if let Some(guild_id) = modal.guild_id {
                    if let Ok(member) = guild_id.member(&ctx.http, modal.user.id).await {
                        // Check if user already has the role
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

                        // Assign the role
                        match member.add_role(&ctx.http, self.member_role_id).await {
                            Ok(_) => {
                                println!("Assigned role {} to {}", self.member_role_id, member.user.name);

                                // Log to admin channel
                                if let Some(admin_channel) = self.admin_channel_id {
                                    let admin_message = format!(
                                        "**New Member Onboarded**\n\
                                        **User:** {} ({})\n\
                                        **Why they joined:** {}\n\
                                        **Core Lane Address:** {}",
                                        member.user.name,
                                        member.user.id,
                                        if why_joined.is_empty() { "Not provided" } else { &why_joined },
                                        if address.is_empty() { "Not provided" } else { &address },
                                    );

                                    if let Err(e) = admin_channel.say(&ctx.http, admin_message).await {
                                        eprintln!("Failed to send admin onboarding message: {:?}", e);
                                    }
                                }

                                // Success response
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

                                if let Err(send_err) = modal.create_response(&ctx.http, response).await {
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

    let intents = GatewayIntents::GUILD_MEMBERS
        | GatewayIntents::GUILDS
        | GatewayIntents::MESSAGE_CONTENT
        | GatewayIntents::GUILD_MESSAGES;

    let handler = Handler {
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
