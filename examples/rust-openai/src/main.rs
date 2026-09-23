use async_openai::{
    Client,
    config::OpenAIConfig,
    middleware::ReqwestService,
    types::chat::{ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequestArgs},
};
use futures_util::StreamExt as _;
use std::{io::Write as _, time::Duration};
use stogas::{Transport, TransportOptions};

fn client(base_url: &str, api_key: &str) -> anyhow::Result<Client<OpenAIConfig>> {
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(45 * 60))
        .build()?;
    let config = OpenAIConfig::new()
        .with_api_base(base_url)
        .with_api_key(api_key);
    // A plain service also disables async-openai's own retry layer.
    Ok(Client::with_config(config).with_http_service(ReqwestService::new(http)))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let api_key = std::env::var("STOGAS_API_KEY")?;
    let model = std::env::var("STOGAS_MODEL")?;
    let mut transport = Transport::start(&TransportOptions::default())?;
    let result = async {
        let client = client(transport.base_url(), &api_key)?;
        let request = CreateChatCompletionRequestArgs::default()
            .model(model)
            .messages([ChatCompletionRequestUserMessageArgs::default()
                .content("Say hello in one sentence.")
                .build()?
                .into()])
            .build()?;
        let mut stream = client.chat().create_stream(request).await?;
        loop {
            tokio::select! {
                chunk = stream.next() => {
                    let Some(chunk) = chunk else { break };
                    for choice in chunk?.choices {
                        if let Some(text) = choice.delta.content {
                            print!("{text}");
                            std::io::stdout().flush()?;
                        }
                    }
                }
                signal = tokio::signal::ctrl_c() => {
                    signal?;
                    anyhow::bail!("cancelled; delivery is incomplete");
                }
            }
        }
        println!();
        Ok(())
    }
    .await;
    transport.close();
    result
}

#[cfg(test)]
mod tests;
