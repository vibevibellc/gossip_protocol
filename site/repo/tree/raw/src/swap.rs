use std::{fs, path::Path};

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::protocol::{
    MICRO_HT, SettlementAsset, SignedSwapQuote, SwapExecutionPlan, SwapQuote, SwapQuoteRequest,
    SwapSide, new_request_id, validate_swap_quote_request,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SwapAdapterConfig {
    FixedRate {
        id: String,
        settlement_asset: SettlementAsset,
        micro_asset_per_token: u64,
        settlement_decimals: u8,
        instructions: Vec<String>,
    },
    HttpBridge {
        id: String,
        settlement_asset: SettlementAsset,
        quote_url: String,
        execution_url: String,
        auth_header_name: Option<String>,
        auth_header_value: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SwapConfigFile {
    #[serde(default)]
    pub adapters: Vec<SwapAdapterConfig>,
}

#[async_trait]
pub trait SwapAdapter: Send + Sync {
    fn id(&self) -> &str;
    fn settlement_asset(&self) -> &SettlementAsset;
    async fn quote(&self, request: &SwapQuoteRequest) -> Result<SwapQuote>;
    async fn execution_plan(&self, quote: &SignedSwapQuote) -> Result<SwapExecutionPlan>;
}

pub struct SwapRegistry {
    adapters: Vec<Box<dyn SwapAdapter>>,
}

impl SwapRegistry {
    pub fn from_optional_file(path: Option<&Path>) -> Result<Self> {
        let mut adapters: Vec<Box<dyn SwapAdapter>> = Vec::new();
        adapters.push(Box::new(FixedRateSwapAdapter {
            id: "fixed-usdc-demo".into(),
            settlement_asset: SettlementAsset::Usdc,
            micro_asset_per_token: 1_000_000,
            settlement_decimals: 6,
            instructions: vec![
                "Send USDC to your configured treasury or OTC desk.".into(),
                "After settlement clears, transfer HT from the treasury wallet to the buyer address.".into(),
            ],
        }));
        adapters.push(Box::new(FixedRateSwapAdapter {
            id: "fixed-usdt-demo".into(),
            settlement_asset: SettlementAsset::Usdt,
            micro_asset_per_token: 1_000_000,
            settlement_decimals: 6,
            instructions: vec![
                "Send USDT to your configured treasury or OTC desk.".into(),
                "After settlement clears, transfer HT from the treasury wallet to the buyer address.".into(),
            ],
        }));

        if let Some(path) = path {
            let contents = fs::read_to_string(path)
                .with_context(|| format!("failed to read swap config {}", path.display()))?;
            let config: SwapConfigFile = serde_json::from_str(&contents)?;
            for adapter in config.adapters {
                adapters.push(adapter.into_adapter()?);
            }
        }

        Ok(Self { adapters })
    }

    pub fn adapter_ids(&self) -> Vec<String> {
        self.adapters
            .iter()
            .map(|adapter| adapter.id().to_string())
            .collect()
    }

    pub async fn quote(&self, request: &SwapQuoteRequest) -> Result<SwapQuote> {
        validate_swap_quote_request(request)?;
        let adapter = if let Some(adapter_id) = &request.adapter {
            self.adapters
                .iter()
                .find(|adapter| adapter.id() == adapter_id)
                .ok_or_else(|| anyhow::anyhow!("unknown adapter {adapter_id}"))?
        } else {
            self.adapters
                .iter()
                .find(|adapter| adapter.settlement_asset() == &request.settlement_asset)
                .ok_or_else(|| {
                    anyhow::anyhow!("no adapter available for {:?}", request.settlement_asset)
                })?
        };

        adapter.quote(request).await
    }

    pub async fn execution_plan(&self, quote: &SignedSwapQuote) -> Result<SwapExecutionPlan> {
        let adapter = self
            .adapters
            .iter()
            .find(|adapter| adapter.id() == quote.quote.adapter)
            .ok_or_else(|| anyhow::anyhow!("unknown adapter {}", quote.quote.adapter))?;
        adapter.execution_plan(quote).await
    }
}

impl SwapAdapterConfig {
    fn into_adapter(self) -> Result<Box<dyn SwapAdapter>> {
        match self {
            SwapAdapterConfig::FixedRate {
                id,
                settlement_asset,
                micro_asset_per_token,
                settlement_decimals,
                instructions,
            } => Ok(Box::new(FixedRateSwapAdapter {
                id,
                settlement_asset,
                micro_asset_per_token,
                settlement_decimals,
                instructions,
            })),
            SwapAdapterConfig::HttpBridge {
                id,
                settlement_asset,
                quote_url,
                execution_url,
                auth_header_name,
                auth_header_value,
            } => Ok(Box::new(HttpBridgeSwapAdapter {
                id,
                settlement_asset,
                quote_url,
                execution_url,
                auth_header_name,
                auth_header_value,
                client: reqwest::Client::new(),
            })),
        }
    }
}

struct FixedRateSwapAdapter {
    id: String,
    settlement_asset: SettlementAsset,
    micro_asset_per_token: u64,
    settlement_decimals: u8,
    instructions: Vec<String>,
}

#[async_trait]
impl SwapAdapter for FixedRateSwapAdapter {
    fn id(&self) -> &str {
        &self.id
    }

    fn settlement_asset(&self) -> &SettlementAsset {
        &self.settlement_asset
    }

    async fn quote(&self, request: &SwapQuoteRequest) -> Result<SwapQuote> {
        let settlement_amount = request
            .token_amount
            .checked_mul(self.micro_asset_per_token)
            .and_then(|value| value.checked_div(MICRO_HT))
            .ok_or_else(|| anyhow::anyhow!("swap amount overflow"))?;
        Ok(SwapQuote {
            chain_id: String::new(),
            quote_id: new_request_id(),
            wallet: request.wallet.clone(),
            adapter: self.id.clone(),
            side: request.side.clone(),
            settlement_asset: request.settlement_asset.clone(),
            token_amount: request.token_amount,
            settlement_amount,
            settlement_decimals: self.settlement_decimals,
            expires_at: Utc::now() + Duration::seconds(request.ttl_secs as i64),
            notes: vec![
                "This adapter does not touch USDC/USDT rails directly.".into(),
                "Use the execution plan as a settlement hand-off to your own desk, bridge, or exchange flow.".into(),
            ],
        })
    }

    async fn execution_plan(&self, quote: &SignedSwapQuote) -> Result<SwapExecutionPlan> {
        let direction = match quote.quote.side {
            SwapSide::Buy => "buy HT with the settlement asset",
            SwapSide::Sell => "sell HT for the settlement asset",
        };
        let mut steps = vec![format!(
            "Use adapter {} to {direction} without embedding any external stablecoin protocol client.",
            self.id
        )];
        if quote.quote.side == SwapSide::Sell {
            steps.push(
                "Lock HT on-chain against the signed quote before releasing the off-chain settlement leg."
                    .into(),
            );
        }
        steps.extend(self.instructions.clone());
        Ok(SwapExecutionPlan {
            quote: quote.clone(),
            steps,
            follow_up_transfer_hint: Some(if quote.quote.side == SwapSide::Sell {
                "After the settlement leg clears, have the treasury wallet settle the locked HT or let the seller cancel after expiry."
                        .into()
            } else {
                "After off-chain settlement, submit a normal HT transfer through the node control API."
                        .into()
            }),
        })
    }
}

struct HttpBridgeSwapAdapter {
    id: String,
    settlement_asset: SettlementAsset,
    quote_url: String,
    execution_url: String,
    auth_header_name: Option<String>,
    auth_header_value: Option<String>,
    client: reqwest::Client,
}

#[async_trait]
impl SwapAdapter for HttpBridgeSwapAdapter {
    fn id(&self) -> &str {
        &self.id
    }

    fn settlement_asset(&self) -> &SettlementAsset {
        &self.settlement_asset
    }

    async fn quote(&self, request: &SwapQuoteRequest) -> Result<SwapQuote> {
        let response = self
            .client
            .post(&self.quote_url)
            .headers(self.headers()?)
            .json(request)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json().await?)
    }

    async fn execution_plan(&self, quote: &SignedSwapQuote) -> Result<SwapExecutionPlan> {
        let response = self
            .client
            .post(&self.execution_url)
            .headers(self.headers()?)
            .json(quote)
            .send()
            .await?
            .error_for_status()?;

        let payload: Value = response.json().await?;
        let steps = payload
            .get("steps")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| {
                vec![
                    "External settlement bridge returned no explicit steps.".into(),
                    "Inspect the attached payload and perform the HT transfer once settlement clears."
                        .into(),
                ]
            });
        let follow_up_transfer_hint = payload
            .get("follow_up_transfer_hint")
            .and_then(Value::as_str)
            .map(ToString::to_string);

        Ok(SwapExecutionPlan {
            quote: quote.clone(),
            steps,
            follow_up_transfer_hint,
        })
    }
}

impl HttpBridgeSwapAdapter {
    fn headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        if let (Some(name), Some(value)) = (&self.auth_header_name, &self.auth_header_value) {
            headers.insert(
                HeaderName::from_bytes(name.as_bytes())?,
                HeaderValue::from_str(value)?,
            );
        }
        Ok(headers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{SettlementAsset, SwapQuoteRequest, SwapSide};

    #[tokio::test]
    async fn registry_produces_fixed_rate_quotes() {
        let registry = SwapRegistry::from_optional_file(None).unwrap();
        let quote = registry
            .quote(&SwapQuoteRequest {
                wallet: "wallet".into(),
                token_amount: 5 * MICRO_HT,
                side: SwapSide::Buy,
                settlement_asset: SettlementAsset::Usdc,
                adapter: Some("fixed-usdc-demo".into()),
                ttl_secs: 300,
            })
            .await
            .unwrap();

        assert_eq!(quote.settlement_amount, 5_000_000);
        assert_eq!(quote.adapter, "fixed-usdc-demo");
        assert_eq!(quote.wallet, "wallet");
    }
}
