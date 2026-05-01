use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::protocol::{Address, compute_hash};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoundRobinDomain {
    HealthCheck,
    Compute,
    MonitorBrowser,
    MonitorConfirmation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoundRobinLease {
    pub provider: Address,
    pub replica_index: usize,
    pub chunk_index: usize,
    pub position_start: usize,
    pub position_end_exclusive: usize,
    #[serde(default)]
    pub audit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskAssignment {
    pub mandatory_providers: Vec<Address>,
    pub audit_provider: Option<Address>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoundRobinPlan {
    pub domain: RoundRobinDomain,
    pub seed: String,
    pub providers: Vec<Address>,
    pub task_count: usize,
    pub lease_span: usize,
    pub chunk_count: usize,
    pub mandatory_replicas: usize,
    pub audit_probability_denominator: usize,
    #[serde(default)]
    pub leases: Vec<RoundRobinLease>,
}

impl RoundRobinPlan {
    pub fn build(
        domain: RoundRobinDomain,
        chain_id: &str,
        epoch_nonce: &str,
        providers: &[Address],
        task_keys: &[String],
        mandatory_replicas: usize,
        enable_chunk_audits: bool,
    ) -> Result<Self> {
        let mut unique_providers = providers.to_vec();
        unique_providers.sort();
        unique_providers.dedup();
        let seed = compute_hash(&(
            domain,
            chain_id.to_string(),
            epoch_nonce.to_string(),
            unique_providers.clone(),
            task_keys,
        ))?;

        if unique_providers.is_empty() || task_keys.is_empty() {
            return Ok(Self {
                domain,
                seed,
                providers: unique_providers,
                task_count: task_keys.len(),
                lease_span: 0,
                chunk_count: 0,
                mandatory_replicas: 0,
                audit_probability_denominator: 0,
                leases: Vec::new(),
            });
        }

        let shuffled = shuffle_providers(&seed, &unique_providers)?;
        let provider_count = shuffled.len();
        let mandatory_replicas = mandatory_replicas.max(1).min(provider_count);
        let lease_span =
            average_tasks_per_provider(task_keys.len(), provider_count).next_power_of_two();
        let chunk_count = div_ceil(task_keys.len(), lease_span);
        let audit_probability_denominator =
            if enable_chunk_audits && provider_count > mandatory_replicas {
                provider_count.next_power_of_two()
            } else {
                0
            };

        let mut leases = Vec::new();
        for chunk_index in 0..chunk_count {
            let position_start = chunk_index * lease_span;
            let position_end_exclusive = (position_start + lease_span).min(task_keys.len());
            for replica_index in 0..mandatory_replicas {
                leases.push(RoundRobinLease {
                    provider: shuffled[(chunk_index + replica_index) % provider_count].clone(),
                    replica_index,
                    chunk_index,
                    position_start,
                    position_end_exclusive,
                    audit: false,
                });
            }

            if audit_probability_denominator > 0
                && chunk_is_audited(&seed, chunk_index, audit_probability_denominator)?
            {
                let audit_provider =
                    shuffled[(chunk_index + mandatory_replicas) % provider_count].clone();
                if !leases.iter().any(|lease| {
                    lease.chunk_index == chunk_index && lease.provider == audit_provider
                }) {
                    leases.push(RoundRobinLease {
                        provider: audit_provider,
                        replica_index: mandatory_replicas,
                        chunk_index,
                        position_start,
                        position_end_exclusive,
                        audit: true,
                    });
                }
            }
        }

        Ok(Self {
            domain,
            seed,
            providers: shuffled,
            task_count: task_keys.len(),
            lease_span,
            chunk_count,
            mandatory_replicas,
            audit_probability_denominator,
            leases,
        })
    }

    pub fn assignment_for_task(&self, task_index: usize) -> Option<TaskAssignment> {
        if self.lease_span == 0 || task_index >= self.task_count {
            return None;
        }
        let chunk_index = task_index / self.lease_span;
        let mut mandatory_providers = self
            .leases
            .iter()
            .filter(|lease| lease.chunk_index == chunk_index && !lease.audit)
            .map(|lease| lease.provider.clone())
            .collect::<Vec<_>>();
        mandatory_providers.sort();
        mandatory_providers.dedup();
        let audit_provider = self
            .leases
            .iter()
            .find(|lease| lease.chunk_index == chunk_index && lease.audit)
            .map(|lease| lease.provider.clone());
        Some(TaskAssignment {
            mandatory_providers,
            audit_provider,
        })
    }

    pub fn provider_should_execute(&self, provider: &str, task_index: usize) -> bool {
        self.assignment_for_task(task_index)
            .map(|assignment| {
                assignment
                    .mandatory_providers
                    .iter()
                    .any(|assigned| assigned == provider)
                    || assignment
                        .audit_provider
                        .as_ref()
                        .map(|assigned| assigned == provider)
                        .unwrap_or(false)
            })
            .unwrap_or(false)
    }
}

fn shuffle_providers(seed: &str, providers: &[Address]) -> Result<Vec<Address>> {
    let mut scored = providers
        .iter()
        .map(|provider| {
            Ok::<_, anyhow::Error>((
                compute_hash(&(seed.to_string(), provider.clone()))?,
                provider.clone(),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    scored.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    Ok(scored.into_iter().map(|(_, provider)| provider).collect())
}

fn average_tasks_per_provider(task_count: usize, provider_count: usize) -> usize {
    div_ceil(task_count.max(1), provider_count.max(1)).max(1)
}

fn chunk_is_audited(seed: &str, chunk_index: usize, denominator: usize) -> Result<bool> {
    let sample = compute_hash(&(seed.to_string(), "audit".to_string(), chunk_index))?;
    let sample = u64::from_str_radix(&sample[..16], 16)?;
    Ok(sample % denominator as u64 == 0)
}

fn div_ceil(left: usize, right: usize) -> usize {
    if right == 0 {
        return 0;
    }
    left.div_ceil(right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_span_tracks_average_tasks_per_provider() {
        let providers = vec!["a".into(), "b".into(), "c".into(), "d".into()];
        let task_keys = (0..1_000)
            .map(|index| format!("task-{index}"))
            .collect::<Vec<_>>();
        let plan = RoundRobinPlan::build(
            RoundRobinDomain::HealthCheck,
            "testnet",
            "epoch-1",
            &providers,
            &task_keys,
            2,
            true,
        )
        .unwrap();

        assert_eq!(plan.lease_span, 256);
        assert_eq!(plan.chunk_count, 4);
        assert_eq!(plan.mandatory_replicas, 2);
    }

    #[test]
    fn assignments_cover_required_replicas_without_duplicates() {
        let providers = vec!["a".into(), "b".into(), "c".into()];
        let task_keys = (0..9)
            .map(|index| format!("task-{index}"))
            .collect::<Vec<_>>();
        let plan = RoundRobinPlan::build(
            RoundRobinDomain::MonitorConfirmation,
            "testnet",
            "epoch-2",
            &providers,
            &task_keys,
            2,
            false,
        )
        .unwrap();

        for index in 0..task_keys.len() {
            let assignment = plan.assignment_for_task(index).unwrap();
            assert_eq!(assignment.mandatory_providers.len(), 2);
            assert_ne!(
                assignment.mandatory_providers[0],
                assignment.mandatory_providers[1]
            );
        }
    }
}
