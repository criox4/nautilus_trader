// -------------------------------------------------------------------------------------------------
//  Copyright (C) 2015-2026 Nautech Systems Pty Ltd. All rights reserved.
//  https://nautechsystems.io
//
//  Licensed under the GNU Lesser General Public License Version 3.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at https://www.gnu.org/licenses/lgpl-3.0.en.html
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
// -------------------------------------------------------------------------------------------------

//! Tenant-owned live runtimes and fair lifecycle scheduling.
//!
//! A [`TenantContext`] owns one `LiveNode` and therefore one complete set of Nautilus engines.
//! [`TenantHost`] is intentionally single-threaded: the underlying engines use `Rc<RefCell<_>>`.
//! It provides the authenticated capability and bounded, round-robin control plane needed by an
//! application service without exposing engine objects to request handlers.

use std::{
    collections::{BTreeMap, VecDeque},
    rc::Rc,
};

use anyhow::Context;
use nautilus_common::{
    msgbus::{MessageBus, MessageBusScope, with_message_bus},
    tenant::{TenantEnvelope, TenantId, TenantNamespace},
};
use nautilus_core::UUID4;
use nautilus_model::identifiers::AccountId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::node::LiveNode;

/// Default maximum number of queued control commands for one tenant.
pub const DEFAULT_TENANT_QUEUE_DEPTH: usize = 10_000;

/// Resource limits applied at the tenant admission boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TenantLimits {
    /// Maximum number of queued commands for the tenant.
    pub max_queue_depth: usize,
    /// Maximum number of open orders the tenant may maintain.
    pub max_open_orders: usize,
    /// Maximum number of tenant-owned strategies.
    pub max_strategies: usize,
    /// Maximum number of runtime events admitted per second.
    pub max_events_per_second: u64,
}

impl Default for TenantLimits {
    fn default() -> Self {
        Self {
            max_queue_depth: DEFAULT_TENANT_QUEUE_DEPTH,
            max_open_orders: 10_000,
            max_strategies: 100,
            max_events_per_second: 100_000,
        }
    }
}

impl TenantLimits {
    /// Validates that every configured quota can admit work.
    ///
    /// # Errors
    ///
    /// Returns an error when any quota is zero.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.max_queue_depth > 0,
            "tenant queue depth must be greater than 0"
        );
        anyhow::ensure!(
            self.max_open_orders > 0,
            "tenant open-order limit must be greater than 0"
        );
        anyhow::ensure!(
            self.max_strategies > 0,
            "tenant strategy limit must be greater than 0"
        );
        anyhow::ensure!(
            self.max_events_per_second > 0,
            "tenant event-rate limit must be greater than 0"
        );
        Ok(())
    }
}

/// An opaque authenticated capability for one tenant.
///
/// The tenant ID is intentionally not sufficient to obtain this value. Application handlers
/// should retain the capability returned by [`TenantHost::register`], after authentication and
/// authorization, and pass it to tenant operations.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TenantHandle {
    tenant_id: TenantId,
    capability: UUID4,
}

impl TenantHandle {
    /// Returns the tenant selected by this authenticated capability.
    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// Lifecycle state for a tenant runtime.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum TenantState {
    /// The tenant has not started its runtime.
    #[default]
    Idle,
    /// The tenant runtime is starting.
    Starting,
    /// The tenant runtime is processing work.
    Running,
    /// The tenant runtime is running but control-plane work is suspended.
    Suspended,
    /// The tenant is stopping.
    Stopping,
    /// The tenant runtime has stopped.
    Stopped,
}

/// A tenant-owned runtime context.
#[derive(Debug)]
pub struct TenantContext {
    tenant_id: TenantId,
    namespaces: Vec<TenantNamespace>,
    broker_accounts: Vec<AccountId>,
    limits: TenantLimits,
    state: TenantState,
    node: LiveNode,
}

impl TenantContext {
    /// Creates a context around a compatibility `LiveNode`.
    ///
    /// The node must already be configured for the tenant's broker account(s). The context keeps
    /// the node's cache, portfolio, engines, trader, runner, and message bus together so they
    /// cannot accidentally be selected independently by a caller.
    ///
    /// # Errors
    ///
    /// Returns an error when no broker account is supplied or a tenant quota is invalid.
    pub fn from_live_node(
        tenant_id: TenantId,
        node: LiveNode,
        broker_accounts: Vec<AccountId>,
        limits: TenantLimits,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !broker_accounts.is_empty(),
            "tenant context requires at least one broker account"
        );
        limits.validate()?;
        let namespaces = broker_accounts
            .iter()
            .copied()
            .map(|account_id| {
                TenantNamespace::new(tenant_id.clone(), account_id, node.instance_id())
            })
            .collect();
        Ok(Self {
            tenant_id,
            namespaces,
            broker_accounts,
            limits,
            state: TenantState::Idle,
            node,
        })
    }

    /// Returns the tenant identity.
    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the durable namespace for the first configured broker account.
    #[must_use]
    pub fn namespace(&self) -> &TenantNamespace {
        &self.namespaces[0]
    }

    /// Returns the durable namespace for every configured broker account.
    #[must_use]
    pub fn namespaces(&self) -> &[TenantNamespace] {
        &self.namespaces
    }

    /// Returns all broker accounts owned by this tenant.
    #[must_use]
    pub fn broker_accounts(&self) -> &[AccountId] {
        &self.broker_accounts
    }

    /// Returns the configured tenant limits.
    #[must_use]
    pub const fn limits(&self) -> &TenantLimits {
        &self.limits
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> TenantState {
        self.state
    }

    /// Returns the runtime instance identifier.
    #[must_use]
    pub const fn runtime_instance_id(&self) -> UUID4 {
        self.node.instance_id()
    }

    /// Wraps an application payload in this context's authenticated tenant scope.
    #[must_use]
    pub fn envelope<T>(&self, payload: T) -> TenantEnvelope<T> {
        TenantEnvelope::new(self.tenant_id.clone(), self.runtime_instance_id(), payload)
    }

    /// Returns the tenant-owned message bus.
    #[must_use]
    pub(crate) fn message_bus(&self) -> Rc<std::cell::RefCell<MessageBus>> {
        self.node.kernel().message_bus()
    }

    /// Runs synchronous tenant work with this context's message bus active.
    ///
    /// This is the integration point for application services that still use Nautilus's legacy
    /// free-standing message-bus functions. The closure must not retain handles obtained from the
    /// bus after it returns.
    pub fn with_message_bus<T>(&self, f: impl FnOnce() -> T) -> T {
        with_message_bus(self.message_bus(), f)
    }

    /// Starts this tenant runtime. Repeated starts are idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error when the runtime is already transitioning or node startup fails.
    pub async fn start(&mut self) -> anyhow::Result<()> {
        if matches!(self.state, TenantState::Running | TenantState::Suspended) {
            return Ok(());
        }
        anyhow::ensure!(
            !matches!(self.state, TenantState::Starting | TenantState::Stopping),
            "tenant runtime is transitioning"
        );

        self.state = TenantState::Starting;
        let result = {
            let _scope = MessageBusScope::enter(self.message_bus());
            self.node.start().await
        };
        if result.is_ok() && self.node.is_running() {
            self.state = TenantState::Running;
        } else {
            self.state = TenantState::Stopped;
        }
        result
    }

    /// Stops this tenant runtime. Repeated stops are idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error when the runtime is already stopping or node shutdown fails.
    pub async fn stop(&mut self) -> anyhow::Result<()> {
        if matches!(self.state, TenantState::Idle | TenantState::Stopped) {
            return Ok(());
        }
        anyhow::ensure!(
            self.state != TenantState::Stopping,
            "tenant runtime is already stopping"
        );

        self.state = TenantState::Stopping;
        let result = {
            let _scope = MessageBusScope::enter(self.message_bus());
            if self.node.is_running() {
                self.node.stop().await
            } else {
                Ok(())
            }
        };
        self.state = TenantState::Stopped;
        result
    }

    /// Suspends control-plane work while retaining the tenant runtime and state.
    ///
    /// # Errors
    ///
    /// Returns an error when the tenant is not running.
    pub fn suspend(&mut self) -> anyhow::Result<()> {
        if self.state == TenantState::Suspended {
            return Ok(());
        }
        anyhow::ensure!(
            self.state == TenantState::Running,
            "tenant runtime is not running"
        );
        self.state = TenantState::Suspended;
        Ok(())
    }

    /// Resumes control-plane work for a suspended tenant.
    ///
    /// # Errors
    ///
    /// Returns an error when the tenant is not suspended.
    pub fn resume(&mut self) -> anyhow::Result<()> {
        if self.state == TenantState::Running {
            return Ok(());
        }
        anyhow::ensure!(
            self.state == TenantState::Suspended,
            "tenant runtime is not suspended"
        );
        self.state = TenantState::Running;
        Ok(())
    }

    /// Disposes all tenant-owned runtime resources.
    pub fn dispose(&mut self) {
        let _scope = MessageBusScope::enter(self.message_bus());
        self.node.dispose();
        self.state = TenantState::Stopped;
    }
}

/// Lifecycle commands admitted by the tenant host.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TenantCommand {
    /// Starts the tenant runtime.
    Start,
    /// Stops the tenant runtime.
    Stop,
    /// Suspends tenant control-plane work.
    Suspend,
    /// Resumes tenant control-plane work.
    Resume,
    /// Destroys a stopped tenant runtime.
    Destroy,
}

#[derive(Debug)]
struct TenantEntry {
    handle: TenantHandle,
    context: TenantContext,
}

#[derive(Debug)]
struct TenantCommandQueue {
    max_depth: usize,
    messages: VecDeque<TenantEnvelope<TenantCommand>>,
}

/// Errors returned when a tenant command cannot be admitted.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TenantQueueError {
    /// The tenant is not registered with this host.
    #[error("tenant is not registered")]
    UnknownTenant,
    /// The command was rejected because its queue is full.
    #[error("tenant command queue is full")]
    QueueFull,
    /// The tenant is suspended and only a resume command is accepted.
    #[error("tenant runtime is suspended")]
    Suspended,
}

/// Outcome of one dispatched tenant lifecycle command.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TenantCommandOutcome {
    /// The request correlation identifier.
    pub correlation_id: UUID4,
    /// The authenticated tenant scope.
    pub tenant_id: TenantId,
    /// The command result.
    pub result: Result<(), String>,
}

/// Process-level host for multiple tenant runtimes.
#[derive(Debug)]
pub struct TenantHost {
    tenants: BTreeMap<TenantId, TenantEntry>,
    destroyed: BTreeMap<TenantId, UUID4>,
    queues: BTreeMap<TenantId, TenantCommandQueue>,
    ready: VecDeque<TenantId>,
    max_dispatch_per_cycle: usize,
}

impl Default for TenantHost {
    fn default() -> Self {
        Self::new(64)
    }
}

impl TenantHost {
    /// Creates a host with a bounded number of commands dispatched per scheduling cycle.
    #[must_use]
    pub fn new(max_dispatch_per_cycle: usize) -> Self {
        Self {
            tenants: BTreeMap::new(),
            destroyed: BTreeMap::new(),
            queues: BTreeMap::new(),
            ready: VecDeque::new(),
            max_dispatch_per_cycle: max_dispatch_per_cycle.max(1),
        }
    }

    /// Registers a tenant runtime and returns its authenticated capability.
    ///
    /// # Errors
    ///
    /// Returns an error when the tenant ID is already registered.
    pub fn register(&mut self, context: TenantContext) -> anyhow::Result<TenantHandle> {
        let tenant_id = context.tenant_id().clone();
        anyhow::ensure!(
            !self.tenants.contains_key(&tenant_id),
            "tenant {tenant_id} is already registered"
        );
        self.destroyed.remove(&tenant_id);
        let handle = TenantHandle {
            tenant_id: tenant_id.clone(),
            capability: UUID4::new(),
        };
        let max_depth = context.limits().max_queue_depth;
        self.tenants.insert(
            tenant_id.clone(),
            TenantEntry {
                handle: handle.clone(),
                context,
            },
        );
        self.queues.insert(
            tenant_id,
            TenantCommandQueue {
                max_depth,
                messages: VecDeque::new(),
            },
        );
        Ok(handle)
    }

    /// Returns the number of registered tenants.
    #[must_use]
    pub fn tenant_count(&self) -> usize {
        self.tenants.len()
    }

    /// Enqueues a lifecycle command after validating the opaque tenant capability.
    ///
    /// # Errors
    ///
    /// Returns [`TenantQueueError`] when the capability is unknown, the tenant is suspended, or
    /// its bounded queue is full.
    pub fn enqueue(
        &mut self,
        handle: &TenantHandle,
        command: TenantCommand,
    ) -> Result<UUID4, TenantQueueError> {
        let Some(entry) = self.tenants.get(handle.tenant_id()) else {
            return Err(TenantQueueError::UnknownTenant);
        };
        if entry.handle.capability != handle.capability {
            return Err(TenantQueueError::UnknownTenant);
        }
        if entry.context.state() == TenantState::Suspended && command != TenantCommand::Resume {
            return Err(TenantQueueError::Suspended);
        }
        let envelope = entry.context.envelope(command);
        let queue = self
            .queues
            .get_mut(handle.tenant_id())
            .ok_or(TenantQueueError::UnknownTenant)?;
        if queue.messages.len() >= queue.max_depth {
            return Err(TenantQueueError::QueueFull);
        }
        let correlation_id = envelope.correlation_id;
        let was_empty = queue.messages.is_empty();
        queue.messages.push_back(envelope);
        if was_empty {
            self.ready.push_back(handle.tenant_id.clone());
        }
        Ok(correlation_id)
    }

    /// Dispatches a fair round-robin batch of queued lifecycle commands.
    pub async fn dispatch(&mut self) -> Vec<TenantCommandOutcome> {
        let mut outcomes = Vec::with_capacity(self.max_dispatch_per_cycle);
        for _ in 0..self.max_dispatch_per_cycle {
            let Some(tenant_id) = self.ready.pop_front() else {
                break;
            };
            let Some(envelope) = self
                .queues
                .get_mut(&tenant_id)
                .and_then(|queue| queue.messages.pop_front())
            else {
                continue;
            };

            if self
                .queues
                .get(&tenant_id)
                .is_some_and(|queue| !queue.messages.is_empty())
            {
                self.ready.push_back(tenant_id.clone());
            }

            let Some(entry) = self.tenants.get(&tenant_id) else {
                outcomes.push(TenantCommandOutcome {
                    correlation_id: envelope.correlation_id,
                    tenant_id,
                    result: Err("tenant was removed before dispatch".to_string()),
                });
                continue;
            };
            let handle = entry.handle.clone();
            if let Err(error) = envelope.validate_scope(
                entry.context.tenant_id(),
                entry.context.runtime_instance_id(),
            ) {
                outcomes.push(TenantCommandOutcome {
                    correlation_id: envelope.correlation_id,
                    tenant_id,
                    result: Err(error.to_string()),
                });
                continue;
            }

            let result = match envelope.payload {
                TenantCommand::Start => self.start_tenant(&handle).await,
                TenantCommand::Stop => self.stop_tenant(&handle).await,
                TenantCommand::Suspend => self.suspend_tenant(&handle),
                TenantCommand::Resume => self.resume_tenant(&handle),
                TenantCommand::Destroy => self.destroy_tenant(&handle),
            };
            outcomes.push(TenantCommandOutcome {
                correlation_id: envelope.correlation_id,
                tenant_id,
                result: result.map_err(|e| e.to_string()),
            });
        }
        outcomes
    }

    /// Returns a tenant context after validating its authenticated capability.
    ///
    /// # Errors
    ///
    /// Returns an error when the tenant is not registered or the capability is unauthorized.
    pub fn context(&self, handle: &TenantHandle) -> anyhow::Result<&TenantContext> {
        let entry = self
            .tenants
            .get(handle.tenant_id())
            .context("tenant is not registered")?;
        anyhow::ensure!(
            entry.handle.capability == handle.capability,
            "tenant capability is not authorized"
        );
        Ok(&entry.context)
    }

    /// Starts a tenant runtime after validating its authenticated capability.
    ///
    /// # Errors
    ///
    /// Returns an error when the capability is unauthorized or startup fails.
    pub async fn start_tenant(&mut self, handle: &TenantHandle) -> anyhow::Result<()> {
        self.context_mut(handle)?.start().await
    }

    /// Stops a tenant runtime after validating its authenticated capability.
    ///
    /// # Errors
    ///
    /// Returns an error when the capability is unauthorized or shutdown fails.
    pub async fn stop_tenant(&mut self, handle: &TenantHandle) -> anyhow::Result<()> {
        self.context_mut(handle)?.stop().await
    }

    /// Suspends a tenant runtime after validating its authenticated capability.
    ///
    /// # Errors
    ///
    /// Returns an error when the capability is unauthorized or the runtime is not running.
    pub fn suspend_tenant(&mut self, handle: &TenantHandle) -> anyhow::Result<()> {
        self.context_mut(handle)?.suspend()
    }

    /// Resumes a tenant runtime after validating its authenticated capability.
    ///
    /// # Errors
    ///
    /// Returns an error when the capability is unauthorized or the runtime is not suspended.
    pub fn resume_tenant(&mut self, handle: &TenantHandle) -> anyhow::Result<()> {
        self.context_mut(handle)?.resume()
    }

    fn context_mut(&mut self, handle: &TenantHandle) -> anyhow::Result<&mut TenantContext> {
        let entry = self
            .tenants
            .get_mut(handle.tenant_id())
            .context("tenant is not registered")?;
        anyhow::ensure!(
            entry.handle.capability == handle.capability,
            "tenant capability is not authorized"
        );
        Ok(&mut entry.context)
    }

    /// Destroys an idle or stopped tenant runtime after validating its authenticated capability.
    ///
    /// # Errors
    ///
    /// Returns an error when the capability is unauthorized or the runtime is still active.
    pub fn destroy_tenant(&mut self, handle: &TenantHandle) -> anyhow::Result<()> {
        let Some(entry) = self.tenants.remove(handle.tenant_id()) else {
            if self.destroyed.get(handle.tenant_id()) == Some(&handle.capability) {
                return Ok(());
            }
            anyhow::bail!("tenant is not registered");
        };
        if entry.handle.capability != handle.capability {
            self.tenants.insert(handle.tenant_id.clone(), entry);
            anyhow::bail!("tenant capability is not authorized");
        }
        if !matches!(
            entry.context.state(),
            TenantState::Idle | TenantState::Stopped
        ) {
            self.tenants.insert(handle.tenant_id.clone(), entry);
            anyhow::bail!("tenant must be idle or stopped before destruction");
        }
        let mut context = entry.context;
        context.dispose();
        self.destroyed
            .insert(handle.tenant_id.clone(), handle.capability);
        self.queues.remove(handle.tenant_id());
        self.ready
            .retain(|tenant_id| tenant_id != handle.tenant_id());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    fn test_limits_reject_zero_values() {
        let limits = TenantLimits {
            max_queue_depth: 0,
            ..TenantLimits::default()
        };
        assert!(limits.validate().is_err());
    }
}
