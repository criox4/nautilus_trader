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

//! Tenant identity and routing primitives.
//!
//! These types deliberately live below the live runtime. Application services can authenticate a
//! tenant once and carry the resulting envelope through the runtime without conflating tenant
//! identity with Nautilus `TraderId`.

use std::{
    fmt::{Display, Formatter, Write as _},
    str::FromStr,
};

use nautilus_core::UUID4;
use nautilus_model::identifiers::AccountId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_TENANT_ID_LENGTH: usize = 128;

/// Encodes an identifier component for use in a durable namespace key.
#[must_use]
pub fn encode_namespace_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            encoded.push(char::from(byte));
        } else {
            write!(encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    encoded
}

/// An immutable platform tenant identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TenantId(String);

impl TenantId {
    /// Creates a tenant identifier after validating its namespace-safe form.
    ///
    /// # Errors
    ///
    /// Returns [`TenantIdError`] when the value is empty, too long, or contains a character that
    /// is unsafe for durable storage namespaces.
    pub fn new(value: impl Into<String>) -> Result<Self, TenantIdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(TenantIdError::Empty);
        }
        if value.len() > MAX_TENANT_ID_LENGTH {
            return Err(TenantIdError::TooLong {
                max: MAX_TENANT_ID_LENGTH,
            });
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(TenantIdError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the tenant identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for TenantId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Display for TenantId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TenantId {
    type Err = TenantIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<String> for TenantId {
    type Error = TenantIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for TenantId {
    type Error = TenantIdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<TenantId> for String {
    fn from(value: TenantId) -> Self {
        value.0
    }
}

/// Errors returned while validating a tenant identifier.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TenantIdError {
    /// The identifier was empty.
    #[error("tenant ID cannot be empty")]
    Empty,
    /// The identifier exceeded the maximum supported length.
    #[error("tenant ID exceeds the maximum length of {max} characters")]
    TooLong { max: usize },
    /// The identifier contained a character unsafe for durable namespaces.
    #[error("tenant ID contains an invalid character")]
    InvalidCharacter,
}

/// The durable namespace owned by one tenant runtime and broker account.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct TenantNamespace {
    /// The platform tenant.
    pub tenant_id: TenantId,
    /// The broker account owned by the tenant.
    pub account_id: AccountId,
    /// The Nautilus runtime instance.
    pub runtime_instance_id: UUID4,
}

impl TenantNamespace {
    /// Creates a tenant namespace.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        account_id: AccountId,
        runtime_instance_id: UUID4,
    ) -> Self {
        Self {
            tenant_id,
            account_id,
            runtime_instance_id,
        }
    }

    /// Returns a stable, collision-resistant key prefix for durable storage.
    #[must_use]
    pub fn key_prefix(&self) -> String {
        format!(
            "nautilus:v1:tenant:{}:account:{}:runtime:{}",
            self.tenant_id,
            encode_namespace_component(self.account_id.as_ref()),
            self.runtime_instance_id
        )
    }
}

/// An authenticated tenant envelope for application/runtime messages.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TenantEnvelope<T> {
    /// The authenticated tenant scope.
    pub tenant_id: TenantId,
    /// The runtime instance receiving the message.
    pub runtime_instance_id: UUID4,
    /// The request correlation identifier.
    pub correlation_id: UUID4,
    /// The tenant-scoped payload.
    pub payload: T,
}

impl<T> TenantEnvelope<T> {
    /// Creates an envelope with a new correlation identifier.
    #[must_use]
    pub fn new(tenant_id: TenantId, runtime_instance_id: UUID4, payload: T) -> Self {
        Self {
            tenant_id,
            runtime_instance_id,
            correlation_id: UUID4::new(),
            payload,
        }
    }

    /// Verifies that this envelope belongs to the expected tenant and runtime.
    ///
    /// # Errors
    ///
    /// Returns [`TenantScopeError`] when either tenant or runtime identity differs.
    pub fn validate_scope(
        &self,
        tenant_id: &TenantId,
        runtime_instance_id: UUID4,
    ) -> Result<(), TenantScopeError> {
        if &self.tenant_id != tenant_id {
            return Err(TenantScopeError::TenantMismatch);
        }
        if self.runtime_instance_id != runtime_instance_id {
            return Err(TenantScopeError::RuntimeMismatch);
        }
        Ok(())
    }

    /// Converts the payload while preserving its authenticated scope.
    #[must_use]
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> TenantEnvelope<U> {
        TenantEnvelope {
            tenant_id: self.tenant_id,
            runtime_instance_id: self.runtime_instance_id,
            correlation_id: self.correlation_id,
            payload: f(self.payload),
        }
    }
}

/// Errors returned when an envelope is routed to the wrong runtime.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TenantScopeError {
    /// The envelope was authenticated for another tenant.
    #[error("tenant envelope does not belong to the target tenant")]
    TenantMismatch,
    /// The envelope was created for another runtime instance.
    #[error("tenant envelope does not belong to the target runtime instance")]
    RuntimeMismatch,
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::empty("")]
    #[case::space("tenant id")]
    #[case::separator("tenant:id")]
    fn test_tenant_id_rejects_unsafe_values(#[case] value: &str) {
        assert!(TenantId::new(value).is_err());
    }

    #[rstest]
    fn test_namespace_component_encoding_is_unambiguous() {
        assert_eq!(encode_namespace_component("account:one"), "account%3Aone");
        assert_ne!(
            encode_namespace_component("account:one"),
            encode_namespace_component("account/one")
        );
    }

    #[rstest]
    fn test_namespace_contains_all_ownership_dimensions() {
        let namespace = TenantNamespace::new(
            TenantId::new("tenant-a").unwrap(),
            AccountId::from("BINANCE-001"),
            UUID4::from("11111111-1111-4111-8111-111111111111"),
        );

        assert_eq!(
            namespace.key_prefix(),
            concat!(
                "nautilus:v1:tenant:tenant-a:account:BINANCE-001:runtime:",
                "11111111-1111-4111-8111-111111111111"
            )
        );
    }

    #[rstest]
    fn test_envelope_scope_rejects_cross_tenant_routing() {
        let tenant_a = TenantId::new("tenant-a").unwrap();
        let tenant_b = TenantId::new("tenant-b").unwrap();
        let runtime = UUID4::new();
        let envelope = TenantEnvelope::new(tenant_a.clone(), runtime, "order");

        assert_eq!(
            envelope.validate_scope(&tenant_b, runtime),
            Err(TenantScopeError::TenantMismatch)
        );
        assert!(envelope.validate_scope(&tenant_a, runtime).is_ok());
    }
}
