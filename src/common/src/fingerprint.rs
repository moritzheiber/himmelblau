/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2025

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

//! Fingerprint verification via fprintd over the system D-Bus.
//!
//! The verification runs inside the privileged daemon (from the resolver), not
//! in the untrusted PAM module, so a fingerprint result is only ever produced
//! by trusted code. fprintd owns the sensor and returns a match/no-match
//! result; it never releases key material. A match therefore only authorizes
//! release of the machine-sealed Hello PIN, matching the fprintd trust model
//! used by comparable projects.

use futures::StreamExt;
use std::time::Duration;
use tokio::time::timeout;
use tracing::debug;
use zbus::proxy;
use zbus::zvariant::OwnedObjectPath;
use zbus::Connection;

const VERIFY_TIMEOUT: Duration = Duration::from_secs(60);

#[proxy(
    interface = "net.reactivated.Fprint.Manager",
    default_service = "net.reactivated.Fprint",
    default_path = "/net/reactivated/Fprint/Manager"
)]
trait FprintManager {
    fn get_default_device(&self) -> zbus::Result<OwnedObjectPath>;
}

#[proxy(
    interface = "net.reactivated.Fprint.Device",
    default_service = "net.reactivated.Fprint"
)]
trait FprintDevice {
    fn list_enrolled_fingers(&self, username: &str) -> zbus::Result<Vec<String>>;
    fn claim(&self, username: &str) -> zbus::Result<()>;
    fn release(&self) -> zbus::Result<()>;
    fn verify_start(&self, finger_name: &str) -> zbus::Result<()>;
    fn verify_stop(&self) -> zbus::Result<()>;

    #[zbus(signal)]
    fn verify_status(&self, result: &str, done: bool) -> zbus::Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintVerification {
    Match,
    NoMatch,
    Unavailable,
}

/// Classify a single fprintd `VerifyStatus` signal. Returns `None` while the
/// scan is still in progress (e.g. `verify-retry-scan`) so the caller keeps
/// waiting, and a terminal result once `done` is set or a match is reported.
fn completed_verification(result: &str, done: bool) -> Option<FingerprintVerification> {
    if result == "verify-match" {
        Some(FingerprintVerification::Match)
    } else if done {
        Some(FingerprintVerification::NoMatch)
    } else {
        None
    }
}

async fn device(connection: &Connection) -> zbus::Result<FprintDeviceProxy<'_>> {
    let manager = FprintManagerProxy::new(connection).await?;
    let path = manager.get_default_device().await?;
    FprintDeviceProxy::builder(connection)
        .path(path)?
        .build()
        .await
}

async fn has_enrollment_inner(username: &str) -> zbus::Result<bool> {
    let connection = Connection::system().await?;
    let device = device(&connection).await?;
    Ok(!device.list_enrolled_fingers(username).await?.is_empty())
}

/// Whether a fingerprint reader exists and `username` has at least one finger
/// enrolled with it. Any D-Bus failure (no fprintd, no reader, polkit refusal)
/// is treated as "not available" so the caller falls back to the PIN.
pub async fn has_enrollment(username: &str) -> bool {
    match has_enrollment_inner(username).await {
        Ok(available) => available,
        Err(err) => {
            debug!(?err, "Fingerprint reader or enrollment unavailable");
            false
        }
    }
}

async fn verify_inner(username: &str) -> zbus::Result<FingerprintVerification> {
    let connection = Connection::system().await?;
    let device = device(&connection).await?;
    if device.list_enrolled_fingers(username).await?.is_empty() {
        return Ok(FingerprintVerification::Unavailable);
    }

    device.claim(username).await?;
    let result = async {
        let mut statuses = device.receive_verify_status().await?;
        device.verify_start("any").await?;

        let outcome = timeout(VERIFY_TIMEOUT, async {
            while let Some(status) = statuses.next().await {
                let args = status.args()?;
                if let Some(outcome) = completed_verification(args.result(), *args.done()) {
                    return Ok(outcome);
                }
            }
            Ok(FingerprintVerification::Unavailable)
        })
        .await
        .unwrap_or(Ok(FingerprintVerification::Unavailable));

        let _ = device.verify_stop().await;
        outcome
    }
    .await;
    let _ = device.release().await;
    result
}

/// Run one fprintd verification round for `username`. Any D-Bus failure is
/// reported as `Unavailable` so the caller falls back to the PIN.
pub async fn verify(username: &str) -> FingerprintVerification {
    match verify_inner(username).await {
        Ok(outcome) => outcome,
        Err(err) => {
            debug!(?err, "Fingerprint verification unavailable");
            FingerprintVerification::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{completed_verification, FingerprintVerification};

    #[test]
    fn verification_match_completes() {
        assert_eq!(
            completed_verification("verify-match", true),
            Some(FingerprintVerification::Match)
        );
    }

    #[test]
    fn terminal_failure_falls_back() {
        assert_eq!(
            completed_verification("verify-no-match", true),
            Some(FingerprintVerification::NoMatch)
        );
    }

    #[test]
    fn retry_status_keeps_waiting() {
        assert_eq!(completed_verification("verify-retry-scan", false), None);
    }
}
