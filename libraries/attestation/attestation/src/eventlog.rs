use anyhow::{bail, Context};
use digest::{Digest, Output};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::{serde_as, IfIsHumanReadable};
use std::{marker::PhantomData, ops::Deref};

pub trait Event: Serialize + DeserializeOwned + Clone {}

#[cfg(feature = "tss-esapi")]
mod generate {
    use tpm_quote::common::{HashingAlgorithm, PcrIndex, PcrSlot};

    use digest::Digest;

    use sha2::Sha256;

    use super::{Event, EventLog};
    use crate::cbor;
    /// A event log that can be extended with new events.
    /// Backed by a TPM SHA256 PCR slot.
    pub struct LiveEventLog<E>
    where
        E: Event,
    {
        tpm_ctx: tss_esapi::Context,
        pcr_slot: PcrSlot,
        eventlog: EventLog<E>,
    }
    impl<E: Event> LiveEventLog<E> {
        /// Create a new LiveEventLog instance.
        ///
        /// HashingAlgorithm must be Sha256.
        /// The PCR slot used for backing the eventlog must not be used for other purposes.
        pub fn new(tpm_context: tss_esapi::Context, PcrIndex { bank, pcr_slot }: PcrIndex) -> Self {
            assert_eq!(bank, HashingAlgorithm::Sha256);
            LiveEventLog {
                tpm_ctx: tpm_context,
                pcr_slot: pcr_slot,
                eventlog: EventLog::empty(),
            }
        }

        /// Push a new event to the event log.
        /// This will extend the PCR slot with the digest of the event.
        /// This operation can not be undone.
        pub fn push_event(&mut self, event: &E) -> anyhow::Result<()> {
            let event_ser = cbor::to_vec(&event)?;
            let event_digest = Sha256::digest(&event_ser[..]);

            // Extend PCR[sha256:EVENTLOG_PCR_INDEX] with digest of serialized event
            let mut vals = tss_esapi::structures::DigestValues::new();
            vals.set(
                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
                event_digest[..].try_into()?,
            );
            // Use pcr_session for authorization when extending
            // PCR 16 with the values for the banks specified in
            // vals.
            self.tpm_ctx
                .execute_with_nullauth_session(|ctx| ctx.pcr_extend(self.pcr_slot.into(), vals))?;

            self.eventlog.events.push(event_ser);

            Ok(())
        }

        /// Get the current version of the event log.
        /// To be verified one should provide the quote and the eventlog together
        /// Note that a quote corresponds to a specific version of the eventlog.
        /// One must be careful to not push new events between the time of the quote and eventlog obtention
        /// (which can be done in any order)
        pub fn get_eventlog(&self) -> &EventLog<E> {
            &self.eventlog
        }
    }
}

#[cfg(feature = "tss-esapi")]
pub use generate::*;

use crate::cbor;

#[derive(Clone)]
pub struct ParsedEventLog<E>
where
    E: Event,
{
    events: Vec<E>,
}

impl<E: Event> Deref for ParsedEventLog<E> {
    type Target = [E];

    fn deref(&self) -> &Self::Target {
        &self.events[..]
    }
}

impl<E: Event> EventLog<E> {
    pub fn digest<D>(&self) -> Output<D>
    where
        D: Digest,
    {
        let events_digest = self.events.iter().map(|e| D::digest(&e[..]));
        let mut state: Output<D> = Default::default();

        // About the initial state of the PCR:
        // Almost all PCR have as initial values 0x00 bytes. We assume the PCR backing the eventlog is one of them.
        // Exceptions are PCR17 to PCR22 (inclusive), their initial values is "all bits set to 1"
        // To simulate the TPM_EXTEND ops, the initial state should be set accordingly with either
        // state.fill(0x00_u8); or state.fill(0xFF_u8);
        // PCR 17 to PCR22 however MUST NOT be used as backing for the eventlog
        // because they behaved differently.

        // Initial state of PCR = 0x00..00
        // Only for clarity (Default::default() returns an array of 0u8 bytes, so this a no-op).
        state.fill(0x00_u8);

        for digest in events_digest {
            let mut hasher = D::new();
            hasher.update(state);
            hasher.update(digest);
            state = hasher.finalize();
        }
        state
    }

    pub fn verify<D>(&self, pcr_value: Output<D>) -> anyhow::Result<ParsedEventLog<E>>
    where
        D: Digest,
    {
        let computed_digest = self.digest::<D>();
        if computed_digest != pcr_value {
            bail!(
                "Bad eventlog : wrong digest. Expected: {}, got: {}.",
                hex::encode(computed_digest),
                hex::encode(pcr_value)
            );
        }
        let parsed_events = self
            .events
            .iter()
            .map(|e| cbor::from_slice::<E>(&e[..]))
            .collect::<Result<Vec<_>, _>>()
            .context("Could not parse an event")?;
        Ok(ParsedEventLog {
            events: parsed_events,
        })
    }

    pub fn unsafe_open(&self) -> anyhow::Result<ParsedEventLog<E>> {
        let parsed_events = self
            .events
            .iter()
            .map(|e| cbor::from_slice::<E>(&e[..]))
            .collect::<Result<Vec<_>, _>>()
            .context("Could not parse an event")?;
        Ok(ParsedEventLog {
            events: parsed_events,
        })
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(transparent)]
pub struct EventLog<E: Event> {
    #[serde_as(as = "Vec<IfIsHumanReadable<serde_with::base64::Base64>>")]
    events: Vec<Vec<u8>>,
    #[serde(skip)]
    _event_type: PhantomData<E>,
}

impl<E: Event> EventLog<E> {
    pub fn empty() -> Self {
        EventLog {
            events: vec![],
            _event_type: PhantomData,
        }
    }
}
