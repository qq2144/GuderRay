//! GuderRay core: profile model, share-link/subscription parsing, sing-box config
//! generation, routing (unified domain/IP/process rules), and on-disk persistence.

pub mod classify;
pub mod config;
pub mod draft;
pub mod error;
pub mod link;
pub mod model;
pub mod routing;
pub mod store;
pub mod sub;

pub use classify::{classify_connection, classify_domain};
pub use draft::{draft_to_outbound, outbound_to_draft, OutboundDraft};
pub use error::{CoreError, Result};
pub use model::{Outbound, Profile};
pub use routing::{RoutingMode, RuleList, UserRules};
pub use store::{Paths, ProfileStore, Running, Settings, State, SubStore, Subscription};
