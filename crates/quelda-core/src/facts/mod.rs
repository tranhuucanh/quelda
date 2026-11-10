//! Facts layer (design §4.1): the union object set, normalized and indexed
//! for rules. Rules read everything through [`Ctx`]; they never parse bytes
//! and never see policy actions.

pub mod content_ops;
pub mod ctx;
pub mod page_tree;
pub mod streams;
pub mod visitor;

pub use content_ops::{ContentOp, InlineImage};
pub use ctx::{Ctx, ImageFact, OpLocation, StreamData, Visitor};
pub use page_tree::{Page, PageBox, PageTree};
pub use streams::StreamRoles;
pub use visitor::{Location, PathSeg};
