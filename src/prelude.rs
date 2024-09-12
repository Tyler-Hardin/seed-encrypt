pub(crate) use anyhow::{Context,Result,anyhow,ensure};

pub use std::time::Duration;

pub(crate) fn round_duration(lhs: Duration, rhs: Duration) -> Duration {
    let lhs = lhs.as_nanos() as u64;
    let rhs = rhs.as_nanos() as u64;

    let num = lhs / rhs;
    let rem = lhs % rhs;
    if rem > rhs / 2 {
        Duration::from_nanos((num + 1) * rhs)
    } else {
        Duration::from_nanos(num * rhs)
    }
}
