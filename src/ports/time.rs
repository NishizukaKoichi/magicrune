use core::time::Duration;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait TimePort: Send + Sync {
    fn now_millis(&self) -> u64;
    fn now_secs(&self) -> u64;
    async fn sleep(&self, duration: Duration);
}
