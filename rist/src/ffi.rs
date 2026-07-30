use crate::{Error, Result};
use std::ffi::CString;
use std::ptr;

/// A parsed librist peer configuration that always releases the C allocation.
pub(crate) struct ParsedPeerConfig {
    ptr: *mut rist_sys::rist_peer_config,
    url: String,
}

impl ParsedPeerConfig {
    pub(crate) fn parse(url: &str) -> Result<Self> {
        let url_c = CString::new(url)?;
        let mut ptr = ptr::null_mut();
        let ret = unsafe { rist_sys::rist_parse_address2(url_c.as_ptr(), &mut ptr) };
        if ret != 0 || ptr.is_null() {
            return Err(Error::UrlParse(url.to_string()));
        }
        Ok(Self {
            ptr,
            url: url.to_string(),
        })
    }

    pub(crate) fn configure(&mut self, configure: impl FnOnce(&mut rist_sys::rist_peer_config)) {
        // SAFETY: `ptr` is non-null and exclusively owned by this guard.
        configure(unsafe { &mut *self.ptr });
    }

    pub(crate) unsafe fn create_peer(
        &self,
        ctx: *mut rist_sys::rist_ctx,
    ) -> Result<*mut rist_sys::rist_peer> {
        let mut peer = ptr::null_mut();
        let ret = unsafe { rist_sys::rist_peer_create(ctx, &mut peer, self.ptr) };
        if ret != 0 || peer.is_null() {
            return Err(Error::PeerCreation(self.url.clone()));
        }

        unsafe { crate::srp::enable_from_peer_config(peer, &*self.ptr)? };
        Ok(peer)
    }
}

impl Drop for ParsedPeerConfig {
    fn drop(&mut self) {
        unsafe {
            rist_sys::rist_peer_config_free2(&mut self.ptr);
        }
    }
}
