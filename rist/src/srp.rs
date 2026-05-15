use crate::{Error, Result};
use std::ptr;

pub(crate) unsafe fn enable_from_peer_config(
    peer: *mut rist_sys::rist_peer,
    config: &rist_sys::rist_peer_config,
) -> Result<()> {
    if c_char_array_is_empty(&config.srp_username) || c_char_array_is_empty(&config.srp_password) {
        return Ok(());
    }

    let ret = unsafe {
        rist_sys::rist_enable_eap_srp_2(
            peer,
            config.srp_username.as_ptr(),
            config.srp_password.as_ptr(),
            None,
            ptr::null_mut(),
        )
    };
    if ret != 0 {
        return Err(Error::Configuration(format!(
            "failed to enable SRP authentication: {ret}"
        )));
    }
    Ok(())
}

fn c_char_array_is_empty(input: &[std::os::raw::c_char]) -> bool {
    input.first().copied().unwrap_or_default() == 0
}
