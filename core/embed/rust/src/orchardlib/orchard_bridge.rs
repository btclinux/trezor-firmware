use core::convert::{TryFrom, TryInto};
use core::ops::{Deref, DerefMut};

use cstr_core::CStr;
use orchard::{
    keys::{
        FullViewingKey, IncomingViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey,
        SpendingKey,
    },
    value::NoteValue,
    Address, Note,
};

use pasta_curves::group::ff::PrimeField;
use pasta_curves::pallas;

use crate::error::Error;
use crate::micropython::{
    buffer::{Buffer, BufferMut},
    dict::Dict,
    gc::Gc,
    map::Map,
    obj::Obj,
    qstr::Qstr,
};
use crate::{trezorhal, util};

#[inline]
fn value_error(msg: &'static str) -> Error {
    Error::ValueError(unsafe { CStr::from_bytes_with_nul_unchecked(msg.as_bytes()) })
}

impl TryFrom<Obj> for SpendingKey {
    type Error = Error;

    fn try_from(sk: Obj) -> Result<SpendingKey, Error> {
        let sk_bytes: [u8; 32] = sk.try_into()?;
        let sk = SpendingKey::from_bytes(sk_bytes);
        let sk: Option<SpendingKey> = sk.into(); // conversion from CtOption to Option
        sk.ok_or_else(|| value_error("Invalid Spending Key\0"))
    }
}

impl TryFrom<Obj> for Scope {
    type Error = Error;

    fn try_from(scope: Obj) -> Result<Scope, Error> {
        let scope: u32 = scope.try_into()?;
        match scope {
            0 => Ok(Scope::External),
            1 => Ok(Scope::Internal),
            _ => Err(value_error("Invalid scope (External = 0, Internal = 1)")),
        }
}

impl TryFrom<Obj> for FullViewingKey {
    type Error = Error;

    fn try_from(fvk: Obj) -> Result<FullViewingKey, Error> {
        let fvk_bytes: [u8; 96] = fvk.try_into()?;
        let fvk = FullViewingKey::from_bytes(&fvk_bytes);
        fvk.ok_or_else(|| value_error("Invalid Full Viewing Key\0"))
    }
}

#[no_mangle]
pub extern "C" fn orchardlib_derive_full_viewing_key(spending_key: Obj) -> Obj {
    let block = || {
        let sk: SpendingKey = spending_key.try_into()?;

        let mut fvk: FullViewingKey = (&sk).into();
        let fvk_bytes = fvk.to_bytes();

        let fvk_obj = Obj::try_from(&fvk_bytes[..])?;
        Ok(fvk_obj)
    };
    unsafe { util::try_or_raise(block) }
}

#[no_mangle]
pub extern "C" fn orchardlib_derive_incoming_viewing_key(full_viewing_key: Obj, scope: Obj) -> Obj {
    let block = || {
        let fvk: FullViewingKey = full_viewing_key.try_into()?;
        let scope: Scope = scope.try_into()?;

        let ivk: IncomingViewingKey = (&fvk).to_ivk(scope);
        let ivk_bytes = ivk.to_bytes();

        let ivk_obj = Obj::try_from(&ivk_bytes[..])?;
        Ok(ivk_obj)
    };
    unsafe { util::try_or_raise(block) }
}

#[no_mangle]
pub extern "C" fn orchardlib_derive_outgoing_viewing_key(full_viewing_key: Obj, scope: Obj) -> Obj {
    let block = || {
        let fvk: FullViewingKey = full_viewing_key.try_into()?;
        let scope: Scope = scope.try_into()?;

        let ovk: OutgoingViewingKey = (&fvk).to_ovk(scope);
        let ovk_bytes: [u8; 32] = ovk.as_ref().clone();

        let ovk_obj = Obj::try_from(&ovk_bytes[..])?;
        Ok(ovk_obj)
    };
    unsafe { util::try_or_raise(block) }
}

#[no_mangle]
pub extern "C" fn orchardlib_derive_address(
    full_viewing_key: Obj,
    diversifier_index: Obj,
    scope: Obj,
) -> Obj {
    let block = || {
        let fvk: FullViewingKey = full_viewing_key.try_into()?;
        let diversifier_index: u64 = diversifier_index.try_into()?;
        let scope: Scope = scope.try_into()?;

        let addr = fvk.address_at(diversifier_index, scope);
        let addr_bytes = addr.to_raw_address_bytes();

        let addr_obj = Obj::try_from(&addr_bytes[..])?;
        Ok(addr_obj)
    };
    unsafe { util::try_or_raise(block) }
}

#[no_mangle]
pub extern "C" fn orchardlib_shield_output(output_info: Obj) -> Obj {
    let block = || {
        // parse output_info as Map
        let dict: Gc<Dict> = output_info.try_into()?;
        let dict: &Dict = dict.deref();
        let output_info: &Map = dict.map();

        let ovk: Option<OutgoingViewingKey> = {
            let ovk_bytes: [u8; 32] = output_info.get(Qstr::MP_QSTR_ovk)?.try_into()?;
            Some(OutgoingViewingKey::from(ovk_bytes))
        };

        let address: [u8; 43] = output_info.get(Qstr::MP_QSTR_address)?.try_into()?;
        let address = Address::from_raw_address_bytes(&address);
        let address = Option::from(address).ok_or_else(|| value_error("Invalied Address\0"))?;

        let value: u64 = output_info.get(Qstr::MP_QSTR_value)?.try_into()?;
        let value = orchard::value::NoteValue::from_raw(value);

        let memo = output_info.get(Qstr::MP_QSTR_memo)?;
        let memo: Option<[u8; 512]> = if memo.is_none() {
            None
        } else {
            Some(memo.try_into()?)
        };


        let action = orchard::hww_utils::shield_output(ovk, address, value, memo);

        let items: [(Qstr, Obj); 4] = [
            (Qstr::MP_QSTR_cmx, action.cmx().to_bytes().try_into()?),
            (
                Qstr::MP_QSTR_epk,
                action.encrypted_note().epk_bytes.try_into()?,
            ),
            (
                Qstr::MP_QSTR_enc_ciphertext,
                action.encrypted_note().enc_ciphertext.try_into()?,
            ),
            (
                Qstr::MP_QSTR_out_ciphertext,
                action.encrypted_note().out_ciphertext.try_into()?,
            ),
        ];

        let mut result = Dict::alloc_with_capacity(items.len())?;
        let mut map = unsafe { Gc::as_mut(&mut result) }.map_mut();
        for (key, value) in items.iter() {
            map.set(*key, *value)?
        }

        Ok(Obj::from(result))
    };
    unsafe { util::try_or_raise(block) }
}

#[no_mangle]
pub extern "C" fn orchardlib_sign(sk: Obj, alpha: Obj, sighash: Obj) -> Obj {
    let block = || {
        let alpha: [u8; 32] = alpha.try_into()?;
        let alpha = pallas::Scalar::from_repr(alpha);
        let alpha = Option::from(alpha).ok_or(Error::TypeError)?;
        let sighash: [u8; 32] = sighash.try_into()?;
        let sk: SpendingKey = sk.try_into()?;

        let ask: SpendAuthorizingKey = (&sk).into();
        let mut rng = trezorhal::random::HardwareRandomness;
        let signature = ask.randomize(&alpha).sign(rng, &sighash);
        let signature_bytes: [u8; 64] = (&signature).into();

        Ok(signature_bytes.try_into()?)
    };
    unsafe { util::try_or_raise(block) }
}
