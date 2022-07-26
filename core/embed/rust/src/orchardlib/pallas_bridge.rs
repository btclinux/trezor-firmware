use core::ops::Deref;

use ff::PrimeField;
use group::Curve;
use pasta_curves::{
    arithmetic::{CurveAffine, CurveExt, FieldExt},
    Ep, Fp, Fq,
};

use crate::{
    error::Error,
    micropython::{
        buffer::{Buffer, StrBuffer},
        dict::Dict,
        ffi,
        gc::Gc,
        map::Map,
        obj::{Obj, ObjBase},
        qstr::Qstr,
        typ::Type,
        util,
    },
};

//===========//
//    Fp     //
//===========//

#[repr(C)]
pub struct FpObj {
    base: ObjBase,
    inner: Fp,
}

impl FpObj {
    fn obj_type() -> &'static Type {
        static TYPE: Type = obj_type! {
            name: Qstr::MP_QSTR_Fp,
            attr_fn: fp_obj_attr,
        };
        &TYPE
    }

    pub fn alloc(fp: Fp) -> Result<Gc<Self>, Error> {
        Gc::new(Self {
            base: Self::obj_type().as_base(),
            inner: fp,
        })
    }

    pub fn wrap(fp: Fp) -> Result<Obj, Error> {
        Self::alloc(fp).map(Obj::from)
    }
}

impl From<Gc<FpObj>> for Obj {
    fn from(value: Gc<FpObj>) -> Self {
        // SAFETY:
        //  - `value` is GC-allocated.
        //  - `value` is `repr(C)`.
        //  - `value` has a `base` as the first field with the correct type.
        unsafe { Self::from_ptr(Gc::into_raw(value).cast()) }
    }
}

impl TryFrom<Obj> for Gc<FpObj> {
    type Error = Error;

    fn try_from(value: Obj) -> Result<Self, Self::Error> {
        if FpObj::obj_type().is_type_of(value) {
            // SAFETY: We assume that if `value` is an object pointer with the correct type,
            // it is always GC-allocated.
            let this = unsafe { Gc::from_raw(value.as_ptr().cast()) };
            Ok(this)
        } else {
            Err(Error::TypeError)
        }
    }
}

unsafe extern "C" fn fp_obj_attr(self_in: Obj, attr: ffi::qstr, dest: *mut Obj) {
    let block = || {
        let this = Gc::<FpObj>::try_from(self_in)?;
        let attr = Qstr::from_u16(attr as _);

        let arg = unsafe { dest.read() };
        if !arg.is_null() {
            // Null destination would mean a `setattr`.
            return Err(Error::TypeError);
        }

        match attr {
            Qstr::MP_QSTR___add__ => {}
            Qstr::MP_QSTR___bytes__ => unsafe {
                dest.write(FP_OBJ_BYTES_OBJ.as_obj());
                dest.offset(1).write(self_in);
            },
            _ => {
                return Err(Error::AttributeError(attr));
            }
        }
        Ok(())
    };
    unsafe { util::try_or_raise(block) }
}

unsafe extern "C" fn fp_obj_bytes(self_in: Obj, bytes: Obj) -> Obj {
    let block = || {
        let this = Gc::<FpObj>::try_from(self_in)?;
        let bytes: [u8; 32] = bytes.try_into()?;
        let fp = Fp::from_repr(bytes).unwrap();
        FpObj::wrap(fp)
    };
    unsafe { util::try_or_raise(block) }
}

static FP_OBJ_BYTES_OBJ: ffi::mp_obj_fun_builtin_fixed_t = obj_fn_2!(fp_obj_bytes);

#[no_mangle]
unsafe extern "C" fn orchardlib_to_base(bytes: Obj) -> Obj {
    let block = || {
        let bytes: [u8; 64] = bytes.try_into()?;
        let elem = Fp::from_bytes_wide(&bytes);
        FpObj::wrap(elem)
    };
    unsafe { util::try_or_raise(block) }
}

//===========//
//    Fq     //
//===========//

#[repr(C)]
pub struct FqObj {
    base: ObjBase,
    inner: Fq,
}

impl FqObj {
    fn obj_type() -> &'static Type {
        static TYPE: Type = obj_type! {
            name: Qstr::MP_QSTR_Fq,
            attr_fn: fq_obj_attr,
        };
        &TYPE
    }

    pub fn alloc(fq: Fq) -> Result<Gc<Self>, Error> {
        Gc::new(Self {
            base: Self::obj_type().as_base(),
            inner: fq,
        })
    }

    pub fn wrap(fq: Fq) -> Result<Obj, Error> {
        Self::alloc(fq).map(Obj::from)
    }
}

impl From<Gc<FqObj>> for Obj {
    fn from(value: Gc<FqObj>) -> Self {
        // SAFETY:
        //  - `value` is GC-allocated.
        //  - `value` is `repr(C)`.
        //  - `value` has a `base` as the first field with the correct type.
        unsafe { Self::from_ptr(Gc::into_raw(value).cast()) }
    }
}

impl TryFrom<Obj> for Gc<FqObj> {
    type Error = Error;

    fn try_from(value: Obj) -> Result<Self, Self::Error> {
        if FqObj::obj_type().is_type_of(value) {
            // SAFETY: We assume that if `value` is an object pointer with the correct type,
            // it is always GC-allocated.
            let this = unsafe { Gc::from_raw(value.as_ptr().cast()) };
            Ok(this)
        } else {
            Err(Error::TypeError)
        }
    }
}

unsafe extern "C" fn fq_obj_attr(self_in: Obj, attr: ffi::qstr, dest: *mut Obj) {
    let block = || {
        let this = Gc::<FqObj>::try_from(self_in)?;
        let attr = Qstr::from_u16(attr as _);

        let arg = unsafe { dest.read() };
        if !arg.is_null() {
            // Null destination would mean a `setattr`.
            return Err(Error::TypeError);
        }

        match attr {
            Qstr::MP_QSTR___add__ => {}
            Qstr::MP_QSTR___bytes__ => unsafe {
                dest.write(FQ_OBJ_BYTES_OBJ.as_obj());
                dest.offset(1).write(self_in);
            },
            _ => {
                return Err(Error::AttributeError(attr));
            }
        }
        Ok(())
    };
    unsafe { util::try_or_raise(block) }
}

unsafe extern "C" fn fq_obj_bytes(self_in: Obj, bytes: Obj) -> Obj {
    let block = || {
        let this = Gc::<FqObj>::try_from(self_in)?;
        let bytes: [u8; 32] = bytes.try_into()?;
        let elem = Fq::from_repr(bytes).unwrap();
        FqObj::wrap(elem)
    };
    unsafe { util::try_or_raise(block) }
}

static FQ_OBJ_BYTES_OBJ: ffi::mp_obj_fun_builtin_fixed_t = obj_fn_2!(fq_obj_bytes);

#[no_mangle]
unsafe extern "C" fn orchardlib_to_scalar(bytes: Obj) -> Obj {
    let block = || {
        let bytes: [u8; 64] = bytes.try_into()?;
        let elem = Fq::from_bytes_wide(&bytes);
        FqObj::wrap(elem)
    };
    unsafe { util::try_or_raise(block) }
}

//===========//
//   Point   //
//===========//

#[repr(C)]
pub struct EpObj {
    base: ObjBase,
    inner: Ep,
}

impl EpObj {
    fn obj_type() -> &'static Type {
        static TYPE: Type = obj_type! {
            name: Qstr::MP_QSTR_Ep,
            attr_fn: eq_obj_attr,
        };
        &TYPE
    }

    pub fn alloc(ep: Ep) -> Result<Gc<Self>, Error> {
        Gc::new(Self {
            base: Self::obj_type().as_base(),
            inner: ep,
        })
    }

    pub fn wrap(ep: Ep) -> Result<Obj, Error> {
        Self::alloc(ep).map(Obj::from)
    }
}

impl From<Gc<EpObj>> for Obj {
    fn from(value: Gc<EpObj>) -> Self {
        // SAFETY:
        //  - `value` is GC-allocated.
        //  - `value` is `repr(C)`.
        //  - `value` has a `base` as the first field with the correct type.
        unsafe { Self::from_ptr(Gc::into_raw(value).cast()) }
    }
}

impl TryFrom<Obj> for Gc<EpObj> {
    type Error = Error;

    fn try_from(value: Obj) -> Result<Self, Self::Error> {
        if EpObj::obj_type().is_type_of(value) {
            // SAFETY: We assume that if `value` is an object pointer with the correct type,
            // it is always GC-allocated.
            let this = unsafe { Gc::from_raw(value.as_ptr().cast()) };
            Ok(this)
        } else {
            Err(Error::TypeError)
        }
    }
}

unsafe extern "C" fn eq_obj_attr(self_in: Obj, attr: ffi::qstr, dest: *mut Obj) {
    let block = || {
        let this = Gc::<EpObj>::try_from(self_in)?;
        let attr = Qstr::from_u16(attr as _);

        let arg = unsafe { dest.read() };
        if !arg.is_null() {
            // Null destination would mean a `setattr`.
            return Err(Error::TypeError);
        }

        match attr {
            Qstr::MP_QSTR___add__ => {}
            Qstr::MP_QSTR_extract => unsafe {
                dest.write(EP_OBJ_EXTRACT_OBJ.as_obj());
                dest.offset(1).write(self_in);
            },
            _ => {
                return Err(Error::AttributeError(attr));
            }
        }
        Ok(())
    };
    unsafe { util::try_or_raise(block) }
}

unsafe extern "C" fn ep_obj_extract(self_in: Obj) -> Obj {
    let block = || {
        let this = Gc::<EpObj>::try_from(self_in)?;
        let elem = this
            .deref()
            .inner
            .to_affine()
            .coordinates()
            .map(|c| *c.x())
            .unwrap_or_else(Fp::zero);
        FpObj::wrap(elem)
    };
    unsafe { util::try_or_raise(block) }
}

static EP_OBJ_EXTRACT_OBJ: ffi::mp_obj_fun_builtin_fixed_t = obj_fn_1!(ep_obj_extract);

#[no_mangle]
unsafe extern "C" fn orchardlib_group_hash(domain: Obj, message: Obj) -> Obj {
    let block = || {
        let domain: StrBuffer = domain.try_into()?;
        let message: Buffer = message.try_into()?;
        let point = Ep::hash_to_curve(domain.deref(), message.deref());
        EpObj::wrap(point)
    };
    unsafe { util::try_or_raise(block) }
}
