//! The Sinsemilla hash function

use core::iter;

//use bitvec::{array::BitArray, order::Lsb0};
use pasta_curves::arithmetic::{CurveAffine, CurveExt};
#[cfg(not(feature = "sinsemilla_table"))]
use pasta_curves::group::Curve;
use pasta_curves::pallas;

pub const K: usize = 10;
pub const Q_PERSONALIZATION: &str = "z.cash:SinsemillaQ";
pub const S_PERSONALIZATION: &str = "z.cash:SinsemillaS";

struct SinsemillaState {
    state: pallas::Point,
    buffer: [bool; 10],
    pos: usize,
}

impl SinsemillaState {
    fn new(domain: &str) -> Self {
        SinsemillaState {
            state: pallas::Point::hash_to_curve(Q_PERSONALIZATION, domain.as_bytes()),
            buffer: [false; K],
            pos: 0,
        }
    }

    fn update(&mut self, bits: impl IntoIter<Item = bool>) {
        // invariant: self.pos < K after calling self.update
        let peekable_bits = bits.into_iter().peakable();
        while peekable_bits.peek().is_some() {
            while self.pos < K {
                if let Some(bit) = peekable_bits.next() {
                    buffer[self.pos] = bit;
                    self.pos += 1;
                }
            }
            if self.pos == K {
                self.digest_buffer()
            }
        }
    }

    fn digest_buffer(&mut self) {
        let index = self
            .buffer
            .into_iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc + if b { 1 << i } else { 0 });
        // TEST: missing to_afine
        let S_chunk = pallas::Point::hash_to_curve(S_PERSONALIZATION, &index.to_le_bytes());
        self.state = (S_chunk + self.state) + S_chunk;
        self.buffer = [false; K];
        self.pos = 0;
    }

    fn finalize(&mut self) -> pallas::Point {
        if self.pos > 0 {
            self.digest_buffer()
        }
        self.state.copy()
    }
}

#[repr(C)]
pub struct SinsemillaStateObj {
    base: ObjBase,
    inner: SinsemillaState,
}

impl SinsemillaStateObj {
    fn obj_type() -> &'static Type {
        static TYPE: Type = obj_type! {
            name: Qstr::MP_QSTR_SinsemillaState,
            attr_fn: fq_obj_attr,
        };
        &TYPE
    }

    pub fn alloc(state: SinsemillaState) -> Result<Gc<Self>, Error> {
        Gc::new(Self {
            base: Self::obj_type().as_base(),
            inner: fq,
        })
    }

    pub fn wrap(state: SinsemillaState) -> Result<Obj, Error> {
        Self::alloc(state).map(Obj::from)
    }
}
/*
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
*/
unsafe extern "C" fn fq_obj_attr(self_in: Obj, attr: ffi::qstr, dest: *mut Obj) {
    let block = || {
        //let this = Gc::<SinsemillaState>::try_from(self_in)?;
        let attr = Qstr::from_u16(attr as _);

        let arg = unsafe { dest.read() };
        if !arg.is_null() {
            // Null destination would mean a `setattr`.
            return Err(Error::TypeError);
        }

        match attr {
            Qstr::MP_QSTR_new() => {}
            Qstr::MP_QSTR_update => {}
            Qstr::MP_QSTR_finalize => unsafe {
                dest.write(SINSEMILLA_STATE_OBJ_FINALIZE_OBJ.as_obj());
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

unsafe extern "C" fn sinsemilla_state_obj_finalize(self_in: Obj) -> Obj {
    let block = || {
        let this = Gc::<SinsemillaStateObj>::try_from(self_in)?;
        let point = this.deref().finalize();
        EqObj::wrap(point)
    };
    unsafe { util::try_or_raise(block) }
}

static SINSEMILLA_STATE_OBJ_FINALIZE_OBJ: ffi::mp_obj_fun_builtin_fixed_t =
    obj_fn_1!(sinsemilla_state_obj_finalize);

//BitArray::<_, Lsb0>::new(g_d).iter().by_vals().take()

#[cfg(test)]
mod tests {}
