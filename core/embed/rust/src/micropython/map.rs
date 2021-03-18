use core::{marker::PhantomData, mem::MaybeUninit, ops::Deref, slice};

use crate::{
    error::Error,
    micropython::{obj::Obj, qstr::Qstr},
};

use super::ffi;

pub type Map = ffi::mp_map_t;
pub type MapElem = ffi::mp_map_elem_t;

impl Map {
    pub const fn from_fixed_static<const N: usize>(table: &'static [MapElem; N]) -> Self {
        // micropython/py/obj.h MP_DEFINE_CONST_DICT
        // .all_keys_are_qstrs = 1,
        // .is_fixed = 1,
        // .is_ordered = 1,
        // .used = MP_ARRAY_SIZE(table_name),
        // .alloc = MP_ARRAY_SIZE(table_name),
        let bits = 0b111 | N << 3;
        let bitfield = ffi::__BindgenBitfieldUnit::new(bits.to_ne_bytes());
        Self {
            _bitfield_align_1: [],
            _bitfield_1: bitfield,
            alloc: N,
            table: table.as_ptr() as *mut MapElem,
        }
    }

    pub const fn at(key: Qstr, value: Obj) -> MapElem {
        MapElem {
            key: key.to_obj(),
            value,
        }
    }
}

impl Map {
    pub fn from_fixed<'a>(table: &'a [MapElem]) -> MapRef<'a> {
        let mut map = MaybeUninit::uninit();
        // SAFETY: `mp_map_init` completely initializes all fields of `map`.
        unsafe {
            ffi::mp_map_init_fixed_table(map.as_mut_ptr(), table.len(), table.as_ptr().cast());
            MapRef::new(map.assume_init())
        }
    }

    pub fn new_with_capacity(capacity: usize) -> Self {
        let mut map = MaybeUninit::uninit();
        // SAFETY: `mp_map_init` completely initializes all fields of `map`, allocating
        // the backing storage for `capacity` items on the heap.
        unsafe {
            ffi::mp_map_init(map.as_mut_ptr(), capacity);
            map.assume_init()
        }
    }

    pub fn len(&self) -> usize {
        self.used()
    }

    pub fn elems(&self) -> &[MapElem] {
        // SAFETY: `self.table` should always point to an array of `MapElem` of
        // `self.len()` items valid at least for the lifetime of `self`.
        unsafe { slice::from_raw_parts(self.table, self.len()) }
    }

    pub fn contains_key(&self, index: impl Into<Obj>) -> bool {
        self.get_obj(index.into()).is_ok()
    }

    pub fn get(&self, index: impl Into<Obj>) -> Result<Obj, Error> {
        self.get_obj(index.into())
    }

    pub fn get_obj(&self, index: Obj) -> Result<Obj, Error> {
        // SAFETY:
        //  - `mp_map_lookup` returns either NULL or a pointer to a `mp_map_elem_t`
        //    value with a lifetime valid for the whole lifetime of the passed immutable
        //    ref of `map`.
        //  - with `_mp_map_lookup_kind_t_MP_MAP_LOOKUP`, `map` stays unmodified and the
        //    cast to mut ptr is therefore safe.
        unsafe {
            let map = self as *const Self as *mut Self;
            let elem = ffi::mp_map_lookup(map, index, ffi::_mp_map_lookup_kind_t_MP_MAP_LOOKUP)
                .as_ref()
                .ok_or(Error::Missing)?;
            Ok(elem.value)
        }
    }

    pub fn set(&mut self, index: impl Into<Obj>, value: impl Into<Obj>) {
        self.set_obj(index.into(), value.into())
    }

    pub fn set_obj(&mut self, index: Obj, value: Obj) {
        unsafe {
            let map = self as *mut Self;
            let elem = ffi::mp_map_lookup(
                map,
                index,
                ffi::_mp_map_lookup_kind_t_MP_MAP_LOOKUP_ADD_IF_NOT_FOUND,
            )
            .as_mut()
            .unwrap();
            elem.value = value;
        }
    }

    pub fn delete(&mut self, index: impl Into<Obj>) {
        self.delete_obj(index.into())
    }

    pub fn delete_obj(&mut self, index: Obj) {
        unsafe {
            let map = self as *mut Self;
            ffi::mp_map_lookup(
                map,
                index,
                ffi::_mp_map_lookup_kind_t_MP_MAP_LOOKUP_REMOVE_IF_FOUND,
            );
        }
    }
}

impl Default for Map {
    fn default() -> Self {
        Self::new_with_capacity(0)
    }
}

// SAFETY: We are in a single-threaded environment.
unsafe impl Sync for Map {}
unsafe impl Sync for MapElem {}

pub struct MapRef<'a> {
    map: Map,
    _phantom: PhantomData<&'a Map>,
}

impl<'a> MapRef<'a> {
    fn new(map: Map) -> Self {
        Self {
            map,
            _phantom: PhantomData::default(),
        }
    }
}

impl<'a> Deref for MapRef<'a> {
    type Target = Map;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}