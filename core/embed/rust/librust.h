#include "librust_qstr.h"

mp_obj_t protobuf_type_for_name(mp_obj_t name);
mp_obj_t protobuf_type_for_wire(mp_obj_t wire_id);
mp_obj_t protobuf_decode(mp_obj_t buf, mp_obj_t def,
                         mp_obj_t enable_experimental);
mp_obj_t protobuf_len(mp_obj_t obj);
mp_obj_t protobuf_encode(mp_obj_t buf, mp_obj_t obj);

#ifdef TREZOR_EMULATOR
mp_obj_t protobuf_debug_msg_type();
mp_obj_t protobuf_debug_msg_def_type();
#endif

extern mp_obj_module_t mp_module_trezorui2;

#ifdef TREZOR_EMULATOR
mp_obj_t ui_debug_layout_type();
#endif

// Zcash
/*
mp_obj_t orchardlib_derive_full_viewing_key(mp_obj_t spending_key);
mp_obj_t orchardlib_derive_incoming_viewing_key(mp_obj_t full_viewing_key, mp_obj_t scope);
mp_obj_t orchardlib_derive_outgoing_viewing_key(mp_obj_t full_viewing_key, mp_obj_t scope);
mp_obj_t orchardlib_derive_address(mp_obj_t full_viewing_key, mp_obj_t diversifier_index, mp_obj_t scope);
mp_obj_t orchardlib_shield_output(mp_obj_t output_info);
mp_obj_t orchardlib_sign(mp_obj_t spending_key, mp_obj_t alpha, mp_obj_t sighash);
*/

mp_obj_t orchardlib_to_base(mp_obj_t bytes);
mp_obj_t orchardlib_to_scalar(mp_obj_t bytes);
mp_obj_t orchardlib_group_hash(mp_obj_t domain, mp_obj_t message);
