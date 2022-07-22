use super::ffi;
use core::{marker::PhantomData, mem::MaybeUninit, ptr};

pub const UZLIB_WINDOW_SIZE: usize = 1 << 10;
pub use ffi::uzlib_uncomp;

impl Default for ffi::uzlib_uncomp {
    fn default() -> Self {
        unsafe { MaybeUninit::<Self>::zeroed().assume_init() }
    }
}

pub struct UzlibContext<'a, 'b> {
    uncomp: ffi::uzlib_uncomp,
    src_data: PhantomData<&'a [u8]>,
    window: Option<[u8; UZLIB_WINDOW_SIZE]>,
    dest_buf: &'b mut [u8],
}

impl<'a, 'b> UzlibContext<'a, 'b> {
    pub fn new(src: &'a [u8], use_window: bool, dest_buf: &'b mut [u8]) -> Self {
        let window = use_window.then(|| [0_u8; UZLIB_WINDOW_SIZE]);

        let mut ctx = Self {
            uncomp: uzlib_uncomp::default(),
            src_data: Default::default(),
            window,
            dest_buf,
        };

        unsafe {
            ctx.uncomp.source = src.as_ptr();
            ctx.uncomp.source_limit = src.as_ptr().add(src.len());
            ctx.uncomp.dest = ctx.dest_buf.as_mut_ptr();
            ctx.uncomp.dest_limit = ctx.dest_buf.as_mut_ptr().add(ctx.dest_buf.len());

            if let Some(w) = ctx.window {
                ffi::uzlib_uncompress_init(&mut ctx.uncomp, w.as_ptr() as _, w.len() as u32);
            } else {
                ffi::uzlib_uncompress_init(&mut ctx.uncomp, ptr::null_mut(), 0);
            }
        }

        ctx
    }

    pub fn uncompress(&mut self) -> Result<&mut [u8], ()> {
        self.uncomp.dest = self.dest_buf.as_mut_ptr();

        unsafe {
            let res = ffi::uzlib_uncompress(&mut self.uncomp);

            if res == 0 {
                Ok(self.dest_buf)
            } else {
                Err(())
            }
        }
    }
}
