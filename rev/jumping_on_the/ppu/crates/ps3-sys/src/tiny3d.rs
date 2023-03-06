///! TODO: Actually safe abstractions over either this API or RSX directly
///! TODO: This module should be behind a feature gate
use libc::c_void;

use crate::println;

// TODO: Texture allocator maybe?
/// Base texture pointer
static mut TEXTURE_BASE: *mut c_void = core::ptr::null_mut();
/// Pointer to free texture space
static mut TEXTURE_PTR: *mut c_void = core::ptr::null_mut();

#[repr(C)]
pub enum AlphaFunc {
    Never = 0x200,
    Less,
    Equal,
    LEqual,
    Greater,
    NotEqual,
    GEqual,
    Always,
}

#[repr(u32)]
pub enum BlendSrcRgb {
    Zero = 0x00000000,
    One,
    SrcColor = 0x00000300,
    OneMinusSrcColor,
    SrcAlpha,
    OneMinusSrcAlpha,
    DstAlpha,
    OneMinusDstAlpha,
    DstColor,
    OneMinusDstColor,
    SrcAlphaSaturate,
    ConstantColor = 0x00008001,
    OneMinusConstantColor,
    ConstantAlpha,
    OneMinusConstantAlpha,
}

#[repr(u32)]
pub enum BlendSrcAlpha {
    Zero = 0x00000000,
    One = 0x00010000,
    SrcColor = 0x03000000,
    OneMinusSrcColor = 0x03010000,
    SrcAlpha = 0x03020000,
    OneMinusSrcAlpha = 0x03030000,
    DstAlpha = 0x03040000,
    OneMinusDstAlpha = 0x03050000,
    DstColor = 0x03060000,
    OneMinusDstColor = 0x03070000,
    SrcAlphaSaturate = 0x03080000,
    ConstantColor = 0x80010000,
    OneMinusConstantColor = 0x80020000,
    ConstantAlpha = 0x80030000,
    OneMinusConstantAlpha = 0x80040000,
}

#[repr(u32)]
pub enum BlendDstRgb {
    Zero = 0x00000000,
    One,
    SrcColor = 0x00000300,
    OneMinusSrcColor,
    SrcAlpha,
    OneMinusSrcAlpha,
    DstAlpha,
    OneMinusDstAlpha,
    DstColor,
    OneMinusDstColor,
    SrcAlphaSaturate,
    ConStantColor = 0x00008001,
    OneMinusConstantColor,
    ConStantAlpha,
    OneMinusConstantAlpha,
}

#[repr(u32)]
pub enum BlendDstAlpha {
    Zero = 0x00000000,
    One = 0x00010000,
    SrcColor = 0x03000000,
    OneMinusSrcColor = 0x03010000,
    SrcAlpha = 0x03020000,
    OneMinusSrcAlpha = 0x03030000,
    DstAlpha = 0x03040000,
    OneMinusDstAlpha = 0x03050000,
    DstColor = 0x03060000,
    OneMinusDstColor = 0x03070000,
    SrcAlphaSaturate = 0x03080000,
    ConstantColor = 0x80010000,
    OneMinusConstantColor = 0x80020000,
    ConstantAlpha = 0x80030000,
    OneMinusConstantAlpha = 0x80040000,
}

#[repr(u32)]
pub enum BlendRgb {
    FuncAdd = 0x00008006,
    Min,
    Max,
    FuncSubtract = 0x0000800a,
    FuncReverseSubtract,
}

#[repr(u32)]
pub enum BlendAlpha {
    FuncAdd = 0x80060000,
    Min = 0x80070000,
    Max = 0x80080000,
    FuncSubtract = 0x800a0000,
    FuncReverseSubtract = 0x800b0000,
}

#[repr(C)]
pub enum Polygon {
    Points = 1,
    Lines,
    LineLoop,
    LineStrip,
    Triangles,
    TriangleStrip,
    TriangleFan,
    Quads,
    QuadStrip,
    Polygon,
}

#[repr(u32)]
pub enum ClearFlags {
    ClearColor = sys::INT_REALITY_CLEAR_BUFFERS_COLOR_R
        | sys::INT_REALITY_CLEAR_BUFFERS_COLOR_G
        | sys::INT_REALITY_CLEAR_BUFFERS_COLOR_B
        | sys::INT_3D_CLEAR_BUFFERS_COLOR_A,
    ClearZBuffer = sys::INT_REALITY_CLEAR_BUFFERS_DEPTH,
    ClearStencil = sys::INT_3D_CLEAR_BUFFERS_STENCIL,
    ClearAll = Self::ClearColor as u32 | Self::ClearZBuffer as u32 | Self::ClearStencil as u32,
}

#[inline]
pub fn clear(color: u32, flags: ClearFlags) {
    unsafe {
        sys::tiny3d_Clear(color, flags);
    }
}

/// Clears the screen and selects the 2D projection
#[inline]
pub fn initialize() {
    unsafe {
        sys::tiny3d_Init(1024 * 1024);
        TEXTURE_BASE = sys::tiny3d_AllocTexture(64 * 1024 * 1024);
        println!("Texture base ptr: {:p}", TEXTURE_BASE);
        TEXTURE_PTR = TEXTURE_BASE;
    }
}

#[inline]
pub fn clear_2d() {
    unsafe {
        sys::tiny3d_Clear(0xff000000, ClearFlags::ClearAll);
        sys::tiny3d_AlphaTest(1, 0x10, AlphaFunc::GEqual);
        sys::blend_func(
            true,
            BlendSrcRgb::SrcAlpha,
            BlendSrcAlpha::SrcAlpha,
            BlendDstRgb::OneMinusSrcAlpha,
            BlendDstAlpha::Zero,
            BlendRgb::FuncAdd,
            BlendAlpha::FuncAdd,
        );
        sys::tiny3d_Project2D();
    }
}

#[inline]
pub fn flip() {
    unsafe {
        sys::tiny3d_Flip();
    }
}

pub struct Texture {
    offset: u32,
    width: u32,
    height: u32,
    stride: u32,
    // TODO: Are those even needed
    ptr: *mut c_void,
    max_len: usize,
}

impl Texture {
    /// Allocates and copies a texture to the RSX
    pub fn new<T>(data: &[T], width: u32, height: u32, stride: u32) -> Self {
        let len = core::mem::size_of::<T>() * data.len();
        debug_assert_eq!(len, stride as usize * height as usize);
        unsafe {
            // Can't use ptr::copy_nonoverlapping
            // because copying to the RSX has to go through system memcpy
            libc::memcpy(TEXTURE_PTR.cast(), data.as_ptr().cast(), len);
            let offset = sys::tiny3d_TextureOffset(TEXTURE_PTR.cast_const());
            let ptr = TEXTURE_PTR;
            let max_len = ((data.len() + 15) & !15) / 4;
            // Update the pointer and align it to 16 bytes
            TEXTURE_PTR = TEXTURE_PTR.add(max_len);
            Texture {
                offset,
                width,
                height,
                stride,

                ptr,
                max_len,
            }
        }
    }

    /// Replace contents of the texture with new data
    pub fn replace<T>(&mut self, data: &[T]) {
        let len = core::mem::size_of::<T>() * data.len();
        debug_assert!(len <= self.max_len);
        unsafe {
            // Can't use ptr::copy_nonoverlapping
            // because copying to the RSX has to go through system memcpy
            libc::memcpy(self.ptr.cast(), data.as_ptr().cast(), len);
        }
    }

    pub fn set(&self) {
        unsafe {
            sys::tiny3d_SetTexture(
                0,
                self.offset,
                self.width,
                self.height,
                self.stride,
                0x00000500,
                0,
            );
        }
    }
}

const SCREEN_WIDTH: f32 = 847.0;
const SCREEN_HEIGHT: f32 = 511.0;
const SQUARE_SIZE: f32 = SCREEN_HEIGHT;
const SQUARE_X_START: f32 = (SCREEN_WIDTH - SQUARE_SIZE) / 2.0;
const SQUARE_X_END: f32 = (SCREEN_WIDTH + SQUARE_SIZE) / 2.0;
const SQUARE_Y_START: f32 = 0.0;
const SQUARE_Y_END: f32 = SCREEN_HEIGHT;

pub fn draw_background_tex() {
    unsafe {
        use sys::*;
        tiny3d_SetPolygon(Polygon::Quads);

        tiny3d_VertexPos(SQUARE_X_START, SQUARE_Y_START, 1.);
        tiny3d_VertexColor(0xffffffff);
        tiny3d_VertexTexture(0., 0.);

        // tiny3d_VertexPos(847., 0., 1.);
        tiny3d_VertexPos(SQUARE_X_END, SQUARE_Y_START, 1.);
        tiny3d_VertexTexture(0.99, 0.);

        // tiny3d_VertexPos(847., 511., 1.);
        tiny3d_VertexPos(SQUARE_X_END, SQUARE_Y_END, 1.);
        tiny3d_VertexTexture(0.99, 0.99);

        // tiny3d_VertexPos(0., 511., 1.);
        tiny3d_VertexPos(SQUARE_X_START, SQUARE_Y_END, 1.);
        tiny3d_VertexTexture(0., 0.99);

        tiny3d_End();
    }
}

/// Bindings to the C library
mod sys {
    use libc::c_void;

    pub const INT_REALITY_CLEAR_BUFFERS_DEPTH: u32 = 0x00000001;
    // TODO: Uncomment
    // pub const INT_REALITY_CLEAR_BUFFERS_STENCIL: u32 = 0x00000002;
    pub const INT_REALITY_CLEAR_BUFFERS_COLOR_R: u32 = 0x00000010;
    pub const INT_REALITY_CLEAR_BUFFERS_COLOR_G: u32 = 0x00000020;
    pub const INT_REALITY_CLEAR_BUFFERS_COLOR_B: u32 = 0x00000040;
    // TODO: Uncomment
    // pub const INT_REALITY_CLEAR_BUFFERS_COLOR_A: u32 = 0x00000080;

    pub const INT_3D_CLEAR_BUFFERS_COLOR_A: u32 = 0x00000080;
    pub const INT_3D_CLEAR_BUFFERS_STENCIL: u32 = 0x00000002;

    #[link(name = "tiny3d")]
    extern "C" {
        pub fn tiny3d_Init(vertex_buff_size: u32) -> i32;
        pub fn tiny3d_Clear(color: u32, flags: super::ClearFlags);
        pub fn tiny3d_Project2D();
        // TODO: Uncomment
        // pub fn tiny3d_Project3D();
        pub fn tiny3d_Flip();
        pub fn tiny3d_SetTexture(
            unit: u32,
            offset: u32,
            w: u32,
            h: u32,
            stride: u32,
            fmt: u32,
            smooth: i32,
        );
        pub fn tiny3d_TextureOffset(text: *const c_void) -> u32;
        pub fn tiny3d_AllocTexture(size: u32) -> *mut c_void;
        pub fn tiny3d_SetPolygon(typ: super::Polygon) -> i32;
        pub fn tiny3d_End() -> i32;
        pub fn tiny3d_VertexPos(x: f32, y: f32, z: f32);
        // TODO: Uncomment
        // pub fn tiny3d_VertexPos4(x: f32, y: f32, z: f32, w: f32);
        // pub fn tiny3d_VertexPosVector( v: VECTOR);
        pub fn tiny3d_VertexColor(rgba: u32);
        // TODO: Uncomment
        // pub fn tiny3d_VertexFcolor(r: f32, g: f32, b: f32, a: f32);
        pub fn tiny3d_VertexTexture(u: f32, v: f32);
        pub fn tiny3d_AlphaTest(enable: i32, refr: u8, func: super::AlphaFunc);
        fn tiny3d_BlendFunc(enable: i32, src_fun: u32, dst_func: u32, func: u32);
    }

    pub unsafe fn blend_func(
        enable: bool,
        src_rgb_fun: super::BlendSrcRgb,
        src_alpha_fun: super::BlendSrcAlpha,
        dst_rgb_fun: super::BlendDstRgb,
        dst_alpha_fun: super::BlendDstAlpha,
        rgb_fun: super::BlendRgb,
        alpha_fun: super::BlendAlpha,
    ) {
        tiny3d_BlendFunc(
            if enable { 1 } else { 0 },
            src_rgb_fun as u32 | src_alpha_fun as u32,
            dst_rgb_fun as u32 | dst_alpha_fun as u32,
            rgb_fun as u32 | alpha_fun as u32,
        );
    }
}

pub mod font {
    use libc::c_void;

    use super::TEXTURE_PTR;

    extern "C" {
        fn ResetFont();
        fn AddFontFromBitmapArray(
            src: *const u8,
            dst: *mut c_void,
            first_char: u8,
            last_char: u8,
            w: i32,
            h: i32,
            bpp: i32,
            byte_order: i32,
        ) -> *mut c_void;
        pub fn SetFontSize(sx: i32, sy: i32);
        pub fn SetFontColor(color: u32, bkcolor: u32);
        pub fn SetFontAutoCenter(on_off: i32);
        pub fn DrawChar(x: f32, y: f32, z: f32, chr: u8);
        pub fn DrawString(x: f32, y: f32, str: *const u8) -> f32;
        pub fn SetFontTextureSmooth(smooth: i32);
    }

    // TODO: Support multiple fonts. Maybe.
    pub fn load_bitmap_font(
        src: &[u8],
        first_char: u8,
        last_char: u8,
        w: i32,
        h: i32,
        bits_per_pixel: i32,
        byte_order: i32,
    ) {
        unsafe {
            ResetFont();
            TEXTURE_PTR = AddFontFromBitmapArray(
                src.as_ptr(),
                TEXTURE_PTR,
                first_char,
                last_char,
                w,
                h,
                bits_per_pixel,
                byte_order,
            );
        }
    }
}
