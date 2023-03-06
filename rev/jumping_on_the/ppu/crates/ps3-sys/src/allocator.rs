use alloc::alloc::{GlobalAlloc, Layout};

pub struct Allocator;

#[global_allocator]
pub static ALLOCATOR: Allocator = Allocator;

// TODO: Better memory allocator (aligned mem, realloc etc)
// TODO: Native rust allocator?
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // let mut res = 0;

        // sysMemoryAllocate(layout.size(), SYS_MEMORY_ACCESS_RIGHT_ANY, &mut res);

        // res as usize as *mut u8
        libc::malloc(layout.size()).cast()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        libc::free(ptr.cast());
        // sysMemoryFree(ptr as usize as _);
    }
}
