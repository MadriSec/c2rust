use ::libc;
extern "C" {
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn add(mut a: libc::c_int, mut b: libc::c_int) -> libc::c_int {
    return a + b;
}
#[no_mangle]
pub unsafe extern "C" fn mul(mut a: libc::c_int, mut b: libc::c_int) -> libc::c_int {
    let mut sum_0: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0 as libc::c_int;
    while i < b {
        sum_0 += a;
        i += 1;
        i;
    }
    return sum_0;
}
#[no_mangle]
pub unsafe extern "C" fn power(mut a: libc::c_int, mut n: libc::c_int) -> libc::c_int {
    let mut product: libc::c_int = 1 as libc::c_int;
    let mut i: libc::c_int = 0 as libc::c_int;
    while i < n {
        product *= a;
        i += 1;
        i;
    }
    return product;
}
#[no_mangle]
pub unsafe extern "C" fn divide(
    mut a: libc::c_int,
    mut b: libc::c_int,
    mut q: *mut libc::c_int,
) -> libc::c_int {
    if b != 0 as libc::c_int {
        *q = a / b;
        return 0 as libc::c_int;
    } else {
        return 1 as libc::c_int
    };
}
#[no_mangle]
pub unsafe extern "C" fn rsh(mut a: libc::c_int, mut n: libc::c_int) -> libc::c_int {
    let mut result: libc::c_int = 0 as libc::c_int;
    divide(a, power(2 as libc::c_int, n), &mut result);
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn sum(
    mut a: *mut libc::c_int,
    mut n: libc::c_uint,
) -> libc::c_int {
    let mut sum_0: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0 as libc::c_int;
    while (i as libc::c_uint) < n {
        sum_0 += *a.offset(i as isize);
        i += 1;
        i;
    }
    return sum_0;
}
unsafe fn main_0() -> libc::c_int {
    let mut array: *mut libc::c_int = malloc(
        (3 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<libc::c_int>() as libc::c_ulong),
    ) as *mut libc::c_int;
    let mut i: libc::c_int = 0 as libc::c_int;
    while i < 3 as libc::c_int {
        *array.offset(i as isize) = i;
        i += 1;
        i;
    }
    let mut total: libc::c_int = sum(array, 3 as libc::c_int as libc::c_uint);
    printf(b"%d\0" as *const u8 as *const libc::c_char, total);
    free(array as *mut libc::c_void);
    return 0 as libc::c_int;
}
pub fn main() {
    unsafe { ::std::process::exit(main_0() as i32) }
}
