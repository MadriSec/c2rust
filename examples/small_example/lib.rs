#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#[no_mangle]
pub extern "C" fn add(mut a: i32, mut b: i32) -> i32 {
    return a + b;
}
#[no_mangle]
pub extern "C" fn mul(mut a: i32, mut b: i32) -> i32 {
    let mut sum_0: i32 = 0 as i32;
    let mut i: i32 = 0 as i32;
    while i < b {
        sum_0 += a;
        i += 1;
        i;
    }
    return sum_0;
}
#[no_mangle]
pub extern "C" fn power(mut a: i32, mut n: i32) -> i32 {
    let mut product: i32 = 1 as i32;
    let mut i: i32 = 0 as i32;
    while i < n {
        product *= a;
        i += 1;
        i;
    }
    return product;
}
#[no_mangle]
pub extern "C" fn div(mut a: i32, mut b: i32, mut q: &mut i32) -> i32 {
    if b != 0 as i32 {
        *q = a / b;
        return 0 as i32;
    } else {
        return 1 as i32;
    };
}
#[no_mangle]
pub extern "C" fn rsh(mut a: i32, mut n: i32) -> i32 {
    let mut result: i32 = 0 as i32;
    div(a, power(2 as i32, n), &mut result);
    return result;
}
#[no_mangle]
pub extern "C" fn sum(mut a: &mut i32, mut n: u32) -> i32 {
    // a is supposed to be of type &mut i32
    let mut sum_0: i32 = 0 as i32;
    let mut i: i32 = 0 as i32;
    while (i as u32) < n {
        sum_0 += *a.offset(i as isize);
        i += 1;
        i;
    }
    return sum_0;
}
fn main() {}
