#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(unused_assignments)]
#![allow(unreachable_patterns)]
#![allow(unused_mut)]

pub fn add(a: i32, b: i32) -> i32 { return a.wrapping_add(b) }

pub fn mul(a: i32, b: i32) -> i32
{
  let mut sum: i32 = 0i32;
  for i in 0i32..b { sum = sum.wrapping_add(a) };
  return sum
}
