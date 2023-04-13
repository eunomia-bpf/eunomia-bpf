//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use std::fmt::Write;
/// Print a character-drawn log2 hist, filled with val_type
pub fn print_log2_hist(vals: &[u32], val_type: impl AsRef<str>, out: &mut String) {
    let val_type = val_type.as_ref();
    let stars_max = 40;
    let mut idx_max = -1;
    let mut val_max = 0u32;
    for (i, v) in vals.iter().enumerate() {
        if *v > 0 {
            idx_max = i as i32;
        }
        if *v > val_max {
            val_max = *v;
        }
    }
    if idx_max < 0 {
        return;
    }
    // printf("%*s%-*s : count    distribution\n", idx_max <= 32 ? 5 : 15, "",    idx_max <= 32 ? 19 : 29, val_type);
    writeln!(
        out,
        "{:>w1$}{:<w2$} : count    distribution",
        "",
        val_type,
        w1 = if idx_max <= 32 { 5 } else { 15 },
        w2 = if idx_max <= 32 { 19 } else { 29 },
    )
    .unwrap();
    let stars = if idx_max <= 32 {
        stars_max
    } else {
        stars_max / 2
    };
    for (i, val) in vals.iter().enumerate().take(idx_max as usize + 1) {
        let mut low = (1u64 << (i + 1)) >> 1;
        let high = (1u64 << (i + 1)) - 1;
        if low == high {
            low -= 1;
        }
        let width = if idx_max <= 32 { 10 } else { 20 };
        //  printf("%*lld -> %-*lld : %-8d |", width, low, width, high, val);
        write!(out, "{low:>width$} -> {high:<width$} : {val:<8} |").unwrap();
        print_stars(*val, val_max, stars as _, out);
        writeln!(out, "|").unwrap();
    }
}

fn print_stars(val: u32, val_max: u32, width: i32, out: &mut String) {
    let num_stars = (val.min(val_max) * width as u32 / val_max) as i32;
    let num_spaces = width - num_stars;
    let need_plus = val > val_max;
    for _ in 0..num_stars {
        out.push('*');
    }
    for _ in 0..num_spaces {
        out.push(' ');
    }
    if need_plus {
        out.push('+')
    }
}

#[cfg(test)]
mod tests {
    use super::print_log2_hist;

    #[test]
    fn test_log2_hist() {
        let mut out = String::default();
        let vals = [1, 1 << 3, (1 << 7) + 10, 1 << 9, (1 << 10) + 5, 1 << 4];
        print_log2_hist(&vals[..], "qaq", &mut out);
        println!("{:?}", out);
        assert_eq!(out,"     qaq                 : count    distribution\n         0 -> 1          : 1        |                                        |\
        \n         2 -> 3          : 8        |                                        |\
        \n         4 -> 7          : 138      |*****                                   |\
        \n         8 -> 15         : 512      |*******************                     |\
        \n        16 -> 31         : 1029     |****************************************|\
        \n        32 -> 63         : 16       |                                        |\n");
    }
}
