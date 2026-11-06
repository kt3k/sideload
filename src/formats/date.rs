//! UTC calendar conversions (no time zones). Times are seconds since the
//! Unix epoch.

use super::{FormatError, FormatResult};

/// Seconds between the Unix epoch and the Apple (Core Foundation) epoch,
/// 2001-01-01T00:00:00Z.
pub const APPLE_EPOCH_OFFSET: i64 = 978_307_200;

/// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant's
/// algorithm).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`].
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// Broken-down UTC time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Civil {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

impl Civil {
    pub fn from_unix(secs: i64) -> Civil {
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400) as u32;
        let (year, month, day) = civil_from_days(days);
        Civil {
            year,
            month,
            day,
            hour: rem / 3600,
            minute: rem / 60 % 60,
            second: rem % 60,
        }
    }

    pub fn to_unix(self) -> i64 {
        days_from_civil(self.year, self.month, self.day) * 86_400
            + i64::from(self.hour) * 3600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ`, as used by XML plists and Apple HTTP headers.
pub fn format_iso8601(secs: i64) -> String {
    let c = Civil::from_unix(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        c.year, c.month, c.day, c.hour, c.minute, c.second
    )
}

/// Parses `YYYY-MM-DDTHH:MM:SS[.fff]Z`. Fractional seconds are truncated.
pub fn parse_iso8601(s: &str) -> FormatResult<i64> {
    let err = || FormatError::new(format!("invalid ISO 8601 date `{s}`"));
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return Err(err());
    }
    let rest = &s[19..];
    let rest = match rest.strip_prefix('.') {
        Some(frac) => {
            let digits = frac.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 {
                return Err(err());
            }
            &frac[digits..]
        }
        None => rest,
    };
    if rest != "Z" {
        return Err(err());
    }
    let num = |r: std::ops::Range<usize>| -> FormatResult<u32> {
        let part = &s[r];
        if part.bytes().all(|c| c.is_ascii_digit()) {
            part.parse().map_err(|_| err())
        } else {
            Err(err())
        }
    };
    let c = Civil {
        year: i64::from(num(0..4)?),
        month: num(5..7)?,
        day: num(8..10)?,
        hour: num(11..13)?,
        minute: num(14..16)?,
        second: num(17..19)?,
    };
    if !(1..=12).contains(&c.month)
        || !(1..=31).contains(&c.day)
        || c.hour > 23
        || c.minute > 59
        || c.second > 60
    {
        return Err(err());
    }
    Ok(c.to_unix())
}

/// DER UTCTime `YYMMDDHHMMSSZ` (years 1950-2049).
pub fn format_utc_time(secs: i64) -> FormatResult<String> {
    let c = Civil::from_unix(secs);
    if !(1950..=2049).contains(&c.year) {
        return Err(FormatError::new("UTCTime only covers 1950-2049"));
    }
    Ok(format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        c.year % 100,
        c.month,
        c.day,
        c.hour,
        c.minute,
        c.second
    ))
}

/// Current time in seconds since the Unix epoch.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_dates() {
        assert_eq!(parse_iso8601("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(
            parse_iso8601("2001-01-01T00:00:00Z").unwrap(),
            APPLE_EPOCH_OFFSET
        );
        assert_eq!(
            parse_iso8601("2026-11-06T12:34:56Z").unwrap(),
            1_793_968_496
        );
        assert_eq!(
            parse_iso8601("2026-11-06T12:34:56.789Z").unwrap(),
            1_793_968_496
        );
        assert_eq!(format_iso8601(1_793_968_496), "2026-11-06T12:34:56Z");
        assert_eq!(format_iso8601(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn civil_roundtrip() {
        for days in (-800_000..800_000).step_by(997) {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }

    #[test]
    fn rejects_bad_dates() {
        for bad in [
            "2026-11-06 12:34:56Z",
            "2026-13-06T12:34:56Z",
            "2026-11-06T12:34:56",
            "2026-11-06T12:34:56+09:00",
        ] {
            assert!(parse_iso8601(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn utc_time() {
        assert_eq!(format_utc_time(1_793_968_496).unwrap(), "261106123456Z");
        assert!(format_utc_time(parse_iso8601("2050-01-01T00:00:00Z").unwrap()).is_err());
    }
}
