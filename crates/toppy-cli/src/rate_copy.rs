use std::io::{self, Read, Write};
use std::time::Duration;
use toppy_core::config::SessionRateLimit;
use toppy_core::rate::TokenBucket;

pub fn copy_rate_limited<R: Read, W: Write>(
    reader: R,
    writer: W,
    limit: SessionRateLimit,
) -> io::Result<u64> {
    let start = std::time::Instant::now();
    copy_rate_limited_with(
        reader,
        writer,
        limit,
        || start.elapsed(),
        std::thread::sleep,
    )
}

fn copy_rate_limited_with<R: Read, W: Write, N: FnMut() -> Duration, S: FnMut(Duration)>(
    mut reader: R,
    mut writer: W,
    limit: SessionRateLimit,
    mut now: N,
    mut sleep: S,
) -> io::Result<u64> {
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0u64;

    if !limit.is_enabled() {
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                return Ok(total);
            }
            writer.write_all(&buf[..n])?;
            total = total.saturating_add(n as u64);
        }
    }

    let mut bucket = TokenBucket::new(limit.burst_bytes, limit.bytes_per_sec);
    let capacity = bucket.capacity().max(1) as usize;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Ok(total);
        }

        let mut offset = 0usize;
        while offset < n {
            let chunk_len = (n - offset).min(capacity);
            let tokens = chunk_len as u64;
            loop {
                let t = now();
                if bucket.try_take(tokens, t) {
                    break;
                }
                let wait = bucket
                    .wait_time(tokens, t)
                    .ok_or_else(|| io::Error::other("rate limiter stalled"))?;
                sleep(wait);
            }
            writer.write_all(&buf[offset..offset + chunk_len])?;
            offset += chunk_len;
            total = total.saturating_add(chunk_len as u64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::Cursor;

    #[test]
    fn disabled_rate_limit_copies_without_sleep() {
        let input = b"hello".to_vec();
        let mut out = Vec::new();
        let slept = Cell::new(Duration::ZERO);
        let now = Cell::new(Duration::ZERO);

        let n = copy_rate_limited_with(
            Cursor::new(input.clone()),
            &mut out,
            SessionRateLimit::disabled(),
            || now.get(),
            |d| slept.set(slept.get() + d),
        )
        .expect("copy");

        assert_eq!(n, 5);
        assert_eq!(out, input);
        assert_eq!(slept.get(), Duration::ZERO);
    }

    #[test]
    fn rate_limit_sleeps_to_throttle() {
        let input = b"hello".to_vec();
        let mut out = Vec::new();
        let slept = Cell::new(Duration::ZERO);
        let now = Cell::new(Duration::ZERO);

        let n = copy_rate_limited_with(
            Cursor::new(input.clone()),
            &mut out,
            SessionRateLimit {
                bytes_per_sec: 1,
                burst_bytes: 1,
            },
            || now.get(),
            |d| {
                slept.set(slept.get() + d);
                now.set(now.get() + d);
            },
        )
        .expect("copy");

        // With 1-byte burst and 1 byte/sec, "hello" (5 bytes) requires 4 seconds of waiting.
        assert_eq!(n, 5);
        assert_eq!(out, input);
        assert_eq!(slept.get(), Duration::from_secs(4));
    }
}
