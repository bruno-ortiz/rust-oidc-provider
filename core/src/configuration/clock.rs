use time::{OffsetDateTime, UtcOffset};

pub trait Clock {
    fn now(&self) -> OffsetDateTime;
}

pub struct UtcClock;

impl Clock for UtcClock {
    #[inline]
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

pub struct OffsetClock {
    offset: UtcOffset,
}

impl Clock for OffsetClock {
    #[inline]
    fn now(&self) -> OffsetDateTime {
        let now = OffsetDateTime::now_utc();
        now.to_offset(self.offset)
    }
}

pub enum ClockProvider {
    Utc(UtcClock),
    Offset(OffsetClock),
    Boxed(Box<dyn Clock + Send + Sync>),
}

impl Clock for ClockProvider {
    #[inline]
    fn now(&self) -> OffsetDateTime {
        match self {
            ClockProvider::Utc(inner) => inner.now(),
            ClockProvider::Offset(inner) => inner.now(),
            ClockProvider::Boxed(inner) => inner.now(),
        }
    }
}

impl Default for ClockProvider {
    fn default() -> Self {
        ClockProvider::Utc(UtcClock)
    }
}
