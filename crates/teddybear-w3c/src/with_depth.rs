use std::marker::PhantomData;

#[derive(thiserror::Error, Debug)]
#[error("recursion limit reached")]
pub struct RecursionLimitReached;

pub trait DepthLimiter: Sized {
    type Error: From<RecursionLimitReached>;

    fn with_depth<T, F: FnOnce(&mut Self) -> Result<T, Self::Error>>(
        &mut self,
        f: F,
    ) -> Result<T, Self::Error>;
}

pub fn init_with_depth<E: From<RecursionLimitReached>>(
    limit: usize,
) -> impl DepthLimiter<Error = E> {
    DepthToken(limit, PhantomData)
}

struct DepthToken<E>(usize, PhantomData<E>);

impl<E: From<RecursionLimitReached>> DepthLimiter for DepthToken<E> {
    type Error = E;

    fn with_depth<T, F: FnOnce(&mut Self) -> Result<T, Self::Error>>(
        &mut self,
        f: F,
    ) -> Result<T, Self::Error> {
        self.0 -= 1;

        if self.0 == 0 {
            return Err(RecursionLimitReached.into());
        }

        let val = f(self)?;

        self.0 += 1;

        Ok(val)
    }
}
