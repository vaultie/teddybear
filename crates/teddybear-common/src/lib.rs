use std::error::Error;

pub trait HttpClient<R> {
    type Error: Error;

    fn get(&self, url: &str) -> impl Future<Output = Result<R, Self::Error>>;
}

impl<T, R> HttpClient<R> for &T
where
    T: HttpClient<R>,
{
    type Error = T::Error;

    #[inline]
    fn get(&self, url: &str) -> impl Future<Output = Result<R, Self::Error>> {
        <T as HttpClient<R>>::get(self, url)
    }
}
