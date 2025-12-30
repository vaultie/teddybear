use std::error::Error;

pub use ssi_status::bitstring_status_list::BitstringStatusListCredential;

pub trait StatusListFetcher {
    type Error: Error;

    fn fetch(
        &self,
        url: &str,
    ) -> impl Future<Output = Result<BitstringStatusListCredential, Self::Error>>;
}

impl<T: StatusListFetcher> StatusListFetcher for &T {
    type Error = T::Error;

    fn fetch(
        &self,
        url: &str,
    ) -> impl Future<Output = Result<BitstringStatusListCredential, Self::Error>> {
        <T as StatusListFetcher>::fetch(self, url)
    }
}
