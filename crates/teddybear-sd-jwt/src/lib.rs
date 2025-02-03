use std::str::FromStr;

use ssi_jwk::JWK;
use ssi_jwt::JWTClaims;
use ssi_sd_jwt::{JsonPointer, SdJwtBuf};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("the provided JWT is incorrect")]
    InvalidJwt,

    #[error("JWT header is incorrect")]
    InvalidHeader,

    #[error("invalid JSON pointer: {0}")]
    InvalidJsonPointer(String),

    #[error("JWT signature verification failed")]
    SignatureVerificationFailed,
}

#[derive(Clone)]
pub struct SdJwt(SdJwtBuf);

impl SdJwt {
    pub fn new(jwt: &str) -> Result<Self, Error> {
        Ok(Self(
            SdJwtBuf::from_str(jwt).map_err(|_| Error::InvalidJwt)?,
        ))
    }

    pub fn parse_untrusted(&self) -> Result<JWTClaims, Error> {
        let revealed = self.0.decode_reveal_any().map_err(|_| Error::InvalidJwt)?;
        Ok(revealed.into_claims())
    }

    pub async fn verify(&self, jwk: &JWK) -> Result<(), Error> {
        self.0
            .jwt()
            .verify(jwk)
            .await
            .map_err(|_| Error::SignatureVerificationFailed)?
            .map_err(|_| Error::SignatureVerificationFailed)
    }

    pub fn disclose<'a, I>(&self, pointers: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let pointers = pointers
            .into_iter()
            .map(|pointer| {
                JsonPointer::from_str_const(pointer)
                    .map_err(|e| Error::InvalidJsonPointer(e.0.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let cloned = self.clone();
        let decoded = cloned
            .0
            .decode_reveal_any()
            .map_err(|_| Error::InvalidJwt)?
            .retaining(&pointers);

        Ok(Self(decoded.into_encoded()))
    }
}

impl AsRef<str> for SdJwt {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}
