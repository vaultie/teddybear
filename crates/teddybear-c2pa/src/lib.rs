pub mod signer;

use std::io::{Read, Seek, Write};

use c2pa::Signer;

pub use c2pa::ManifestDefinition;

#[derive(Default, Debug)]
pub struct Builder {
    inner: c2pa::Builder,
}

impl Builder {
    pub fn set_thumbnail<R: Read + Seek>(
        &mut self,
        source: &mut R,
        format: &str,
    ) -> c2pa::Result<()> {
        self.inner.set_thumbnail(format, source)?;
        Ok(())
    }

    pub fn add_resource<R: Read + Seek + Send>(
        &mut self,
        source: &mut R,
        id: &str,
    ) -> c2pa::Result<()> {
        self.inner.add_resource(id, source)?;
        Ok(())
    }

    pub fn finalize<R: Read + Seek + Send, W: Write + Read + Seek + Send, S: Signer>(
        mut self,
        source: &mut R,
        dest: &mut W,
        format: &str,
        definition: ManifestDefinition,
        signer: &S,
    ) -> c2pa::Result<Vec<u8>> {
        self.inner.definition = definition;
        self.inner.sign(signer, format, source, dest)
    }
}
