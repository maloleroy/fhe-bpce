//! Data stored as raw bytes.

use tokio::io::AsyncReadExt;
const SIZE_LIMIT: u64 = 1024 * 1024;

pub struct BytesLoader {}

async fn get_file_size_hint(file: &tokio::fs::File) -> Option<usize> {
    file.metadata().await.ok()?.len().try_into().ok()
}

impl super::DataLoader<Vec<u8>> for BytesLoader {
    async fn load(file: tokio::fs::File) -> super::DataResult<Vec<u8>> {
        const DEFAULT_VEC_SIZE: usize = 100;

        let mut buffer =
            Vec::with_capacity(get_file_size_hint(&file).await.unwrap_or(DEFAULT_VEC_SIZE));

        file.take(SIZE_LIMIT).read_to_end(&mut buffer).await?;

        Ok(buffer)
    }
}
