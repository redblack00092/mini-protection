/// 프로세스 간 상태 공유 (rate counter, blocklist 등)를 위한 공유 메모리 래퍼.
/// `shared_memory` crate를 사용하며, 레이아웃은 고정 크기 구조체로 정의한다.
pub struct SharedState {
    // TODO: ShmemConf handle, mapped region pointer
}

impl SharedState {
    pub fn open_or_create(name: &str, size: usize) -> anyhow::Result<Self> {
        todo!("open or create named shared memory region")
    }

    pub fn as_slice(&self) -> &[u8] {
        todo!()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        todo!()
    }
}
