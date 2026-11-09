//! ADI ABI marshalling over interpreted guest calls; all pointers are guest addresses.
use super::runtime::Runtime;
use sideload::anisette::local_adi::{AdiResult, provisioning::Engine};
use std::path::Path;
const DSID: u64 = u64::MAX - 1;
const BUDGET: usize = 50_000_000;
const MAX_OUTPUT: usize = 4 * 1024 * 1024;

pub struct Adi {
    runtime: Runtime,
}
fn status(code: u64, operation: &str) -> AdiResult<()> {
    let code = code as u32 as i32;
    if code == 0 {
        Ok(())
    } else {
        Err(format!("interpreted ADI {operation} returned {code}"))
    }
}
fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}
impl Adi {
    pub fn open(libraries: &Path, storage: &Path, android_id: &str) -> AdiResult<Self> {
        if android_id.len() != 16 || !android_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid Android identifier".into());
        }
        let read = |name: &str| -> AdiResult<Vec<u8>> {
            let p = libraries.join(name);
            let m = std::fs::symlink_metadata(&p).map_err(|_| "missing ADI library")?;
            if !m.is_file() || m.file_type().is_symlink() || m.len() > 32 * 1024 * 1024 {
                return Err("invalid ADI library file".into());
            }
            std::fs::read(p).map_err(|_| "cannot read ADI library".into())
        };
        let mut runtime = Runtime::new(&read("libCoreADI.so")?, &read("libstoreservicescore.so")?)
            .map_err(error)?;
        runtime.set_storage(storage).map_err(error)?;
        for entry in [
            "aslgmuibau",
            "rsegvyrt87",
            "uv5t6nhkui",
            "fy34trz2st",
            "jk24uiwqrg",
            "qi864985u0",
            "kq56gsgHG6",
            "nf92ngaK92",
            "Sph98paBcz",
        ] {
            if runtime.symbol(entry).is_none() {
                return Err("missing ADI entry point".into());
            }
        }
        let path = runtime.c_string("/adi").map_err(error)?;
        let id = runtime.c_string(android_id).map_err(error)?;
        let result = (|| {
            status(
                runtime.call("kq56gsgHG6", &[path], BUDGET).map_err(error)?,
                "set library path",
            )?;
            status(
                runtime.call("nf92ngaK92", &[path], BUDGET).map_err(error)?,
                "set provisioning path",
            )?;
            status(
                runtime
                    .call("Sph98paBcz", &[id, 16], BUDGET)
                    .map_err(error)?,
                "set identifier",
            )
        })();
        runtime.release(path).map_err(error)?;
        runtime.release(id).map_err(error)?;
        result?;
        Ok(Self { runtime })
    }
    fn dispose(&mut self, pointer: u64) -> AdiResult<()> {
        if pointer != 0 {
            self.runtime
                .call("jk24uiwqrg", &[pointer], BUDGET)
                .map_err(error)?;
        }
        Ok(())
    }
    fn output(&mut self, pointer: u64, length: u64) -> AdiResult<Vec<u8>> {
        let result = if pointer == 0 || length == 0 || length > MAX_OUTPUT as u64 {
            Err("invalid ADI output buffer".into())
        } else {
            self.runtime
                .memory
                .read(pointer, length as usize)
                .map(|b| b.to_vec())
                .map_err(|_| "ADI output outside guest memory".into())
        };
        let disposal = self.dispose(pointer);
        result.and_then(|bytes| disposal.map(|_| bytes))
    }
    fn scratch<T>(
        &mut self,
        inputs: &[&[u8]],
        call: impl FnOnce(&mut Self, &[u64]) -> AdiResult<T>,
    ) -> AdiResult<T> {
        let mut addresses = Vec::new();
        let result = (|| {
            for input in inputs {
                addresses.push(self.runtime.buffer(input).map_err(error)?);
            }
            call(self, &addresses)
        })();
        for pointer in addresses {
            let _ = self.runtime.release(pointer);
        }
        result
    }
    fn word(&self, address: u64, size: usize) -> AdiResult<u64> {
        let bytes = self
            .runtime
            .memory
            .read(address, size)
            .map_err(|_| "invalid ADI output slot")?;
        let mut out = [0; 8];
        out[..size].copy_from_slice(bytes);
        Ok(u64::from_le_bytes(out))
    }
}
impl Engine for Adi {
    fn is_provisioned(&mut self) -> AdiResult<bool> {
        match self
            .runtime
            .call("aslgmuibau", &[DSID], BUDGET)
            .map_err(error)? as u32 as i32
        {
            0 => Ok(true),
            -45061 => Ok(false),
            n => Err(format!("interpreted ADI provisioning query returned {n}")),
        }
    }
    fn start(&mut self, spim: &[u8]) -> AdiResult<(Vec<u8>, u32)> {
        self.scratch(&[spim, &[0; 24]], |this, p| {
            let code = this
                .runtime
                .call(
                    "rsegvyrt87",
                    &[DSID, p[0], spim.len() as u64, p[1], p[1] + 8, p[1] + 16],
                    BUDGET,
                )
                .map_err(error)?;
            let pointer = this.word(p[1], 8)?;
            let length = this.word(p[1] + 8, 4)?;
            let session = this.word(p[1] + 16, 4)? as u32;
            if let Err(e) = status(code, "start provisioning") {
                let _ = this.dispose(pointer);
                return Err(e);
            }
            match this.output(pointer, length) {
                Ok(bytes) => Ok((bytes, session)),
                Err(e) => {
                    this.destroy(session);
                    Err(e)
                }
            }
        })
    }
    fn finish(&mut self, session: u32, ptm: &[u8], tk: &[u8]) -> AdiResult<()> {
        self.scratch(&[ptm, tk], |this, p| {
            status(
                this.runtime
                    .call(
                        "uv5t6nhkui",
                        &[
                            session as u64,
                            p[0],
                            ptm.len() as u64,
                            p[1],
                            tk.len() as u64,
                        ],
                        BUDGET,
                    )
                    .map_err(error)?,
                "finish provisioning",
            )
        })
    }
    fn destroy(&mut self, session: u32) {
        let _ = self.runtime.call("fy34trz2st", &[session as u64], BUDGET);
    }
    fn otp(&mut self) -> AdiResult<(Vec<u8>, Vec<u8>)> {
        self.scratch(&[&[0; 32]], |this, p| {
            let code = this
                .runtime
                .call(
                    "qi864985u0",
                    &[DSID, p[0], p[0] + 8, p[0] + 16, p[0] + 24],
                    BUDGET,
                )
                .map_err(error)?;
            let mid = this.word(p[0], 8)?;
            let mid_len = this.word(p[0] + 8, 4)?;
            let otp = this.word(p[0] + 16, 8)?;
            let otp_len = this.word(p[0] + 24, 4)?;
            if let Err(e) = status(code, "request OTP") {
                let _ = this.dispose(mid);
                let _ = this.dispose(otp);
                return Err(e);
            }
            let m = this.output(mid, mid_len);
            let o = this.output(otp, otp_len);
            Ok((m?, o?))
        })
    }
}
