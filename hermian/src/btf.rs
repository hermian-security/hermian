//! Minimal BTF reader: enough to find struct member offsets in the running
//! kernel's `/sys/kernel/btf/vmlinux`. Used to hand `task_struct` offsets to the
//! eBPF programs so one object works on every kernel version.
//!
//! Format reference: `include/uapi/linux/btf.h`.

use std::fs;

use anyhow::{anyhow, Context, Result};

const BTF_MAGIC: u16 = 0xEB9F;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;

const KIND_INT: u32 = 1;
const KIND_PTR: u32 = 2;
const KIND_ARRAY: u32 = 3;
const KIND_ENUM: u32 = 6;
const KIND_FWD: u32 = 7;
const KIND_TYPEDEF: u32 = 8;
const KIND_VOLATILE: u32 = 9;
const KIND_CONST: u32 = 10;
const KIND_RESTRICT: u32 = 11;
const KIND_FUNC: u32 = 12;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_FLOAT: u32 = 16;
const KIND_DECL_TAG: u32 = 17;
const KIND_TYPE_TAG: u32 = 18;
const KIND_ENUM64: u32 = 19;

pub struct Btf {
    types: Vec<u8>,
    strings: Vec<u8>,
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

impl Btf {
    pub fn from_sys_fs() -> Result<Btf> {
        let data = fs::read("/sys/kernel/btf/vmlinux").context("read /sys/kernel/btf/vmlinux")?;
        Self::parse(&data)
    }

    pub fn parse(data: &[u8]) -> Result<Btf> {
        if u16_at(data, 0) != Some(BTF_MAGIC) {
            return Err(anyhow!("bad BTF magic"));
        }
        let hdr_len = u32_at(data, 4).ok_or_else(|| anyhow!("short BTF"))? as usize;
        let type_off = u32_at(data, 8).ok_or_else(|| anyhow!("short BTF"))? as usize;
        let type_len = u32_at(data, 12).ok_or_else(|| anyhow!("short BTF"))? as usize;
        let str_off = u32_at(data, 16).ok_or_else(|| anyhow!("short BTF"))? as usize;
        let str_len = u32_at(data, 20).ok_or_else(|| anyhow!("short BTF"))? as usize;
        let types = data
            .get(hdr_len + type_off..hdr_len + type_off + type_len)
            .ok_or_else(|| anyhow!("BTF type section out of range"))?
            .to_vec();
        let strings = data
            .get(hdr_len + str_off..hdr_len + str_off + str_len)
            .ok_or_else(|| anyhow!("BTF string section out of range"))?
            .to_vec();
        Ok(Btf { types, strings })
    }

    fn name(&self, off: u32) -> &str {
        let start = off as usize;
        let end = self.strings[start..]
            .iter()
            .position(|b| *b == 0)
            .map(|p| start + p)
            .unwrap_or(self.strings.len());
        std::str::from_utf8(&self.strings[start..end]).unwrap_or("")
    }

    /// Byte offset of `member` within `struct name`, or None.
    pub fn struct_member_offset(&self, name: &str, member: &str) -> Option<u32> {
        let mut o = 0usize;
        while o + 12 <= self.types.len() {
            let name_off = u32_at(&self.types, o)?;
            let info = u32_at(&self.types, o + 4)?;
            let size_or_type = u32_at(&self.types, o + 8)?;
            let kind = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;
            let kflag = (info >> 31) & 1;
            let body = o + 12;
            let body_len = match kind {
                KIND_INT => 4,
                KIND_PTR | KIND_FWD | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT
                | KIND_FUNC | KIND_FLOAT | KIND_TYPE_TAG => 0,
                KIND_ARRAY => 12,
                KIND_STRUCT | KIND_UNION => 12 * vlen,
                KIND_ENUM => 8 * vlen,
                KIND_ENUM64 => 12 * vlen,
                KIND_FUNC_PROTO => 8 * vlen,
                KIND_VAR => 4,
                KIND_DATASEC => 12 * vlen,
                KIND_DECL_TAG => 4,
                _ => return None, // unknown kind: cannot continue safely
            };
            if kind == KIND_STRUCT && self.name(name_off) == name {
                let _ = size_or_type;
                for i in 0..vlen {
                    let m = body + i * 12;
                    let m_name = u32_at(&self.types, m)?;
                    let m_off = u32_at(&self.types, m + 8)?;
                    if self.name(m_name) == member {
                        // With kflag the offset field packs bitfield size in the
                        // top byte; the low 24 bits are the bit offset.
                        let bits = if kflag == 1 {
                            m_off & 0x00ff_ffff
                        } else {
                            m_off
                        };
                        return Some(bits / 8);
                    }
                }
                return None;
            }
            o = body + body_len;
        }
        None
    }
}

/// `(real_parent offset, tgid offset)` in `task_struct`, if BTF is available.
pub fn task_struct_offsets() -> Option<(u32, u32)> {
    let btf = Btf::from_sys_fs().ok()?;
    let parent = btf.struct_member_offset("task_struct", "real_parent")?;
    let tgid = btf.struct_member_offset("task_struct", "tgid")?;
    Some((parent, tgid))
}
