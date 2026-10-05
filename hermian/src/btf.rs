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
        let section = |off: usize, len: usize, what: &str| -> Result<Vec<u8>> {
            let start = hdr_len
                .checked_add(off)
                .ok_or_else(|| anyhow!("BTF {} section out of range", what))?;
            let end = start
                .checked_add(len)
                .ok_or_else(|| anyhow!("BTF {} section out of range", what))?;
            Ok(data
                .get(start..end)
                .ok_or_else(|| anyhow!("BTF {} section out of range", what))?
                .to_vec())
        };
        let types = section(type_off, type_len, "type")?;
        let strings = section(str_off, str_len, "string")?;
        Ok(Btf { types, strings })
    }

    /// The string at `off`, or "" if the offset is out of range (a corrupt or
    /// unexpected BTF blob must not panic the daemon).
    fn name(&self, off: u32) -> &str {
        let start = off as usize;
        let Some(tail) = self.strings.get(start..) else {
            return "";
        };
        let end = tail.iter().position(|b| *b == 0).unwrap_or(tail.len());
        std::str::from_utf8(&tail[..end]).unwrap_or("")
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny BTF blob: one struct `s` with members `a` (offset 0) and
    /// `b` (bit offset 64).
    fn blob(name_off_b: u32) -> Vec<u8> {
        let strings = b"\0s\0a\0b\0".to_vec();
        let mut types = Vec::new();
        let push = |v: &mut Vec<u8>, x: u32| v.extend_from_slice(&x.to_le_bytes());
        push(&mut types, 1); // name "s"
        push(&mut types, (KIND_STRUCT << 24) | 2); // kind, vlen 2
        push(&mut types, 16); // size
        for (name, off) in [(3u32, 0u32), (name_off_b, 64)] {
            push(&mut types, name);
            push(&mut types, 0); // type
            push(&mut types, off);
        }
        let mut d = Vec::new();
        d.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        d.extend_from_slice(&[1, 0]); // version, flags
        let push_d = |v: &mut Vec<u8>, x: u32| v.extend_from_slice(&x.to_le_bytes());
        push_d(&mut d, 24); // hdr_len
        push_d(&mut d, 0); // type_off
        push_d(&mut d, types.len() as u32);
        push_d(&mut d, types.len() as u32); // str_off
        push_d(&mut d, strings.len() as u32);
        d.extend_from_slice(&types);
        d.extend_from_slice(&strings);
        d
    }

    #[test]
    fn finds_member_offsets() {
        let btf = Btf::parse(&blob(5)).unwrap();
        assert_eq!(btf.struct_member_offset("s", "a"), Some(0));
        assert_eq!(btf.struct_member_offset("s", "b"), Some(8));
        assert_eq!(btf.struct_member_offset("s", "c"), None);
    }

    #[test]
    fn corrupt_input_does_not_panic() {
        // A member name offset far past the string table.
        let btf = Btf::parse(&blob(0xFFFF_FF00)).unwrap();
        assert_eq!(btf.struct_member_offset("s", "b"), None);
        // Section lengths that overflow or run past the end.
        let mut d = blob(5);
        d[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Btf::parse(&d).is_err());
        assert!(Btf::parse(&[0u8; 3]).is_err());
    }
}
