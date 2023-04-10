use anyhow::{anyhow, Context, Result};
use btf::types::{BtfConst, BtfIntEncoding, BtfRestrict, BtfType, BtfTypedef, BtfVolatile};
use faerie::{ArtifactBuilder, Decl, SectionKind};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};
use target_lexicon::triple;

/// Currently, btfdump doesn't support load BTF from a btf archive
/// So if we want to use btf archive, we have to wrap that into an ELF..
pub fn create_elf_with_btf_section(btf_data: &[u8], is_64: bool) -> Result<Vec<u8>> {
    let mut obj = ArtifactBuilder::new(if is_64 {
        triple!("x86_64-unknown-unknown-unknown-elf")
    } else {
        triple!("i386-unknown-unknown-unknown-elf")
    })
    .name("btf-archive.bpf.o".into())
    .finish();
    obj.declare(".BTF", Decl::section(SectionKind::Data))?;
    obj.define(".BTF", btf_data.to_vec())?;
    Ok(obj.emit()?)
}

// Try to get the btf file of the running system under the archive directory
pub fn get_current_system_btf_file(archive_path: &Path) -> Result<PathBuf> {
    let release_info =
        os_release::OsRelease::new().with_context(|| anyhow!("Failed to load /etc/os-releases"))?;
    let uname = uname_rs::Uname::new().with_context(|| anyhow!("Failed to call uname"))?;
    let btf_path = format!(
        "{}/{}/{}/{}.btf",
        release_info.id, release_info.version, uname.machine, uname.release
    );
    Ok(archive_path.join(btf_path))
}

pub trait BtfHelper {
    fn resolve_real_type(&self, ty: u32) -> Result<u32>;
    fn is_char(&self, ty: u32) -> Result<bool>;
    fn is_char_array(&self, ty: u32) -> Result<bool>;
}

impl<'a> BtfHelper for btf::types::Btf<'a> {
    fn resolve_real_type(&self, ty: u32) -> Result<u32> {
        let btf_ty = self
            .types()
            .get(ty as usize)
            .ok_or_else(|| anyhow!("Invalid type: {}", ty))?;

        Ok(match btf_ty {
            BtfType::Typedef(BtfTypedef { type_id, .. })
            | BtfType::Volatile(BtfVolatile { type_id })
            | BtfType::Const(BtfConst { type_id })
            | BtfType::Restrict(BtfRestrict { type_id }) => self.resolve_real_type(*type_id)?,
            _ => ty,
        })
    }
    fn is_char(&self, ty: u32) -> Result<bool> {
        let ty = self.resolve_real_type(ty)?;
        #[allow(clippy::match_like_matches_macro)]
        Ok(match self.type_by_id(ty) {
            BtfType::Int(btf_int)
                if matches!(btf_int.encoding, BtfIntEncoding::Char) || btf_int.name == "char" =>
            {
                true
            }
            _ => false,
        })
    }
    fn is_char_array(&self, ty: u32) -> Result<bool> {
        let ty = self.resolve_real_type(ty)?;
        Ok(
            matches!(self.type_by_id(ty), BtfType::Array(arr) if self.is_char(self.resolve_real_type(arr.val_type_id)?)?),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{btf_container::BtfContainer, tests::get_assets_dir};

    use super::create_elf_with_btf_section;

    #[test]
    fn test_create_elf_with_btf_section() {
        let assets_dir = get_assets_dir();
        let btf_from_elf = BtfContainer::new_from_binary(
            &std::fs::read(assets_dir.join("simple_prog").join("simple_prog.bpf.o")).unwrap(),
        )
        .unwrap();
        let btf_from_archive = BtfContainer::new_from_binary(
            &create_elf_with_btf_section(
                &std::fs::read(assets_dir.join("simple_prog").join("simple_prog.btf")).unwrap(),
                true,
            )
            .unwrap(),
        )
        .unwrap();
        let elf_btf = btf_from_elf.borrow_btf().types();
        let archive_btf = btf_from_archive.borrow_btf().types();
        assert_eq!(elf_btf.len(), archive_btf.len());
        for (a, b) in elf_btf.iter().zip(archive_btf.iter()) {
            assert_eq!(a.to_string(), b.to_string());
        }
    }
}
