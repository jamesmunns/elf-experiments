use object::{
    elf::{FileHeader32, PT_LOAD},
    read::elf::{FileHeader, ProgramHeader},
    LittleEndian, Object, ObjectSection,
};
use std::{
    cmp::Ordering,
    error::Error,
    fs,
    io::{ErrorKind, Write},
    ops::Range,
};

/// Reads a file and displays the content of the ".boot" section.
fn main() -> Result<(), Box<dyn Error>> {
    // let bin_data = fs::read("../../elfs/soup-app-demo.elf")?;
    let bin_data = fs::read("../../elfs/stage0-v2_0_0.elf")?;
    let obj_file = object::File::parse(&*bin_data)?;

    match obj_file.format() {
        object::BinaryFormat::Elf => {}
        _ => panic!("Unsupported format. Only elf."),
    }

    assert!(obj_file.is_little_endian(), "Only LE supported");

    let file_kind = object::FileKind::parse(&*bin_data)?;

    match file_kind {
        object::FileKind::Elf32 => {}
        fk => panic!("Unsupported file type: {:?}", fk),
    }

    let elf_header = FileHeader32::<LittleEndian>::parse(&*bin_data)?;
    let endian = elf_header.endian()?;

    let mut lowest_addr = u64::MAX;
    let mut highest_addr = u64::MIN;
    let mut bin_contents = vec![];

    // NOTE: Using https://github.com/probe-rs/probe-rs/blob/5a29e83847118c3999a2ca0ab017f080719b8ae5/probe-rs/src/flashing/download.rs#L194
    // as a reference
    for segment in elf_header.program_headers(endian, &*bin_data)? {
        let p_paddr: u64 = segment.p_paddr(endian).into();
        let p_vaddr: u64 = segment.p_vaddr(endian).into();
        let flags = segment.p_flags(endian);

        let segment_data = segment.data(endian, &*bin_data).unwrap();

        let load = segment.p_type(endian) == PT_LOAD;
        let sz = segment_data.len();

        println!("{p_paddr:08X}, {p_vaddr:08X}, {flags:08X}, sz: {sz}, l?: {load}");

        let (segment_offset, segment_filesize) = segment.file_range(endian);

        let sector: core::ops::Range<u64> = segment_offset..segment_offset + segment_filesize;

        for section in obj_file.sections() {
            let (section_offset, section_filesize) = match section.file_range() {
                Some(range) => range,
                None => continue,
            };

            if sector.contains_range(&(section_offset..section_offset + section_filesize)) {
                println!("  -> Matching section: {:?}", section.name()?);
                println!("  -> {:08X}, {}", p_paddr, segment_data.len());

                lowest_addr = lowest_addr.min(p_paddr);
                let fsz: u32 = segment.p_filesz(endian);
                let fsz64: u64 = fsz.into();
                assert_eq!(segment_data.len(), fsz.try_into()?);

                highest_addr = highest_addr.max(p_paddr + fsz64);
                bin_contents.push((p_paddr, segment_data));

                for (offset, relocation) in section.relocations() {
                    panic!(
                        "I can't do relocations sorry: ({}) {:?}, {:?}",
                        section.name()?,
                        offset,
                        relocation,
                    );
                }
            }
        }
    }

    match lowest_addr.cmp(&highest_addr) {
        Ordering::Less => {}
        Ordering::Equal => panic!("Empty file?"),
        Ordering::Greater if bin_contents.is_empty() => panic!("No sections found?"),
        Ordering::Greater => panic!("Start is after end?"),
    }

    let ttl_len: usize = (highest_addr - lowest_addr).try_into()?;
    println!("start: 0x{lowest_addr:08X}");
    println!("end:   0x{highest_addr:08X}");
    println!("size:  {ttl_len}");

    let mut output = vec![0x00u8; ttl_len];
    for (addr, data) in bin_contents.iter() {
        let adj_addr = (addr - lowest_addr).try_into()?;
        let size = data.len();
        output[adj_addr..][..size].copy_from_slice(data);
    }

    let name = format!("./target/output_0x{lowest_addr:08X}.bin");
    match std::fs::remove_file(&name) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => panic!("{e:?}"),
    }
    let mut outfile = std::fs::File::create(&name)?;
    outfile.write_all(&output)?;

    Ok(())
}

///////
// https://github.com/probe-rs/probe-rs/blob/ef635f213a2741ebac4c1ccfb700230992dd10a6/probe-rs-target/src/memory.rs#L102-L130
///////

pub trait MemoryRange {
    /// Returns true if `self` contains `range` fully.
    fn contains_range(&self, range: &Range<u64>) -> bool;

    /// Returns true if `self` intersects `range` partially.
    fn intersects_range(&self, range: &Range<u64>) -> bool;
}

impl MemoryRange for Range<u64> {
    fn contains_range(&self, range: &Range<u64>) -> bool {
        if range.end == 0 {
            false
        } else {
            self.contains(&range.start) && self.contains(&(range.end - 1))
        }
    }

    fn intersects_range(&self, range: &Range<u64>) -> bool {
        if range.end == 0 {
            false
        } else {
            self.contains(&range.start) && !self.contains(&(range.end - 1))
                || !self.contains(&range.start) && self.contains(&(range.end - 1))
                || self.contains_range(range)
                || range.contains_range(self)
        }
    }
}
