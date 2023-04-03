use object::{Object, ObjectSection, SectionKind};
use std::cmp::Ordering;
use std::error::Error;
use std::fs;
use std::io::{Write, ErrorKind};

/// Reads a file and displays the content of the ".boot" section.
fn main() -> Result<(), Box<dyn Error>> {
    let bin_data = fs::read("../../elfs/stage0-v2_0_0.elf")?;
    let obj_file = object::File::parse(&*bin_data)?;

    let mut lowest_addr = u64::MAX;
    let mut highest_addr = u64::MIN;

    let mut bin_contents = vec![];

    for s in obj_file.sections() {
        use SectionKind::*;
        match s.kind() {
            Text | ReadOnlyData | ReadOnlyString => {
                let start = s.address();
                let size = s.size();
                let end = start + size;
                println!("{}: 0x{start:08X}..0x{end:08X}", s.name()?);

                lowest_addr = lowest_addr.min(start);
                highest_addr = highest_addr.max(end);
                bin_contents.push(s);
            },
            _ => {
                println!("Ignoring section {}; kind {:?}; start 0x{:08X}", s.name()?, s.kind(), s.address());
                continue;
            }
        }
    }

    match lowest_addr.cmp(&highest_addr) {
        Ordering::Less => {},
        Ordering::Equal => panic!("Empty file?"),
        Ordering::Greater if bin_contents.is_empty() => panic!("No sections found?"),
        Ordering::Greater => panic!("Start is after end?"),
    }

    let ttl_len: usize = (highest_addr - lowest_addr).try_into()?;
    println!("start: 0x{lowest_addr:08X}");
    println!("end:   0x{highest_addr:08X}");
    println!("size:  {ttl_len}");

    let mut output = vec![0xFFu8; ttl_len];
    for s in bin_contents.iter() {
        let adj_addr = (s.address() - lowest_addr).try_into()?;
        let size = s.size().try_into()?;
        output[adj_addr..][..size].copy_from_slice(s.data()?);
    }

    let name = format!("./target/output_0x{lowest_addr:08X}.bin");
    match std::fs::remove_file(&name) {
        Ok(()) => {},
        Err(e) if e.kind() == ErrorKind::NotFound => {},
        Err(e) => panic!("{e:?}"),
    }
    let mut outfile = std::fs::File::create(&name)?;
    outfile.write_all(&output)?;


    // println!("{:#?}", obj_file);
    // if let Some(section) = obj_file.section_by_name(".boot") {
    //     println!("{:#x?}", section.data()?);
    // } else {
    //     eprintln!("section not available");
    // }
    Ok(())
}
