use std::os::raw::{c_char,c_int,c_void};
use std::time::Instant;
type S=i32;
// T_FILE=1, MESSAGEAPI=48, PAYLOAD=49, TSBPD=22, SNDBUF=5, RCVBUF=6, FC=4, RCVSYN=2, SNDSYN=1
const T_FILE:c_int=1;const MESSAGEAPI:c_int=48;const PAYLOAD:c_int=49;const TSBPD:c_int=22;
const SNDBUF:c_int=5;const RCVBUF:c_int=6;const FC:c_int=4;const RCVSYN:c_int=2;const SNDSYN:c_int=1;
extern "C"{fn srt_startup()->c_int;fn srt_cleanup()->c_int;fn srt_create_socket()->S;
fn srt_setsockopt(u:S,l:c_int,o:c_int,v:*const c_void,n:c_int)->c_int;fn srt_bind(u:S,s:*const libc::sockaddr,n:c_int)->c_int;
fn srt_listen(u:S,b:c_int)->c_int;fn srt_accept(u:S,s:*mut libc::sockaddr,n:*mut c_int)->S;
fn srt_connect(u:S,s:*const libc::sockaddr,n:c_int)->c_int;fn srt_sendmsg(u:S,b:*const c_char,l:c_int,t:c_int,i:c_int)->c_int;
fn srt_recvmsg(u:S,b:*mut c_char,l:c_int)->c_int;fn srt_close(u:S)->c_int;fn srt_getlasterror_str()->*const c_char;}
const MSG:usize=1316;
fn le()->String{unsafe{let p=srt_getlasterror_str();if p.is_null(){"?".into()}else{std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()}}}
fn sa(p:u16)->libc::sockaddr_in{let mut s:libc::sockaddr_in=unsafe{std::mem::zeroed()};s.sin_family=libc::AF_INET as u16;s.sin_port=p.to_be();s.sin_addr.s_addr=u32::from_ne_bytes([127,0,0,1]);s}
fn cfgs(s:S){unsafe{let so=|o:c_int,v:&i32|assert_ne!(srt_setsockopt(s,0,o,v as *const i32 as *const c_void,4),-1,"opt{o}:{}",le());
so(T_FILE,&1);so(MESSAGEAPI,&1);so(PAYLOAD,&(MSG as i32));so(TSBPD,&0);
so(SNDBUF,&(32*1024*1024));so(RCVBUF,&(16*1024*1024));so(FC,&65536);
let p=b"change-me-strong-passphrase-2026";assert_ne!(srt_setsockopt(s,0,26,p.as_ptr() as *const c_void,p.len() as c_int),-1,"ph");so(27,&16);}}
fn srv(msgs:usize){unsafe{srt_startup();let s=srt_create_socket();cfgs(s);let a=sa(9007);
assert_ne!(srt_bind(s,&a as *const _ as *const libc::sockaddr,std::mem::size_of::<libc::sockaddr_in>() as c_int),-1);
assert_ne!(srt_listen(s,128),-1);let mut pe=unsafe{std::mem::zeroed()};let mut pl=std::mem::size_of::<libc::sockaddr_in>() as c_int;
let acc=srt_accept(s,&mut pe as *mut _ as *mut libc::sockaddr,&mut pl);assert!(acc!=-1);
std::thread::sleep(std::time::Duration::from_millis(300));let z=0i32;srt_setsockopt(acc,0,RCVSYN,&z as *const i32 as *const c_void,4);srt_setsockopt(acc,0,SNDSYN,&z as *const i32 as *const c_void,4);
// 接收
let mut b=[0u8;4096];let mut n=0u64;let st=Instant::now();
while n<msgs as u64{let r=srt_recvmsg(acc,b.as_mut_ptr() as *mut c_char,b.len() as c_int);if r>0{n+=1;}else{std::thread::sleep(std::time::Duration::from_micros(20));}}
let el=st.elapsed().as_secs_f64();eprintln!("[server RCV] {msgs}@{:.0}msg/s {:.2}MB/s",msgs as f64/el,msgs as f64*MSG as f64/el/1e6);
srt_close(acc);srt_close(s);srt_cleanup();}}
fn cli(msgs:usize){unsafe{srt_startup();let s=srt_create_socket();cfgs(s);let a=sa(9007);
assert_ne!(srt_connect(s,&a as *const _ as *const libc::sockaddr,std::mem::size_of::<libc::sockaddr_in>() as c_int),-1);
std::thread::sleep(std::time::Duration::from_millis(500));let z=0i32;srt_setsockopt(s,0,RCVSYN,&z as *const i32 as *const c_void,4);srt_setsockopt(s,0,SNDSYN,&z as *const i32 as *const c_void,4);
let d=vec![0xEEu8;MSG];let mut n=0u64;let st=Instant::now();
while n<msgs as u64{let r=srt_sendmsg(s,d.as_ptr() as *const c_char,d.len() as c_int,-1,1);if r==-1{std::thread::sleep(std::time::Duration::from_micros(20));}else{n+=1;}}
let el=st.elapsed().as_secs_f64();eprintln!("[client SND initiator→] {msgs}@{:.0}msg/s {:.2}MB/s",msgs as f64/el,msgs as f64*MSG as f64/el/1e6);
srt_close(s);srt_cleanup();}}
fn main(){let msgs:usize=std::env::args().nth(1).map(|x|x.parse().unwrap()).unwrap_or(50000);println!("=== initiator(client)发送 = 上传方向 ===");let s=std::thread::spawn(move||srv(msgs));std::thread::sleep(std::time::Duration::from_millis(300));let c=std::thread::spawn(move||cli(msgs));let _=c.join();let _=s.join();}
