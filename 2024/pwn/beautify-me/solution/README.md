# Solutions
## Author solution
* Get leak using type confusion in json key.
* Get uninitialized pointer 
* Create fake heap structures on the stack
* Setup ropchain on the stack and overwrite return pointer with `add rsp, 0x820; pop rbp; pop r12; pop r13; ret;`
