#ifndef ROP_LANG_H
#define ROP_LANG_H 

#define MOV 0
#define ADD 1
#define SUB 2
#define XOR 3
#define PUSH 4
#define POP 5
#define ROR 6
#define ROL 7
#define SHL 8
#define SHR 9
#define SYSCALL 0xa
#define CMP 0xb
#define JE 0xc
#define RET 0xd
#define CALL 0xe
#define STR 0xf
#define LDR 0x10
#define JNE 0x11

#define GADGETS "\x41\x5f\xc3\x41\x5e\xc3\x41\x5d\xc3\x4f\x89\x2c\xf7\xc3\x4f\x8b\x2c\xef\xc3\x49\x8B\x67\x78\x5D\xC3\x4F\x01\x2C\xF7\xC3\x4F\x29\x2C\xF7\xC3\x4F\x31\x2C\xF7\xC3\x4F\x8B\x34\xF7\xC3\x4D\x89\x75\x00\xC3\x4D\x8B\x6D\x00\xC3\x58\xC3\x5F\xC3\x5E\xC3\x5A\xC3\x41\x5A\xC3\x41\x58\xC3\x41\x59\xC3\x0F\x05\xC3\x49\x89\x07\xC3"
#define GADGETS_LEN 79

#define POP_R15 0 //len 3
#define POP_R14 POP_R15+3 //len 3
#define POP_R13 POP_R14+3 //len 3
#define MOV_IMM_R14_R15_R13 POP_R13+3 //len 5
#define MOV_R13_IMM_R13_R15 MOV_IMM_R14_R15_R13+5 //len 5
#define RESTORE_STACK MOV_R13_IMM_R13_R15+5 //len 6
#define ADD_IMM_R14_R15_R13 RESTORE_STACK+6 //len 5
#define SUB_IMM_R14_R15_R13 ADD_IMM_R14_R15_R13+5 //len 5
#define XOR_IMM_R14_R15_R13 SUB_IMM_R14_R15_R13+5 //len 5
#define MOV_R14_IMM_R14_R15 XOR_IMM_R14_R15_R13+5 //len 5
#define MOV_IMM_R13_R14 MOV_R14_IMM_R14_R15+5 //len 5
#define DEREF_R13 MOV_IMM_R13_R14+5 //len 5

#define POP_RAX DEREF_R13+5 //len 2
#define POP_RDI POP_RAX+2 //len 2
#define POP_RSI POP_RDI+2 //len 2
#define POP_RDX POP_RSI+2 //len 2
#define POP_R10 POP_RDX+2 //len 3
#define POP_R8 POP_R10+3 //len 3
#define POP_R9 POP_R8+3 //len 3
#define SYSCALL_GADGET POP_R9+3 //len 3
#define MOV_IMM_R15_RAX SYSCALL_GADGET+3 //len 4

typedef char byte;

#define REG_REG (byte)1
#define REG_IMM (byte)0x80


#define MAX_INSTRUCTIONS 0x11
#define MAX_REGISTERS 14





typedef struct Instructions_t {
    byte inst;
    byte type; //imm64 or reg
    byte dst;
    unsigned long src;
    struct Instructions_t* next; //The next instruction
    struct Instructions_t* prev; //The previous instruction
    unsigned long idx;
}inst_t;

typedef struct String_t{
    void *str;
    int len;
}string;

typedef struct Payload_t{
    string pload;
    inst_t* instruction;
}payload;


typedef struct Reg_t{
    unsigned long r1;
    unsigned long r2;
    unsigned long r3;
    unsigned long r4;
    unsigned long r5;
    unsigned long r6;
    unsigned long r7;
    unsigned long r8;
    unsigned long r9;
    unsigned long r10;
    unsigned long r11;
    unsigned long r12;
    unsigned long rs;
    unsigned long rb;
    unsigned long ip;
    unsigned long old_rsp;
    unsigned long cmp;
}reg_t;

typedef enum REG_TARGETS {
    r1 = 0x1,
    r2 = 0x2,
    r3 = 0x3,
    r4 = 0x4,
    r5 = 0x5,
    r6 = 0x6,
    r7 = 0x7,
    r8 = 0x8,
    r9 = 0x9,
    r10 = 0xa,
    r11 = 0xb,
    r12 = 0xc,
    rs = 0xd,
    rb = 0xe
}REGISTERS;


extern char *gadgets;
extern reg_t *registers;
extern char *pop_r15;
extern char *pop_r14;
extern char *pop_r13;
extern char *mov_r13_imm_r13_r15;
extern char *restore_stack;
extern char* register_addr;

unsigned long setup_stack();

void setup_registers();
void destroy_registers();

inst_t parse_instruction(char *inst_bytes);
inst_t* parse_instructions(char *program, unsigned long len);

inst_t* inst_list_append(inst_t* list,inst_t item);
inst_t* inst_list_init(inst_t item);
inst_t* inst_list_get_idx(inst_t* list, unsigned long idx);
unsigned long inst_list_get_len(inst_t* list);
void inst_destroy(inst_t* instruction);
void inst_list_destroy(inst_t* list);


unsigned long u64(char *str);
char* p64(unsigned long num);

void create_gadgets();
void destroy_gadgets();


payload create_payload(inst_t *instruction);
int requires_rop_payload(byte inst);
void __execute_payload(payload _payload);
void execute_payload(payload _payload);
void cleanup_payload(payload _payload);
unsigned int get_gadget_len(char *gadget);

string create_arith_chain(byte _dst, unsigned long _src, byte _type, unsigned long _gadget_off);
string create_mov(inst_t* instruction);
string create_add(inst_t *instruction);
string create_sub(inst_t *instruction);
string create_xor(inst_t *instruction);
string create_str(inst_t *instruction);
string create_ldr(inst_t *instruction);
string create_push(inst_t *instruction);
string create_pop(inst_t *instruction);
string create_syscall(inst_t* instruction);

void string_append(string* dst, string* src);
string string_slice(string* to_slice, int start, int stop);

#endif