#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <byteswap.h>
#include <sys/mman.h>
#include "rop_lang.h"

char* gadgets;
void* new_stack_chunk;
reg_t* registers;

char *pop_r15;
char *pop_r14;
char *pop_r13;
char *mov_r13_imm_r13_r15;
char *restore_stack;
char* register_addr;


void string_append(string* dst, string* src){
    int new_len = dst->len + src->len;
    void* new_str = realloc(dst->str,new_len+1);
    dst->str = new_str;
    
    void* tmp_str = new_str+dst->len;
    memcpy(tmp_str,src->str,src->len);
    
    dst->len = new_len;

}

string string_slice(string *to_slice, int start, int stop){
    if(stop<start || stop == start || start<0 || stop<0 || start>to_slice->len || stop>to_slice->len){
        exit(1);
    }
    string sliced;
    sliced.len = stop-start;
    sliced.str = malloc(sliced.len+1);

    char* tmp_str = to_slice->str;
    tmp_str+=start;
    memcpy(sliced.str,tmp_str,sliced.len);
    
    return sliced;

}
unsigned long setup_stack(){
    new_stack_chunk = malloc(0x8000);
    unsigned long new_stack = (unsigned long)new_stack_chunk;
    new_stack+=0x4000;
    return new_stack;
}

void setup_registers(){
    registers = malloc(sizeof(reg_t));
    memset(registers,'\x00',sizeof(reg_t));
    registers->rs = setup_stack();
    registers->ip = 0;
    register_addr = p64((unsigned long)registers);
}

void destroy_registers(){
    free(new_stack_chunk);
    free(registers);
    return;
}

inst_t parse_instruction(char *inst_bytes){
    inst_t instruction = {0};
    instruction.inst = *inst_bytes;
    inst_bytes++;
    instruction.type = *inst_bytes;
    inst_bytes++;
    instruction.dst = *inst_bytes;
    inst_bytes++;
    instruction.src = 0x0;
    for(int i = 0; i<8; i++){
        instruction.src = (instruction.src << 8) | *inst_bytes;
        inst_bytes++;
    }
    instruction.src = bswap_64(instruction.src);
    return instruction;
}

inst_t* parse_instructions(char *program, unsigned long len){
    if(len%11!=0){
        fprintf(stderr,"Instruction format error\n");
        exit(1);
    }
    if(len == 0){
        fprintf(stderr,"No instructions given!\n");
        exit(1);
    }
    inst_t* inst_list = inst_list_init(parse_instruction(program));
    program+=11;
    for(unsigned long i = 11; i<len;i+=11){
        inst_list_append(inst_list,parse_instruction(program));
        program+=11;
    }
    return inst_list;
}




inst_t* inst_list_init(inst_t item){
    inst_t* head = malloc(sizeof(inst_t)+1);
    head->next = NULL;
    head->prev = NULL;
    head->idx = 0;
    head->inst = item.inst;
    head->type = item.type;
    head->dst = item.dst;
    head->src = item.src;
    return head;
}

inst_t* inst_list_append(inst_t* list, inst_t item){
    inst_t* curr_inst = list;
    while(curr_inst->next != NULL){
        curr_inst = curr_inst->next;
    }
    //If the next instruction is NULL we are at the end and we need to initialize
    inst_t* tmp_inst = malloc(sizeof(inst_t)+1);
    tmp_inst->prev = curr_inst;
    tmp_inst->next = NULL;
    tmp_inst->idx = curr_inst->idx + 1;
    tmp_inst->inst = item.inst;
    tmp_inst->type = item.type;
    tmp_inst->dst = item.dst;
    tmp_inst->src = item.src;
    curr_inst->next = tmp_inst;
    return tmp_inst;
}

inst_t* inst_list_get_idx(inst_t* list, unsigned long idx){
    inst_t* instruction = NULL;
    inst_t* curr_inst = list;
    while(curr_inst!=NULL){
        if(curr_inst->idx == idx){
            instruction = curr_inst;
            break;
        }
        curr_inst = curr_inst->next;
    }
    return instruction;
}

unsigned long inst_list_get_len(inst_t* list){
    inst_t* curr_inst = list;
    unsigned long len = 0;
    while(curr_inst != NULL){
        len++;
        curr_inst = curr_inst->next;
    }
    return len;
}
void inst_destroy(inst_t* instruction){
    free(instruction);
}

void inst_list_destroy(inst_t* list){
    unsigned long len = inst_list_get_len(list);
    for(int i = (len-1); i>-1;i--){
        inst_t* instruction = inst_list_get_idx(list,i);
        inst_destroy(instruction);
    }
}

unsigned long u64(char* str){
    unsigned long converted = 0;
    for(int i = 0; i<8;i++){
        unsigned long or_value = ((unsigned long)(*str))<<(i*8);
        converted = converted | or_value;
        str++;
    }
    return converted;
}

char* p64(unsigned long num){
    char *outbuf = malloc(8);
    memcpy(outbuf,&num,8);
    return outbuf;
}

void create_gadgets(){
    gadgets = mmap(0,0x1000,0x7,0x22,-1,0);
    if((unsigned long)gadgets == -1){
        fprintf(stderr,"MMAP FAILED\n");
        exit(1);
    }
    memcpy(gadgets,GADGETS,GADGETS_LEN);
    pop_r15 = p64((unsigned long)(gadgets+POP_R15));
    pop_r14 = p64((unsigned long)(gadgets+POP_R14));
    pop_r13 = p64((unsigned long)(gadgets+POP_R13));
    mov_r13_imm_r13_r15 = p64((unsigned long)(gadgets+MOV_R13_IMM_R13_R15));
    restore_stack = p64((unsigned long)(gadgets+RESTORE_STACK));
    mprotect(gadgets,0x1000,PROT_READ | PROT_EXEC);

}

void destroy_gadgets(){
    free(pop_r15);
    free(pop_r14);
    free(pop_r13);
    free(mov_r13_imm_r13_r15);
    free(restore_stack);
    free(register_addr);
}

payload create_payload(inst_t* instruction){
    payload to_return;
    
    to_return.pload.str = NULL;
    to_return.pload.len = 0;
    to_return.instruction = instruction;

    switch(instruction->inst){
        case MOV:
            to_return.pload = create_mov(instruction);
            break;
        case ADD:
            to_return.pload = create_add(instruction);
            break;
        case SUB:
            to_return.pload = create_sub(instruction);
            break;
        case XOR:
            to_return.pload = create_xor(instruction);
            break;
        case PUSH:
            to_return.pload = create_push(instruction);
            break;
        case POP:
            to_return.pload = create_pop(instruction);
            break;
        case ROR:
            //TODO implement
            break;
        case ROL:
            //TODO implement
            break;
        case SHL:
            //TODO implement
            break;
        case SHR:
            //TODO implement
            break;
        case SYSCALL:
            to_return.pload = create_syscall(instruction);
            break;
        case CMP:
            break;
        case JE:
            break;
        case RET:
            break;
        case CALL:
            break;
        case STR:
            to_return.pload = create_str(instruction);
            break;
        case LDR:
            to_return.pload = create_ldr(instruction);
            break;
        default:
            fprintf(stderr,"Invalid instruction: %p\n",instruction->inst);
            exit(1);
            break;
    }
    return to_return;
    
}

int requires_rop_payload(byte inst){
    int required = 0;
    byte requires[] = {
        MOV,
        ADD,
        SUB,
        XOR,
        PUSH,
        POP,
        ROR,
        ROL,
        SHL,
        SHR,
        SYSCALL,
        STR,
        LDR
    };
    int requires_len = 13;
    for(int i = 0;i<requires_len;i++){
        if(inst == requires[i]){
            required = 1;
            break;
        }
    }
    return required;
}

void __execute_payload(payload _payload){
    char *payload_str = _payload.pload.str;
    asm volatile( 
        "mov %%rsp, %0\n\t"
        : "=r"(registers->old_rsp)
    );
    asm volatile(
        "mov %0, %%rsp\n\t"
        :
        :"a"(payload_str)
    );
    asm volatile(
        "ret"
    );
    return;
}

void handle_cmp(payload _payload){
    unsigned long num1;
    unsigned long num2;

    unsigned int dst = (((unsigned int)_payload.instruction->dst)-1);
    
    if(dst > MAX_REGISTERS){
        fprintf(stderr,"Invalid instruction\n");
        exit(1);
    }
    
    unsigned long *dst_reg = ((unsigned long*)registers)+dst;
    
    num1 = *dst_reg;

    if(_payload.instruction->type == REG_IMM){
        num2 = _payload.instruction->src;
    }
    else if(_payload.instruction->type == REG_REG){
        unsigned long src = ((_payload.instruction->src)-1);
        if(src > MAX_REGISTERS){
            fprintf(stderr,"Invalid instruction\n");
            exit(1);
        }
        unsigned long *src_reg = ((unsigned long*)registers)+src;
        num2 = *src_reg;
    }
    else{
        fprintf(stderr,"Invalid instruction\n");
        exit(1);
    }

    registers->cmp = num1-num2;
}

void execute_payload(payload _payload){
    inst_t instruction;
    payload load;
    string chain;
    
    if(requires_rop_payload(_payload.instruction->inst)){
        __execute_payload(_payload);
        registers->ip+=1;
        return;
    }
    switch(_payload.instruction->inst){
        case CMP:
            handle_cmp(_payload);
            registers->ip+=1;
            break;
        case JE:
            if(registers->cmp == 0x0){
                registers->ip = _payload.instruction->src;
            }
            else{
                registers->ip+=1;
            }
            break;
        case RET:
            instruction.type = REG_REG;
            instruction.dst = (byte)0x1;
            instruction.src = (unsigned long)15;
            instruction.inst = 0;

            chain = create_pop(&instruction);

            load.pload = chain;

            __execute_payload(load);
            registers->ip+=1;
            break;
        case JNE:
            if(registers->cmp == 0x0){
                registers->ip+=1;
            }
            else{
                registers->ip = _payload.instruction->src;
            }
            break;
        case CALL:
            instruction.type = REG_REG;
            instruction.dst = (byte)0x1;
            instruction.src = (unsigned long)15;
            instruction.inst = (byte)0x4;

            chain = create_push(&instruction);
            
            load.pload = chain;

            __execute_payload(load);

            registers->ip = _payload.instruction->src;
            break;
    }
}

void cleanup_payload(payload _payload){
    if(_payload.pload.str != NULL){
        free(_payload.pload.str);
    }
    return;
}


string create_arith_chain(byte _dst, unsigned long _src, byte _type, unsigned long gadget_off){
    string chain;
    char *gadget = p64((unsigned long)(gadgets+gadget_off));
    
    char* dst = p64(((unsigned long)_dst)-1);
    char* src;

    if(_type == REG_IMM){
        chain.len = 8*8;
        src = p64(_src);
    }
    else if(_type == REG_REG){
        chain.len = 8*9;
        src = p64(_src-1);
    }
    else{
        fprintf(stderr,"Invalid instruction\n");
        exit(1);
    }
    
    chain.str = malloc(chain.len+1);
    char* tmp_chain = chain.str;

    //Copy in the chain
    memcpy(tmp_chain,pop_r15,8);
    tmp_chain+=8;
    memcpy(tmp_chain,register_addr,8);
    tmp_chain+=8;
    memcpy(tmp_chain,pop_r14,8);
    tmp_chain+=8;
    memcpy(tmp_chain,dst,8);
    tmp_chain+=8;
    memcpy(tmp_chain,pop_r13,8);
    tmp_chain+=8;
    memcpy(tmp_chain,src,8);
    tmp_chain+=8;

    if(_type == REG_IMM){
        memcpy(tmp_chain,gadget,8);
    }
    else if(_type == REG_REG){
        memcpy(tmp_chain,mov_r13_imm_r13_r15,8);
        tmp_chain+=8;
        memcpy(tmp_chain,gadget,8);
    }
    tmp_chain+=8;
    memcpy(tmp_chain,restore_stack,8);
    
    free(gadget);
    free(dst);
    free(src);

    return chain;
}


string create_mov(inst_t* instruction){
    string mov_chain = create_arith_chain(instruction->dst,instruction->src,instruction->type,MOV_IMM_R14_R15_R13);
    return mov_chain;
}

string create_add(inst_t *instruction){
    string add_chain = create_arith_chain(instruction->dst,instruction->src,instruction->type,ADD_IMM_R14_R15_R13);
    return add_chain;

}
string create_sub(inst_t *instruction){
    string sub_chain = create_arith_chain(instruction->dst,instruction->src,instruction->type,SUB_IMM_R14_R15_R13);
    return sub_chain;
}

string create_xor(inst_t *instruction){
    string xor_chain = create_arith_chain(instruction->dst, instruction->src, instruction->type, XOR_IMM_R14_R15_R13);
    return xor_chain;
}

string create_str(inst_t *instruction){
    string chain;
    char *mov_r14_imm_r14_r15 = p64((unsigned long)(gadgets+MOV_R14_IMM_R14_R15));
    char *mov_imm_r13_r14 = p64((unsigned long)(gadgets+MOV_IMM_R13_R14));
    char *dst = p64((unsigned long)instruction->dst-1);
    char *src;
    if(instruction->type == REG_IMM){
        chain.len = 8*9;
        src = p64(instruction->src);
    }
    else if(instruction->type == REG_REG){
        chain.len = 8*10;
        src = p64(instruction->src-1);
    }
    else{
        fprintf(stderr,"Invalid instruction\n");
        exit(1);
    }
    chain.str = malloc(chain.len+1);
    char *tmp_chain = chain.str;

    memcpy(tmp_chain, pop_r15, 8);
    tmp_chain+=8;
    memcpy(tmp_chain, register_addr, 8);
    tmp_chain+=8;
    memcpy(tmp_chain, pop_r14, 8);
    tmp_chain+=8;
    memcpy(tmp_chain, src, 8);
    tmp_chain+=8;
    memcpy(tmp_chain, pop_r13, 8);
    tmp_chain+=8;
    memcpy(tmp_chain, dst, 8);
    tmp_chain+=8;
    memcpy(tmp_chain,mov_r13_imm_r13_r15,8);
    tmp_chain+=8;

    if(instruction->type == REG_REG){
        memcpy(tmp_chain,mov_r14_imm_r14_r15,8);
        tmp_chain+=8;   
    }
    memcpy(tmp_chain,mov_imm_r13_r14,8);
    tmp_chain+=8;
    memcpy(tmp_chain,restore_stack,8);

    free(src);
    free(dst);
    free(mov_r14_imm_r14_r15);
    free(mov_imm_r13_r14);
    return chain;
}

string create_ldr(inst_t *instruction){
    string chain;
    char *mov_imm_r14_r15_r13 = p64((unsigned long)(gadgets+MOV_IMM_R14_R15_R13));
    char *deref_r13 = p64((unsigned long)(gadgets+DEREF_R13));
    char *dst = p64((unsigned long)instruction->dst-1);
    char *src;
    if(instruction->type == REG_IMM){
        chain.len = 8*9;
        src = p64(instruction->src);
    }
    else if(instruction->type == REG_REG){
        chain.len = 8*10;
        src = p64(instruction->src-1);
    }
    else{
        fprintf(stderr,"Invalid instruction\n");
        exit(1);
    }
    chain.str = malloc(chain.len+1);
    char *tmp_chain = chain.str;

    memcpy(tmp_chain, pop_r15, 8);
    tmp_chain+=8;
    memcpy(tmp_chain, register_addr, 8);
    tmp_chain+=8;
    memcpy(tmp_chain, pop_r14, 8);
    tmp_chain+=8;
    memcpy(tmp_chain, dst, 8);
    tmp_chain+=8;
    memcpy(tmp_chain, pop_r13, 8);
    tmp_chain+=8;
    memcpy(tmp_chain, src, 8);
    tmp_chain+=8;

    if(instruction->type == REG_REG){
        memcpy(tmp_chain,mov_r13_imm_r13_r15,8);
        tmp_chain+=8;
    }

    memcpy(tmp_chain,deref_r13,8);
    tmp_chain+=8;
    memcpy(tmp_chain,mov_imm_r14_r15_r13,8);
    tmp_chain+=8;
    memcpy(tmp_chain,restore_stack,8);

    free(src);
    free(dst);
    free(mov_imm_r14_r15_r13);
    free(deref_r13);
    return chain;

}

string create_push(inst_t* instruction){
    inst_t store_on_stack;
    inst_t decrement_stack;
    
    REGISTERS dst_reg = rs;
    
    store_on_stack.type = instruction->type;
    store_on_stack.dst = (byte)dst_reg;
    store_on_stack.src = instruction->src;

    decrement_stack.type = (byte)REG_IMM;
    decrement_stack.dst = (byte)dst_reg;
    decrement_stack.src = (unsigned long)0x8;

    string sub_payload = create_sub(&decrement_stack);
    string str_payload = create_str(&store_on_stack);

    string final_payload = string_slice(&sub_payload,0,sub_payload.len-8);
    string_append(&final_payload,&str_payload);

    free(sub_payload.str);
    free(str_payload.str);

    return final_payload;

}

string create_pop(inst_t* instruction){
    inst_t load_from_stack;
    inst_t increment_stack;

    REGISTERS src_reg = rs;

    load_from_stack.type = instruction->type;
    load_from_stack.dst = instruction->src;
    load_from_stack.src = (unsigned long)src_reg;

    increment_stack.type = (byte)REG_IMM;
    increment_stack.dst = (byte)src_reg;
    increment_stack.src = (unsigned long)0x8;
    
    string ldr_payload = create_ldr(&load_from_stack);
    string add_payload = create_add(&increment_stack);

    string final_payload = string_slice(&ldr_payload,0,ldr_payload.len-8);
    
    string_append(&final_payload,&add_payload);
    
    free(add_payload.str);
    free(ldr_payload.str);

    return final_payload;
}

//calling convention is
//R10 = syscall num
//args = r1-r6

string create_syscall(inst_t* instruction){
    string chain;
    char *pop_rax = p64((unsigned long)(gadgets+POP_RAX));
    char *pop_rdi = p64((unsigned long)(gadgets+POP_RDI));
    char *pop_rsi = p64((unsigned long)(gadgets+POP_RSI));
    char *pop_rdx = p64((unsigned long)(gadgets+POP_RDX));
    char *pop_r10 = p64((unsigned long)(gadgets+POP_R10));
    char *pop_r8 = p64((unsigned long)(gadgets+POP_R8));
    char *pop_r9 = p64((unsigned long)(gadgets+POP_R9));
    char *syscall = p64((unsigned long)(gadgets+SYSCALL_GADGET));
    char *mov_imm_r15_rax = p64((unsigned long)(gadgets+MOV_IMM_R15_RAX));

    chain.len = 18*8;
    chain.str = malloc(chain.len+1);

    char *tmp_str = chain.str;

    memcpy(tmp_str, pop_rax, 8);
    tmp_str+=8;

    memcpy(tmp_str,&registers->r10,8);
    tmp_str+=8;

    memcpy(tmp_str, pop_rdi , 8);
    tmp_str+=8;

    memcpy(tmp_str, &registers->r1, 8);
    tmp_str+=8;

    memcpy(tmp_str, pop_rsi , 8);
    tmp_str+=8;

    memcpy(tmp_str, &registers->r2, 8);
    tmp_str+=8;

    memcpy(tmp_str, pop_rdx, 8);
    tmp_str+=8;
    
    memcpy(tmp_str, &registers->r3, 8);
    tmp_str+=8;

    memcpy(tmp_str, pop_r10, 8);
    tmp_str+=8;

    memcpy(tmp_str, &registers->r4, 8);
    tmp_str+=8;

    memcpy(tmp_str, pop_r8, 8);
    tmp_str+=8;

    memcpy(tmp_str, &registers->r5, 8);
    tmp_str+=8;

    memcpy(tmp_str, pop_r9, 8);
    tmp_str+=8;

    memcpy(tmp_str,&registers->r6,8);
    tmp_str+=8;

    memcpy(tmp_str,syscall,8);
    tmp_str+=8;
    
    memcpy(tmp_str,pop_r15,8);
    tmp_str+=8;
    memcpy(tmp_str,register_addr,8);
    tmp_str+=8;
    memcpy(tmp_str,mov_imm_r15_rax,8);
    tmp_str+=8;

    memcpy(tmp_str,restore_stack,8);
    tmp_str+=8;

    free(pop_rax);
    free(pop_rdi);
    free(pop_rsi);
    free(pop_rdx);
    free(pop_r10);
    free(pop_r8);
    free(pop_r9);
    free(syscall);
    free(mov_imm_r15_rax);
    
    return chain;
}