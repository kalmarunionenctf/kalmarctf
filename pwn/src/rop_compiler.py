import sys
import string
INSTRUCTIONS = {
    "MOV":[0x0,0x3],
    "ADD":[0x01,0x3],
    "SUB":[0x02,0x3],
    "XOR":[0x03,0x3],
    "PUSH" : [0x04,0x2],
    "POP" : [0x05,0x2],
    "ROR" : [0x06, 0x3],
    "ROL" : [0x07, 0x3],
    "SHL" : [0x08, 0x3],
    "SHR" : [0x09, 0x3],
    "SYSCALL": [0x0a,0x1],
    "CMP": [0x0b,0x3],
    "JE": [0x0c,0x2],
    "RET":[0xd,0x1],
    "CALL":[0xe,0x2],
    "STR":[0xf,0x3],
    "LDR":[0x10,0x3]
}

REGISTERS = {
    "R1" : 0x1,
    "R2" : 0x2,
    "R3" : 0x3,
    "R4" : 0x4,
    "R5" : 0x5,
    "R6" : 0x6,
    "R7" : 0x7,
    "R8" : 0x8,
    "R9" : 0x9,
    "R10" : 0xa,
    "R11" : 0xb,
    "R12" : 0xc,
    "RS" : 0xd,
    "RB" : 0xe
}
instruction_num = 0
def is_hex(to_test):
    return all(c in string.hexdigits for c in to_test)

def p64(num:int):
    return num.to_bytes(8,"little")

def p8(num:int):
    return num.to_bytes(1,"little")

def is_label(line:list):
    if line[1].endswith(":"):
        return True
    return False

def is_IMM(src:str):
    if(not src.startswith("0X")):
        return False
    return True


def parse_instruction(line:list):
    inst_num = -1
    dst_num = -1
    src_num = -1
    type_num = -1

    tmp_instruction_tokens = line[1].split(" ")
    instruction_tokens = []
    
    for lines in tmp_instruction_tokens:
        instruction_tokens.append(lines.strip(","))
    print(instruction_tokens)
    instruction = instruction_tokens[0]
    if instruction not in INSTRUCTIONS:
        print(f"Invalid instruction on line: {line[0]} : {line[1]}")
        exit(1)
    if len(instruction_tokens)!=INSTRUCTIONS[instruction][1]:
        print(f"Invalid instruction on line: {line[0]} : {line[1]}")
        print(f"Instruction length invalid for {instruction}. Should be {INSTRUCTIONS[instruction][1]} got {len(instruction_tokens)}")
        exit(1)
    
    #Should handle labels
    if len(instruction_tokens) == 1:
        inst_num = INSTRUCTIONS[instruction][0]
        dst_num = 0x1
        src_num = 0x1
        type_num = 0x1
    
    if len(instruction_tokens) == 2:
        inst_num = INSTRUCTIONS[instruction][0]
        src = instruction_tokens[1]

        if(instruction == "CALL" or instruction == "JE"):
            if src in labels.keys():
                src = hex(labels[src]).upper()
        if(is_IMM(src)):
            #Check if valid hex value
            if(len(src[2:])>16):
                print(f"Invalid instruction on line: {line[0]} : {line[1]}")
                print(f"Instruction invalid for {instruction}. Hex value too big")
                exit(1)
            if(not is_hex(src[2:])):
                print(f"Invalid instruction on line: {line[0]} : {line[1]}")
                print(f"Instruction invalid for {instruction}. All values must be given in hex")
                exit(1)
            #If valid we set it
            type_num = 0x80
            src_num = int(src,16)
            dst_num = 0x1
        
        #If its not IMM it's REG_REG
        else:
            if(src not in REGISTERS.keys()):
                print(f"Invalid instruction on line: {line[0]} : {line[1]}")
                print(f"Register: {src} does not exist")
                exit(1)
            type_num = 0x1
            src_num = REGISTERS[src]
            dst_num = 0x1
    
    if len(instruction_tokens) == 3:
        inst_num = INSTRUCTIONS[instruction][0]
        dst = instruction_tokens[1]
        src = instruction_tokens[2]
        
        if(is_IMM(src)):
            #Check if valid hex value
            if(len(src[2:])>16):
                print(f"Invalid instruction on line: {line[0]} : {line[1]}")
                print(f"Instruction invalid for {instruction}. Hex value too big")
                exit(1)
            if(not is_hex(src[2:])):
                print(f"Invalid instruction on line: {line[0]} : {line[1]}")
                print(f"Instruction invalid for {instruction}. All values must be given in hex")
                exit(1)
            #If valid we set it
            type_num = 0x80
            src_num = int(src,16)
        else:
            if(src not in REGISTERS.keys()):
                print(f"Invalid instruction on line: {line[0]} : {line[1]}")
                print(f"Register: {src} does not exist")
                exit(1)
            type_num = 0x1
            src_num = REGISTERS[src]
        
        if dst not in REGISTERS.keys():
            print(f"Invalid instruction on line: {line[0]} : {line[1]}")
            print(f"Register: {dst} does not exist")
            exit(1)
        
        dst_num = REGISTERS[dst]

    inst_compiled = p8(inst_num)
    dst_compiled = p8(dst_num)
    type_compiled = p8(type_num)
    src_compiled = p64(src_num)

    return inst_compiled + type_compiled + dst_compiled + src_compiled

def parse_labels(source:list):
    new_source = []
    instruction_num = 0
    for line in source:
        if line[1].endswith(":"):
            labels[line[1][:-1].upper()] = instruction_num
            continue
        new_source.append(line)
        instruction_num +=1
    return new_source

labels = {}

line_num = 0




filename = sys.argv[1]

source_code = []

with open(filename,"r") as f:
    source_code = f.readlines()

#Strip out comments and extra lines
source_code_2 = []
for line in source_code:
    line_num+=1
    tmp_line = line.strip()
    if(tmp_line.startswith("#") or len(tmp_line) == 0):
        continue
    source_code_2.append([line_num,tmp_line.upper()])

compiled_code = b''

source_code_2 = parse_labels(source_code_2)

i = 0
for line in source_code_2:
    print(f"{i}:", end="")
    compiled_code+=parse_instruction(line)
    i+=1

with open("./rop_compiled","wb") as f:
    f.write(compiled_code)

