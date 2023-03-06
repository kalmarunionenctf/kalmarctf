#include <stdio.h>
#include <stdlib.h>
#include "rop_lang.h"

string read_file(char* filename){
    FILE *fp = fopen(filename,"r");
    if(fp == NULL){
        //fprintf(stderr,"Can't find file %s\n",filename);
        exit(1);
    
    }
    string file_contents;
    fseek(fp,0,SEEK_END);
    file_contents.len = ftell(fp);
    file_contents.str = malloc(file_contents.len+1);
    rewind(fp);
    fread(file_contents.str, 1, file_contents.len, fp);
    fclose(fp);
    return file_contents;
}
void print_usage(){
    printf("Usage:\n");
    printf("./robber <filename>\n");
    return;
}


int main(int argc, char* argv[]){
    if(argc!=2){
        print_usage();
        exit(1);
    }
    char *filename = argv[1];
    string test = read_file(filename);
    unsigned long program_len = test.len;
    unsigned int instruction_num = program_len/11;
    create_gadgets();
    setup_registers();
    

    inst_t* instructions = parse_instructions(test.str,program_len);

    int i = 0;
    while(i<instruction_num){
        inst_t *instruction = inst_list_get_idx(instructions,i);
        payload pload = create_payload(instruction);
        execute_payload(pload);
        cleanup_payload(pload);
        i=registers->ip;
    }

    inst_list_destroy(instructions);
    destroy_gadgets();
    destroy_registers();
}