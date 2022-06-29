#include <stdio.h>
#include <stdlib.h>
#include "elf64.h"
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <string.h>


#define SHT_SYMTAB 0x2
#define SHT_STRTAB 0x3


pid_t run_target(char* argv[])
{
    pid_t pid = fork();
    if (pid > 0) {
        return pid;
    } else if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        execv(argv[2], argv+2);
    } else {
        perror("fork");
        exit(1);
    }
}

int check_substring(char* str,int size, char* sub){
    int cur_offset = 0;
    int counter = 0;
    for(int i = 0 ; i < size ; i++){
        if(*(str+i) == *(sub+counter)){
            if(*(str+i) == '\0'){
                return cur_offset;
            }
            counter++;
        } else {
            counter = 0;
            cur_offset = i + 1;
        }
    }
    return -1;
}

Elf64_Shdr *get_section(Elf64_Ehdr *header, char *section_name) {
    Elf64_Shdr *section = (Elf64_Shdr *) ((void *) header + header->e_shoff); //pointer to sections
    Elf64_Shdr *shtrtab = (Elf64_Shdr *) ((void *) header + header->e_shoff +
                                          ((sizeof(Elf64_Shdr)) * header->e_shstrndx));
    Elf64_Shdr *section_header_to_return = NULL;
    for (unsigned long i = 0; i < header->e_shnum; i++) {
        Elf64_Shdr *current_section = section + i;
        char *curr_section_name = (char *) ((void *) header + shtrtab->sh_offset + current_section->sh_name);
        if (strcmp(section_name, curr_section_name) == 0) {
            section_header_to_return = section + i;
        }
    }
    return section_header_to_return;
}

int find_function_dynamic(Elf64_Ehdr *header, char *function, FILE *file , Elf64_Addr * address){
    Elf64_Shdr *rela_plt_section = get_section(header,".rela.plt");
    Elf64_Shdr *dynsym_section = get_section(header,".dynsym");
    Elf64_Shdr *dynstr = get_section(header,".dynstr");

    unsigned long num_of_entries = rela_plt_section->sh_size / rela_plt_section->sh_entsize;
    // find rela
    Elf64_Rela *curr_rela;
    Elf64_Sym *curr_sym;
    for (unsigned long i = 0; i < num_of_entries; i++) {
        curr_rela = (Elf64_Rela *) ((void *) header + rela_plt_section->sh_offset) + i;

        curr_sym = (Elf64_Sym *) ((void *) header + dynsym_section->sh_offset +
                                  ELF64_R_SYM(curr_rela->r_info) * sizeof(Elf64_Sym)); ///
        char *rela_name = (char *) (((void *) header) + dynstr->sh_offset + curr_sym->st_name);
        if (rela_name && (strcmp(rela_name, function) == 0)) {
            break;
        }
    }

    return curr_rela->r_offset;
}

int find_function_in_st(Elf64_Ehdr *header, char *function, FILE *file , Elf64_Addr * address , int* is_dynamic) {
    int ret = 0;
    fseek(file,header->e_shoff,SEEK_SET); // pointer to section header table
    Elf64_Shdr s_header , symtab_header , str_header;
    int strtab_indx = header->e_shstrndx - 1;
    int flag= 1;
    for(int i = 0 ; i < header->e_shnum ; i++ ){ //search for needed tables
        fread(&s_header , header->e_shentsize , 1 , file);
        if (s_header.sh_type == SHT_SYMTAB){
           symtab_header = s_header;
        } else if (i == strtab_indx){
            str_header = s_header;
            flag = 0;
        }
    }

    //read symtab
    fseek(file,symtab_header.sh_offset,SEEK_SET);// go to symtab
    Elf64_Xword sym_quantity = symtab_header.sh_size / symtab_header.sh_entsize;
    Elf64_Sym symtab_table[sym_quantity]; // array with size of the number of sections
    fread(symtab_table, symtab_header.sh_entsize, sym_quantity, file); // read the symtab sections
/*
    Elf64_Sym shstrtable_entry = symtab_table[shstrtab_indx];
    char *shstr_table = malloc(shstrtable_entry.st_size );
    fseek(file,shstrtable_entry.st_value,SEEK_SET);// go to symtab
    fread(shstr_table,shstrtable_entry.st_size,1,file);
    printf("%u\n",shstrtable_entry.st_name);
    int strtable_offset = check_substring(shstr_table,shstrtable_entry.st_size,".strtab");
*/
    char *str_table = malloc(str_header.sh_size );
    fseek(file,str_header.sh_offset,SEEK_SET);// go to symtab
    fread(str_table,str_header.sh_size,1,file);

    int place = check_substring(str_table,str_header.sh_size,function); // checks for function offset
    if(place == -1){
        ret =  0;
    } else {

        for (int i = 0; i < sym_quantity; i++) {
            Elf64_Word offset = symtab_table[i].st_name;
            if (offset == place) {
                if (ELF64_ST_BIND(symtab_table[i].st_info) == 0x1) { // if its the right symtab entry update the address
                    *address = symtab_table[i].st_value;
                    if(symtab_table[i].st_shndx == 0){
                        *address = find_function_dynamic(header,function,file,address);
                        *is_dynamic = 1;
                    }
                    ret = 1;
                    break;
                } else {
                    ret = -1;
                    break;
                }
            }
        }
    }

    free(str_table);

    return ret;
}

void debugger(pid_t pid, Elf64_Addr address,int* counter , int is_dynamic){
    struct user_regs_struct regs;
    long data;
    unsigned long break_data;
    int wait_status;
    wait(&wait_status);

    if(is_dynamic) {
        address = ptrace(PTRACE_PEEKTEXT, pid, address);
    }

    while(1){
        data = ptrace(PTRACE_PEEKTEXT , pid , (void*) address , NULL);
        break_data = (data & 0xffffffffffffff00) | 0xcc; // breakpoint in function
        ptrace(PTRACE_POKETEXT,pid,(void*)address,(void*)break_data); //apply breakpoint
        ptrace(PTRACE_CONT,pid,NULL,NULL); // continue
        wait(&wait_status);
        if(!WIFSTOPPED(wait_status)){
            return;
        }
        ptrace(PTRACE_POKETEXT,pid,(void*)address,(void*)data); // fix the instruction
        ptrace(PTRACE_GETREGS , pid,NULL , &regs);
        Elf64_Xword ret_address = ptrace(PTRACE_PEEKTEXT, pid, (void *) regs.rsp, NULL); //get ret address
        Elf64_Xword data_return = ptrace(PTRACE_PEEKTEXT, pid, (void *) ret_address, NULL); //get ret instruction
        break_data = (data_return & 0xffffffffffffff00) | 0xcc; // breakpoint in return
        ptrace(PTRACE_POKETEXT, pid, (void *) ret_address, break_data); // apply breakpoint

        regs.rip -= 1;
        ptrace(PTRACE_SETREGS , pid, NULL , &regs); // fix rip
        ptrace(PTRACE_CONT,pid,NULL,NULL); //continue

        wait(&wait_status);
        if(!WIFSTOPPED(wait_status)){
            return;
        }

        ptrace(PTRACE_POKETEXT,pid,(void*)ret_address,(void*)data_return); // fix ret instruction
        ptrace(PTRACE_GETREGS , pid,NULL , &regs);
        int rax_data = regs.rax; // get return value
        printf("PRF:: run #%d returned with %d\n", (*counter)++ , rax_data);

        regs.rip -= 1;
        ptrace(PTRACE_SETREGS , pid, NULL , &regs); // fix rip
    }
}

int main(int argc, char** argv) {
    pid_t child_pid = run_target(argv);
    int counter = 1;
    int is_dynamic = 0;
    FILE *file = fopen(argv[2],"rb");
    if(!file){
        exit(1);
    }
    Elf64_Ehdr header;
    fread(&header , sizeof(header) , 1 , file); // read header
    // check for exe
    if (header.e_type != 2){
        fclose(file);
        printf("PRF:: %s not an executable!\n", argv[2]);
    } else {
        Elf64_Addr address;
        int res = find_function_in_st(&header, argv[1], file , &address , &is_dynamic);
        if (res == 0) {
            fclose(file);
            printf("PRF:: %s not found!\n", argv[1]);
        } else if (res == -1) {
            fclose(file);
            printf("PRF:: %s is not a global symbol! :(\n", argv[1]);
        } else {
            debugger(child_pid, address,&counter , is_dynamic);
        }
    }


    return 0;
}
