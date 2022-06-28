#include <stdio.h>
#include <stdlib.h>
#include "elf64.h"
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>


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
        execv(argv[2], argv);
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

int find_function_dynamic(Elf64_Ehdr *header, char *function, FILE *file , Elf64_Addr * address){}

int find_function_in_st(Elf64_Ehdr *header, char *function, FILE *file , Elf64_Addr * address) {
    int ret = 0;
    fseek(file,header->e_shoff,SEEK_SET); // pointer to section header table
    Elf64_Shdr s_header , symtab_header , str_header;
    for(int i = 0 ; i < header->e_shnum ; i++ ){ //search for needed tables
        fread(&s_header , header->e_shentsize , 1 , file);
        if (s_header.sh_type == SHT_SYMTAB){
           symtab_header = s_header;
        } else if (s_header.sh_type == SHT_STRTAB){
            str_header = s_header;
        }
    }

    //read symtab
    fseek(file,symtab_header.sh_offset,SEEK_SET);// go to symtab
    Elf64_Xword sym_quantity = symtab_header.sh_size / symtab_header.sh_entsize;
    Elf64_Sym symtab_table[sym_quantity]; // array with size of the number of sections
    fread(symtab_table, symtab_header.sh_entsize, sym_quantity, file); // read the symtab sections

    char *str_table = malloc(str_header.sh_size );
    fseek(file,str_header.sh_offset,SEEK_SET);// go to symtab
    fread(str_table,str_header.sh_size,1,file);

    int place = check_substring(str_table,str_header.sh_size,function); // checks for function offset
    if(place == -1){
        ret =  -1;
    } else {

        for (int i = 0; i < sym_quantity; i++) {
            Elf64_Word offset = symtab_table[i].st_name;
            if (offset == place) {
                if (symtab_table[i].st_info != 0) { // if its the right symtab entry update the address
                    *address = symtab_table[i].st_value;
                    if(symtab_table[i].st_shndx == 0){
                        find_function_dynamic(header,function,file,address); //TODO complete
                    }
                    ret = 1;
                    break;
                } else {
                    ret = 0;
                    break;
                }
            }
        }
    }

    free(str_table);
    return ret;
}

void debugger(pid_t pid, Elf64_Addr address,int* counter){
    struct user_regs_struct regs;
    long data;
    unsigned long break_data;
    int wait_status;
    wait(&wait_status);
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
        int res = find_function_in_st(&header, argv[1], file , &address);
        if (res == 0) {
            fclose(file);
            printf("PRF:: %s not found!\n", argv[1]);
        } else if (res == -1) {
            fclose(file);
            printf("PRF:: %s is not a global symbol!\n", argv[1]);
        } else {
            debugger(child_pid, address,&counter);
        }
    }


    return 0;
}
