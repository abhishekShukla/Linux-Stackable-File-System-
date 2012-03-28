#include "wrapfs_ioctl.h"

int main(int argc, char **argv){
    
    char *mount_point = NULL;
    unsigned char* res = (unsigned char*)malloc(16*sizeof(unsigned char));
    unsigned char* md = (unsigned char*)malloc(16*sizeof(unsigned char));
    unsigned char* pass_temp = NULL;
    unsigned char* password = NULL;
    unsigned long keylen = 0;
    int pass_looper = 0;
    int temp_looper = 0; 
    int help = 0;
    int flag = 0;
    int option = 0; 
    int err = 1;
    int fd;
    int ret;
    memset(res, 0, 16);
    memset(md, 0, 16);
    while ((option = getopt (argc, argv, "m:p:h")) != -1){
        err = 0;
        switch(option){
            case 'm':
                mount_point = optarg;
                break;
            case 'p':
                pass_temp = (unsigned char*)optarg;
                break;
            case 'h':
                help = 1;
                break;
            case '?':
                if (optopt == 'p')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (optopt == 'd')
                     fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr, "Unknown option character `\\x%x'.\n",optopt);
                    fprintf (stderr, "Please Use \"./xcrypt -h\" for help\n");
                return 1;
            default:
                help = 1;
        }
    }
    if(err){
        fprintf(stderr,"ERROR: YOU ARE PROBABLY TRYING TO REDIRECT THE INPUT FROM A FILE. GET OPT FAILED!\n\n");
        help = 1;
    }
    if(help){
        printf("USAGE:\n./pass_key [OPTIONS] [ARGUMENT] [INPUT] \nDESCRIPTION\n\tOPTIONS\n\t\t-m: Mount Point Directory \n\t\t-p: Encryption/Decryption Key. Pass the Key as the Argument. Must be atleast 6 characters\n\t\t-h: Help\n");
        return 0;
    }
    if((strlen((char*)pass_temp) < 6)){
        fprintf(stderr,"PASSWORD IS TOO SHORT. IT MUST BE ATLEAST 6 CHARACTERS LONG!\n");
        return 1;
    }
    
    password = (unsigned char*)malloc(strlen((char*)pass_temp));
    memset(password, 0, strlen((char*)pass_temp));
    
    for(temp_looper = 0; temp_looper < strlen((char*)pass_temp); temp_looper++){
        if(pass_temp[temp_looper] != '\n'){
            password[pass_looper] = pass_temp[temp_looper];
            pass_looper++;
        }
    }
    
    for(pass_looper = 0; pass_looper < strlen((char*)password) - 1; pass_looper++){
        if(password[pass_looper] != '0'){
            flag = 1;
        }
    }
    
    if(flag == 0){
        memset(md, '0', 16);
    }
    else{
        keylen = strlen((char*)password);
        md = MD5(password, keylen ,res);
    }

    fd = open("/mnt/wrapfs", O_RDONLY);
    if(fd < 0){
        printf("Could Not Open Descriptor\n");
        return 1;
    }
    ret = ioctl(fd, WRAPFS_IOCSETD, md);

    close(fd);
    
    return 0;

}
