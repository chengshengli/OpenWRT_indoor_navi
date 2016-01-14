#include <stdlib.h>      // malloc, free, relloc    //
#include <stdio.h>       // printf                  //
#include <time.h>        // time_t                  //
#include <pcap.h>        // pcap_live               //
#include <unistd.h>      // close(socket)           //
#include <arpa/inet.h>   // inet_addr               //
#include <netdb.h>       // gethostbyname           //

#define      VAL_BUF 3   // Values q for every app

typedef struct {
    char mac[6];
    int  valid;
    int  signal;
} radiotap;

typedef struct {
    char *key;
    int  *values;
    int  values_num;
    time_t at;
} key_v;

typedef struct {
    int sm;
    int bg;
    int av;
} average;

    // TODO: move it to the main function.
    key_v keyv[500];
    char *ap_mac;
    static int keyv_len = 0;
    struct sockaddr_in addr; // server address
    struct hostent *server;  // server domain


// Radiotap data Offsets. We need only 6 offsets    //
unsigned int TO[] = {    // to get antenna values   //
                     16, // [0] TSFT                //
                      1, // [1] Flags               //
                      1, // [2] Rate                //
                      4, // [3] Channel             //
                      2, // [4] FHSS                //
                      1, // [5] Antenna             //
                      1};// [6] Antenna noise       //

void copyMac(char **key, const char *orig){
    /* some sort of strcpy */
    int i;
    int len = 7; // mac == 6 + 1 for '\0'
    *key = (char *)malloc(sizeof(char) * len);
    for(i = 0; i < len; i++){
        (*key)[i] = orig[i];
    }
}

void createKey(key_v *keyv, const char *k){
    /* create key in dict */
    copyMac(&keyv->key,k);
    keyv->values = (int *)malloc(sizeof(int) * VAL_BUF);
    keyv->values_num = 0;
};

void deleteKey(key_v *keyv){
    /* delete key in dict and allocated memory */
    free(keyv->key);
    if(keyv->values_num > 0){
        free(keyv->values);
        keyv->values_num = 0;
    }
}

void setNow(time_t *t){
    time(t);
}

void addValueKey(key_v *keyv, int value){
    /* add value to array of the key */
    int length = keyv->values_num;//++;
    if(length >= VAL_BUF){
        keyv->values = (int *)realloc(
            keyv->values, sizeof(int) * (length+1));
    }
    keyv->values[length] = value;
    keyv->values_num++;
}

void freeValueArr(key_v *keyv){
    free(keyv->values);
    keyv->values = (int *)malloc(sizeof(int) * VAL_BUF);
    keyv->values_num = 0;
}

int getValueLen(key_v *keyv){
    return keyv->values_num;
}

average* getAv(int *arr, int length){
    int i;
    average *av = (average *)malloc(sizeof(average));
    av->av = 0;
    av->sm = -255;
    av->bg = 255;
    for(i = 0; i < length; i++ ){
        if(av->sm < arr[i]){
            av->sm = arr[i];
        }
        if(av->bg > arr[i]){
            av->bg = arr[i];
        }
        av->av += arr[i];
    }
    av->av = av->av / length;
    return av;
}

int searchKey(const key_v *keys, const char *key, ...){
    /* search for key in dict */
    int i;
    int j;

    for(i = 0; i < keyv_len; i++){
        for(j=0;j<6;j++){
            if((&keys[i])->key[j] != key[j]){
                break;
            }
        }
        return i;
    }
    return -1;
}

int send_packet(struct sockaddr_in addr,
                key_v *keyv,
                average *av,
                char *ap_mac){
    int i;
    int rc;
    int sockfd;
    int data_len = 0;
    int pack_len = 0;
    char buffer[1000];
    char data_buffer[100];

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
        printf("Socket error\n");
        return -1;
    }

    rc = connect(sockfd,
                 (struct sockaddr *)&addr,
                 sizeof(struct sockaddr_in)
    );
    if(rc < 0) {
        printf("Connect tcp error\n");
        return rc;
    }

    data_len = sprintf(data_buffer, (
        "ap=%s&"
        "cl=%02x:%02x:%02x:%02x:%02x:%02x&"
        "av=%i&"
        "sm=%i&"
        "bg=%i"
        ), ap_mac,
           (unsigned char)keyv->key[0],
           (unsigned char)keyv->key[1],
           (unsigned char)keyv->key[2],
           (unsigned char)keyv->key[3],
           (unsigned char)keyv->key[4],
           (unsigned char)keyv->key[5],
           av->av,
           av->sm,
           av->bg
    );

    // TODO: ATTRS from args 
    pack_len = sprintf(buffer, (
            "POST / HTTP/1.1\n"
            "Host: example.com\n"
            "User-Agent: WIFIMON/0.01b\n"
            "Content-Type: application/x-www-form-urlencoded\n"
            "Connection: close\n"
            "Content-Length:%i\n\n"), data_len);

    for(i = 0; i < data_len; i++){
        buffer[pack_len+i] = data_buffer[i];
    }
    rc = send(sockfd, buffer, pack_len+data_len, 0);
    rc = recv(sockfd, buffer, sizeof(buffer), 0);
    close(sockfd);
    return rc;
}

void sendKey(key_v *keyv){
    average *av = getAv(keyv->values, keyv->values_num);
    send_packet(addr, keyv, av, ap_mac);
    free(av);
}

// omg, change the whole code bellow
void callback (u_char *arg,
               const struct pcap_pkthdr* pkthdr,
               const u_char* packet){
    int i;
    int result; // searchKey result
    int length = pkthdr->len;
    int header_len = packet[2] | packet[3] << 8;
    double diff;
    time_t now;
    time(&now);
    if(length > header_len + 4 + 6 + 6 && packet[4] >> 5 & 1){
        int ant_off = 0;
        int off_flag = 0;

        radiotap* tap = (radiotap *)malloc(sizeof(radiotap));
        for(i=0;i<6;i++){
            tap->mac[i] = packet[header_len+4+6+i];
        }
        for(i = 0; i < 8; i++){
            off_flag = packet[4] >> i & 1;
            if(i == 2 && off_flag != 1){
                off_flag = 1;
            }
            if(off_flag == 1){
                ant_off += TO[i];
            }
        }
        tap->signal = ((int)packet[7 + ant_off])-256;

        result = searchKey(keyv, tap->mac);
        if(result > -1){
            if(keyv[result].values_num < 1){
                keyv[result].at = now;
            }
            addValueKey(&keyv[result], tap->signal);
        } else {
            createKey(&(keyv[keyv_len]), tap->mac);
            addValueKey(&(keyv[keyv_len]), tap->signal);
            keyv[keyv_len].at = now;
            keyv_len++;
        }
        free(tap);
    }
    int keyv_len_t = 0;
    for(i=0;i<keyv_len;i++){
        diff = difftime(now, keyv[i].at);
        if(diff >= 1){
            if(keyv[i].values_num > 0){
                sendKey(&keyv[i]);
            }
            deleteKey(&keyv[i]);
        } else {
            keyv[keyv_len_t] = keyv[i];
            keyv_len_t++;
        }
    }
    keyv_len = keyv_len_t;
}

int is_bigendian(){
    int big = 1;
    if(*((unsigned char *) &big) == 0){
        return 1;
    } else {
        return 0;
    }
}

// TODO: Need to do multithreading
// 1 process is collector
// 1 process is packager
// 1 process is sender
int main(int argc, char* argv[]) {
    if(argc < 4){
        printf("Usage: %s domain port mac\n", argv[0]);
        printf("Example: %s example.com 80 ff:ff:ff:ff:ff:ff\n",argv[0]);
        return 1;
    }

    char dev[] = "mon0";
    char errbuf[PCAP_ERRBUF_SIZE];

    addr.sin_family = AF_INET;
    server = gethostbyname(argv[1]);
    int i;
    for(i=0;i<server->h_length;i++){
        if(is_bigendian()){
            addr.sin_addr.s_addr |= server->h_addr[i] << (24-(i*8));
        } else {
            addr.sin_addr.s_addr |= server->h_addr[i] << (8*i);
        }
    }

    addr.sin_port = htons(atoi(argv[2]));
    ap_mac = argv[3];
    pcap_t* descr;
    descr = pcap_open_live(dev, BUFSIZ, 1, 50, errbuf); /* 50 ms wait packs */
    if(descr == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        return 1;
    }
    pcap_loop(descr, -1, callback, NULL);
    return 0;
}
