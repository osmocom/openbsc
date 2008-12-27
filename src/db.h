#include <stdint.h>

#define NUMBER_LENGTH 32

typedef struct {
    uint64_t imsi;
    uint64_t tmsi;
    char number[NUMBER_LENGTH];
    uint16_t lac;
} db_subscriber;

int db_init();
int db_prepare();
int db_fini();

int db_insert_imei(uint64_t imei);

int db_insert_imsi(uint64_t imsi);
int db_imsi_set_tmsi(uint64_t imsi, uint64_t tmsi);
int db_imsi_set_lac(uint64_t imsi, uint16_t lac);
int db_imsi_get_subscriber(uint64_t imsi, db_subscriber* subscriber);
int db_tmsi_get_subscriber(uint64_t tmsi, db_subscriber* subscriber);

