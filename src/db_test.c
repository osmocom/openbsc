#include "db.h"

#include <stdio.h>

int main() {

    if (db_init()) {
        printf("DB: Failed to init database. Please check the option settings.\n");
        return 1;
    }    
    printf("DB: Database initialized.\n");

    if (db_prepare()) {
        printf("DB: Failed to prepare database.\n");
        return 1;
    }
    printf("DB: Database prepared.\n");

    db_insert_imsi(3243245432351LLU);
    db_insert_imsi(3243245432352LLU);
    db_imsi_set_tmsi(3243245432345LLU, 99999999LLU);
    db_imsi_set_lac(3243245432345LLU, 42);

    db_subscriber alice;
    db_imsi_get_subscriber(3243245432345LLU, &alice);
    db_tmsi_get_subscriber(99999999LLU, &alice);

    db_fini();

    return 0;
}
