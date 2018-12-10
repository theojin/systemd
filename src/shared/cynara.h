#pragma once

#include "sd-bus.h"

typedef struct CynaraData CynaraData;

int cynara_data_new(sd_event *event, CynaraData **cynara_data);
void cynara_data_free(CynaraData *data);

int bus_verify_cynara(sd_bus_message *call, CynaraData* cynara_data);
int bus_verify_cynara_async(sd_bus_message *call, int capability, CynaraData* cynara_data);
