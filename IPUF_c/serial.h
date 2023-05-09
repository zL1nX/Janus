#ifndef SERIAL_H
#define SERIAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>


typedef struct {
    int fd;
} serial_t;

bool serial_open(serial_t* serial, const char* device, int baud_rate);
void serial_close(serial_t* serial);
bool serial_write(serial_t* serial, const void* data, size_t size);
bool serial_read(serial_t* serial, void* buffer, size_t size);
bool serial_write_command(serial_t* serial, uint8_t cmd);
bool serial_empty(serial_t* serial);
int bytes_in_buffer(serial_t* serial);

#endif // SERIAL_H