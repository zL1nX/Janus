
#include "serial.h"
#include <fcntl.h>
#include <string.h>
#include <termios.h>
#include <sys/ioctl.h>    /* BSD and Linux */

bool serial_open(serial_t* serial, const char* device, int baud_rate)
{
    struct termios options;

    // Open the serial port
    serial->fd = open(device, O_RDWR | O_NOCTTY);
    if (serial->fd == -1) {
        return false;
    }

    // Set the serial port parameters
    tcgetattr(serial->fd, &options);
    cfsetispeed(&options, B19200);
    cfsetospeed(&options, B19200);
    options.c_cflag &= ~CSIZE;
    options.c_cflag |= CS8;
    options.c_cflag &= ~PARENB;
    options.c_cflag &= ~CSTOPB;
    options.c_cflag &= ~CRTSCTS;
    options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    options.c_iflag &= ~(IXON | IXOFF | IXANY);
    options.c_cc[VMIN] = 0;
    options.c_cc[VTIME] = 10;
    tcsetattr(serial->fd, TCSANOW, &options);

    return true;
}

void serial_close(serial_t* serial)
{
    close(serial->fd);
}

int bytes_in_buffer(serial_t* serial)
{
    int bytes_avaliable = 0;
    ioctl(serial->fd, FIONREAD, &bytes_avaliable);
    return bytes_avaliable;
}

bool serial_empty(serial_t* serial)
{
    return (bytes_in_buffer(serial) == 0);
}

bool serial_write(serial_t* serial, const void* data, size_t size)
{
    ssize_t bytes_written = write(serial->fd, data, size);
    return (bytes_written == (ssize_t)size);
}


bool serial_read(serial_t* serial, void* buffer, size_t size)
{
    int bytes_avaliable = 0;
    while (1)
    {
        ioctl(serial->fd, FIONREAD, &bytes_avaliable);
        if(bytes_avaliable != 0)
        {
            break;
        }
    }
    ssize_t bytes_read = read(serial->fd, buffer, size);
    printf("%ld\n", bytes_read);
    return (bytes_read == (ssize_t)size);
}

bool serial_write_command(serial_t* serial, uint8_t cmd)
{
    ssize_t bytes_written = write(serial->fd, &cmd, 1);
    return (bytes_written == (ssize_t)1);
}