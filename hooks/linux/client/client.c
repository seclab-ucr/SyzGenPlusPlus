#include <stdio.h>

#include "driver.h"

int main(int argc, char **argv) {
    init_driver();

    enable_driver();
    test_driver();
    disable_driver();

    print_driver();

    close_driver();
    return 0;
}