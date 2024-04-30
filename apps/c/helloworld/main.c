#include <stdio.h>

#include <unistd.h>

int main()
{
    printf("Hello from parent [%d]\n", getpid());
}