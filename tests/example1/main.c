#include <unistd.h>

int bb(char a) {
  if (a == 'a') {
    return 1;
  } else {
    if (a == 'A') {
      return 0;
    }
    return 11;
  }
}

int main(int argc, char **argv) {
  // keep the program running for debugging purposes
  while (1) {
    sleep(5);
  }
}
