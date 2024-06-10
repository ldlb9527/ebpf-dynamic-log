//go:build ignore

#include <stdio.h>

int AddNum(int i, int i1);


int main() {
    printf("%d\n", AddNum(3,2));
    return 0;
}

int AddNum(int n1, int n2) {
    return n1 + n2;
}