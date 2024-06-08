#include "lib.h"

char* NewCharArray(size_t size) {
    // Allocate memory for the array
    char* array = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size * sizeof(char));
    if (!array) {
        // Handle allocation failure
        MessageBox(NULL, TEXT("Memory allocation failed"), TEXT("Error"), MB_OK | MB_ICONERROR);
        return NULL;
    }
    return array;
}

void FreeCharArray(char* array) {
    if (array) {
        HeapFree(GetProcessHeap(), 0, array);
    }
}