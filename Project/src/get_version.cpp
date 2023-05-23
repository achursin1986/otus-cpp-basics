#include "get_version.h"

#include "version.h"

int patch_version() {
    return PROJECT_VERSION_PATCH;
}
int version() {
    return PROJECT_VERSION_MINOR;
}
