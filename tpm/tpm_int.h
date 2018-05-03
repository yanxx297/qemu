/*
 * TPM configuration
 *
 * Copyright (C) 2011-2013 IBM Corporation
 *
 * Authors:
 *  Stefan Berger    <stefanb@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef TPM_TPM_INT_H
#define TPM_TPM_INT_H

#include "exec/memory.h"
#include "tpm/tpm_tis.h"

struct TPMDriverOps;
typedef struct TPMDriverOps TPMDriverOps;

typedef struct TPMBackend {
    char *id;
    enum TpmModel fe_model;
    char *path;
    char *cancel_path;
    const TPMDriverOps *ops;

    QLIST_ENTRY(TPMBackend) list;
} TPMBackend;

/* overall state of the TPM interface */
typedef struct TPMState {
    ISADevice busdev;
    MemoryRegion mmio;

    union {
        TPMTISEmuState tis;
    } s;

    uint8_t     locty_number;
    TPMLocality *locty_data;

    char *backend;
    TPMBackend *be_driver;
} TPMState;

#define TPM(obj) OBJECT_CHECK(TPMState, (obj), TYPE_TPM_TIS)

typedef void (TPMRecvDataCB)(TPMState *, uint8_t locty);

struct TPMDriverOps {
    enum TpmType type;
    /* get a descriptive text of the backend to display to the user */
    const char *(*desc)(void);

    TPMBackend *(*create)(QemuOpts *opts, const char *id);
    void (*destroy)(TPMBackend *t);

    /* initialize the backend */
    int (*init)(TPMBackend *t, TPMState *s, TPMRecvDataCB *datacb);
    /* start up the TPM on the backend */
    int (*startup_tpm)(TPMBackend *t);
    /* returns true if nothing will ever answer TPM requests */
    bool (*had_startup_error)(TPMBackend *t);

    size_t (*realloc_buffer)(TPMSizedBuffer *sb);

    void (*deliver_request)(TPMBackend *t);

    void (*reset)(TPMBackend *t);

    void (*cancel_cmd)(TPMBackend *t);

    bool (*get_tpm_established_flag)(TPMBackend *t);
};

TPMBackend *qemu_find_tpm(const char *id);
int tpm_register_model(enum TpmModel model);
int tpm_register_driver(const TPMDriverOps *tdo);
void tpm_display_backend_drivers(void);
const TPMDriverOps *tpm_get_backend_driver(const char *type);

#endif /* TPM_TPM_INT_H */
