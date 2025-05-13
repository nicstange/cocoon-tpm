# Generate the interface.rs with gen-tpm2-cmd-interface
# from https://github.com/nicstange/gen-tpm2-cmd-interface-rs

gen-tpm2-cmd-interface \
    -t tpm2_algorithms.csv \
    -t tpm2_structures.csv \
    -t tpm2_commands.csv \
    -t tpm2_vendor.csv \
    -d TPM_RC \
    -d TPMT_HA \
    -d TPMI_ALG_HASH \
    -d TPM2B_PUBLIC_KEY_RSA \
    -d TPM2B_PRIVATE_KEY_RSA \
    -d TPM_ECC_CURVE \
    -d TPMS_ECC_POINT \
    -m TPMS_ECC_POINT \
    -u TPMS_ECC_POINT \
    -d TPM2B_ECC_PARAMETER \
    -d TPMI_ALG_SYM_OBJECT \
    -d TPMI_ALG_CIPHER_MODE \
    -m TPMI_ALG_HASH \
    -u TPMI_ALG_HASH \
    -m TPMI_ALG_CIPHER_MODE \
    -m TPMI_ALG_SYM_OBJECT \
    -u TPMI_ALG_SYM_OBJECT \
    -s TPMU_HA
