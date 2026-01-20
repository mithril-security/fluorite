# tpm-structs


`tpm-structs` is a library that provides rust types for the TPMT_SIGNATURE and TPMS_ATTEST structures with methods for marshalling and unmarshalling.

The code in this crate was initially auto-generated using the [gen-tpm2-cmd-interface](https://github.com/nicstange/gen-tpm2-cmd-interface-rs/tree/fe8e01e26d398a8a36513cfc1108e9b43bc50466) tool, which generates Rust code from TPM 2.0 specification tables. Thanks to Nicolai Stange for this work.

Modifications were made to adapt the generated code for our usecase (not implementing a TPM, but implementing a quote verifier).

## How was the original code generated ?

The following steps outline how the code was generated. These instructions can be followed to reproduce or understand the code generation process.

### Step 1 : Extract TPM2 Specification tables from official PDFs

Clone and build the `extract-tpm2-spec-tables` tool :

```console
git clone git@github.com:mithril-security/extract-tpm2-spec-tables.git
cd extract-tpm2-spec-tables
cargo build --release
alias extract-tpm2-spec-tables="$PWD/target/release/extract-tpm2-spec-tables"
``` 

Download the PDF from TCG website :

```console
wget https://trustedcomputinggroup.org/wp-content/uploads/TCG-_Algorithm_Registry_r1p32_pub.pdf
wget https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf
wget https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part3_Commands_pub.pdf
```

Extract the tables and output them as CSV files :

```console
extract-tpm2-spec-tables -s 'TCG Algorithm Registry (rev 01.32)' TCG-_Algorithm_Registry_r1p32_pub.pdf > tpm2_algorithms.csv
extract-tpm2-spec-tables -s 'TCG TPM2 Library (rev 01.59), Part 2' TCG_TPM2_r1p59_Part2_Structures_pub.pdf > tpm2_structures.csv
extract-tpm2-spec-tables -s 'TCG TPM2 Library (rev 01.59), Part 3' TCG_TPM2_r1p59_Part3_Commands_pub.pdf > tpm2_commands.csv
```

### Step 2: Generate the TPM 2.0 Structures Interface Code


```console
git clone git@github.com:nicstange/gen-tpm2-cmd-interface-rs.git
cd gen-tpm2-cmd-interface-rs
cargo build --release
alias gen-tpm2-cmd-interface="$PWD/target/release/gen-tpm2-cmd-interface"
```

#### Prepare the tables:

Create a "tables" directory and copy the csv files from the step 1 to `gen-tpm2-cmd-interface-rs/tables`

#### Patch the tables to fix issues and inconsistencies:

A patch file is provided to automate the input preparation step as described in the [usage section of the gen-tpm2-cmd-interface](https://github.com/nicstange/gen-tpm2-cmd-interface-rs/tree/fe8e01e26d398a8a36513cfc1108e9b43bc50466?tab=readme-ov-file#usage). The patch also creates an additional `tpm2_vendor.csv` file.

Apply the patch:


```console
$ patch --directory=tables --strip=1 < REPLACE_WITH_PATH_TO_PATCH
patching file tpm2_algorithms.csv
patching file tpm2_commands.csv
patching file tpm2_structures.csv
patching file tpm2_vendor.csv
```

#### Generate the code for the TPMT_SIGNATURE, TPMS_ATTEST and TPMT_PUBLIC structures 

```console
gen-tpm2-cmd-interface \
    -t tables/tpm2_algorithms.csv  \
    -t tables/tpm2_structures.csv  \
    -t tables/tpm2_commands.csv    \
    -t tables/tpm2_vendor.csv      \
    -u TPMT_SIGNATURE \
    -m TPMT_SIGNATURE \
    -u TPMS_ATTEST \
    -m TPMS_ATTEST \
    -u TPMT_PUBLIC \
    -m TPMT_PUBLIC \
    > generated.rs
```

## What modifications were made ? 

The code was modified to :
  * remove use of cargo features, enabling all of them by default 
  * remove use of `Box::<Self>::try_new` as we don't care about allocation failure (we don't expect our crate to be used in memory constrained environments)
  * generate enum kind types for TpmtSignature with [kinded](https://docs.rs/kinded/latest/kinded/)
  * add `#![forbid(unsafe_code)]`
  * implement reasonable defaults for TpmLimits : 

```rs
impl Default for TpmLimits {
    fn default() -> Self { 
        TpmLimits {
            hash_count: 16,
            implementation_pcr: 32,
            max_nv_buffer_size: 2048,
            max_rsa_key_bytes: 4096,
            platform_pcr: 0,
        }
    }
}
```

##### License

Licensed under Apache License Version 2.0
