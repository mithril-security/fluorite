# tpm-quote

A library for generating and verifying TPM 2.0 quotes.


### Generating a Quote

To generate a quote, you'll need access to a TPM device. Here's a basic example:

```rs
use tpm_quote::generate::*;
use tss_esapi::structures::PcrSelectionList;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::PcrSlot;

let mut tpm_ctx = tpm_context()?;

// To generate a quote, you first need to select the key you want the quote to be signed with.
// At the moment, this crate only supports using AK specified by an AK template stored in the TPM's NVRAM.
// The example below uses the RSA AK of a GCP Shielded VM's TPM.
let mut ak_handle = AttestationKeyHandle::create_from_template_at_nvindex(
    &mut tpm_ctx,
    0x01c10001.try_into()?,
)?;
// Then you need to select which PCRs you want to include in the quote. Below we only include sha256:0, but you'll likely want to include more.
let pcr_selections = PcrSelectionList::builder()
    .with_selection(
        HashingAlgorithm::Sha256,
        &[PcrSlot::Slot0],
    )
    .build()?;

// Finally you can generate the quote.
let quote = ak_handle.quote(&pcr_selections)?;
```

### Verifying a Quote

```rs
use tpm_quote::verify::*;

// To verify a quote you need a quote and the public key of the AK that signed it :
let quote: Quote = ...;

// AK certificate in DER format (a certificate already validated).
// Retrieving the AK certificate is out of scope for this crate. 
let ak_leaf_cert_bytes : &[u8] = ...; 
let ak_leaf_cert = rustls_pki_types::CertificateDer::from_slice(ak_leaf_cert_bytes);

let ak = EccAttestationKey::try_from_der(ak_leaf_cert)?;

// Now let's verify the quote. 
let verified_pcr_data = ak.verify_quote(&quote)?;

// Important : To assess the state of the remote system, the verifier considers the
// TPM state, i.e. the values of the quoted PCRs. The verifier MUST use the `SanitizedPcrData` 
// returned by the `verify_quote` method, and MUST NOT use Pcr Data originating elsewhere as they are not verified.
// Only `SanitizedPcrData` can be assumed to represent the genuine values of the PCRs of the remote system.

println!("Verified PCR data: {:?}", verified_pcr_data);
```

## Features

The crate has two features:

- `generate`: Enables quote generation.
- `verify`: Enables quote verification.

Both features are enabled by default. You can disable one if you only need the generation or verification part. 

Note that the `generate` feature depends on `tss-easpi-sys`, which is a binding to the TPM Software Stack (TSS) through a C FFI.  So `generate` add some requirements when building. It also limits platform support. The verify feature however does not depend on `tss-esapi` and is mostly relying on pure-Rust dependencies, so it does not have these constraints.

## Credits 

The `common` module contains source code from the [`rust-tss-esapi` repo](https://github.com/parallaxsecond/rust-tss-esapi/tree/96f685554edc2aa57e298a017831e13fe975313c). This code is licensed under the Apache License, Version 2.0 and is authored by the Parsec Project Contributors.

## License

This project is licensed under the Apache License, Version 2.0. See the LICENSE file for details.