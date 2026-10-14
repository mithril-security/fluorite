// Initialize Lucide icons
lucide.createIcons();

const domainInput = document.getElementById('domain-input');
const lookupForm = document.getElementById('domain-lookup-form');
const lookupButton = document.getElementById('lookup-button');
const buttonText = document.getElementById('button-text');
const loadingSpinner = document.getElementById('loading-spinner');
const inputErrorMessage = document.getElementById('input-error-message');

const resultsSection = document.getElementById('results-section');
const resultsTitle = document.getElementById('results-title');
const domainDisplay = document.querySelector('.domain-display');
const loadingIndicator = document.getElementById('loading-indicator');
const errorDisplay = document.getElementById('error-display');
const errorMessageText = document.getElementById('error-message-text');

const certificateTableSection = document.getElementById('certificate-table-view');
const wildcardCertificateMessage = document.getElementById('wildcard-certificate-message');

const certificateTableBody = document.getElementById('certificate-table-body');

const certificateTableContainer = document.getElementById('certificate-table-container');
const crtShError = document.getElementById('crt-sh-error');
const crtShErrorText = document.getElementById('crt-sh-error-text');
const crtShEmpty = document.getElementById('crt-sh-empty');

const liveCertificateView = document.getElementById('live-certificate-view');
const liveCertificateTableContainer = document.getElementById('live-certificate-table-container');
const liveCertificateError = document.getElementById('live-certificate-error');
const liveCertificateErrorText = document.getElementById('live-certificate-error-text');
const liveCertificateTableBody = document.getElementById('live-certificate-table-body');

const singleCertificateView = document.getElementById('single-certificate-view');
const certificateDataDisplay = document.getElementById('certificate-data-display');

// Information fields
const infoIssuer = document.getElementById('info-issuer');
const infoSubject = document.getElementById('info-subject');
const infoValidFrom = document.getElementById('info-valid-from');
const infoValidTo = document.getElementById('info-valid-to');
const infoDaysRemaining = document.getElementById('info-days-remaining');
const infoSerial = document.getElementById('info-serial');
const domainCn = document.getElementById('domain-cn');
const domainSans = document.getElementById('domain-sans');
const techSignatureAlgo = document.getElementById('tech-signature-algo');
const techPubkeyAlgo = document.getElementById('tech-pubkey-algo');
const techPubkeyAlgoParam = document.getElementById('tech-pubkey-algo-param');
const techPubkeySize = document.getElementById('tech-pubkey-size');
const techPubkey = document.getElementById('tech-pubkey');
const techVersion = document.getElementById('tech-version');
const rawCertificate = document.getElementById('raw-certificate');
const rawCertificateLink = document.getElementById('raw-certificate-link');
const copyRawCertButton = document.getElementById('copy-raw-cert-button');
const copyMessage = document.getElementById('copy-message');

// Attestation fields (Current Certificate)
const attestationBackend = document.getElementById('attestation-backend');
const attestationOperatorCert = document.getElementById('attestation-operator-cert');
const rawAttestationDocumentTxt = document.getElementById('attestation-raw-document');

const copyOperatorCertButton = document.getElementById('copy-operator-cert-button');
const copyOperatorMessage = document.getElementById('copy-operator-message');
const attestationPackageHashDisplay = document.getElementById('attestation-package-hash-display');
const attestationPackageHashLink = document.getElementById('attestation-package-hash-link');
const attestationOsHashDisplay = document.getElementById('attestation-os-hash-display');
const attestationOsHashLink = document.getElementById('attestation-os-hash-link');
const attestationStatusIcon = document.getElementById('attestation-status-icon');
const attestationLink = document.getElementById('attestation-link');
const attestationStatusText = document.getElementById('attestation-status-text');


const backToTableButton = document.getElementById('back-to-table-button');
const lookupAnotherButton = document.getElementById('lookup-another-button');
const safetyMessage = document.getElementById('safety-message'); // Get the safety message element
const keyProperties = document.getElementById('key-properties');
const reportedTCBVersion = document.getElementById('reported-tcb-version');
const platformInfo = document.getElementById('platform-info');
const operatorCertificate = document.getElementById('operator-certificate');
const rawAttestationDocument = document.getElementById('raw-document');

let allCertificateData = []; // Store the fetched data globally


function uint8ToHex(uint8) {
    // Use map to convert each number to a padded hex string
    const hexArray = Array.from(uint8, (byte) => {
        // Convert the number to a hex string and pad with a leading zero
        return byte.toString(16).padStart(2, '0');
    });
    // Join all the hex strings together
    return hexArray.join('');
}

// --- Helper Functions ---

/**
 * Sets the loading state for the lookup button and results section.
 * @param {boolean} isLoading - True to show loading state, false otherwise.
 */
function setLoadingState(isLoading) {
    lookupButton.disabled = isLoading;
    if (isLoading) {
        buttonText.textContent = 'Loading...';
        loadingSpinner.classList.remove('hidden');
        resultsSection.classList.remove('hidden'); // Show results section to display loading indicator
        loadingIndicator.classList.remove('hidden');
        certificateDataDisplay.classList.add('hidden');
        errorDisplay.classList.add('hidden');
        lookupAnotherButton.classList.add('hidden');
        backToTableButton.classList.add('hidden');
        inputErrorMessage.classList.add('hidden'); // Hide input error
        safetyMessage.classList.add('hidden'); // Hide safety message during loading
        certificateTableSection.classList.add('hidden'); // Hide table during loading
        liveCertificateView.classList.add('hidden');
        liveCertificateTableBody.replaceChildren();
        wildcardCertificateMessage.classList.add('hidden'); // Hide wilcard message during loading
        singleCertificateView.classList.add('hidden'); // Hide single view during loading

        keyProperties.classList.add('hidden');
        reportedTCBVersion.classList.add('hidden');
        platformInfo.classList.add('hidden');
        operatorCertificate.classList.add('hidden');
        rawAttestationDocument.classList.add('hidden');
    } else {
        buttonText.textContent = 'Lookup Certificate';
        loadingSpinner.classList.add('hidden');
        loadingIndicator.classList.add('hidden');
    }
}

/**
 * Displays an error message in the results section.
 * @param {string} message - The error message to display.
 * @param {boolean} isLookupError - True if it's a top-level lookup error, false otherwise.
 */
function displayError(message, errorType = "lookup") {
    setLoadingState(false);
    resultsSection.classList.remove('hidden');
    errorDisplay.classList.remove('hidden');
    errorMessageText.textContent = message;
    lookupAnotherButton.classList.remove('hidden');


    if (errorType == "lookup") {
        certificateDataDisplay.classList.add('hidden');
        certificateTableSection.classList.add('hidden');
        liveCertificateView.classList.add('hidden');
        wildcardCertificateMessage.classList.add('hidden');
        singleCertificateView.classList.add('hidden');
        safetyMessage.classList.add('hidden');
        backToTableButton.classList.add('hidden');
    } else if (errorType == "certificate_info") {
        // For errors within a specific certificate view, hide data but keep the view and the back button.
        certificateDataDisplay.classList.add('hidden');
        certificateTableSection.classList.add('hidden');
        liveCertificateView.classList.add('hidden');
        wildcardCertificateMessage.classList.add('hidden');
        singleCertificateView.classList.remove('hidden');
        safetyMessage.classList.add('hidden');
        backToTableButton.classList.remove('hidden');
    } else if (errorType == "cluster_info") {
        certificateTableSection.classList.add('hidden');
        liveCertificateView.classList.add('hidden');
        singleCertificateView.classList.remove('hidden');
        wildcardCertificateMessage.classList.add('hidden');
        safetyMessage.classList.add('hidden');
        backToTableButton.classList.remove('hidden');

    }
}

/**
 * Populates the attestation details fields for a given attestation object.
 * This function is reused for both current and past certificates.
 * @param {object} attestation - The attestation document object.
 * @param {string} prefix - A prefix for element IDs (e.g., 'attestation-' for current, 'past-attestation-' for past).
 * @param {string} copyOpCertBtnId - ID of the copy operator cert button.
 * @param {string} copyOpMsgId - ID of the copy operator message span.
 * @param {boolean} isPastCert - True if this is a past certificate, for smaller icons.
 * @param {HTMLElement} safetyMsgElement - Reference to the main safety message element.
 */
function populateAttestationDetails(data, prefix, copyOpCertBtnId, copyOpMsgId, safetyMsgElement, domain) {
    const cluster_info = data.cluster_info;
    const attestation_report = data.attestation_report;

    const is_valid_now = data.certificate_info.is_valid_now;

    const iconSizeClass = 'w-5 h-5';
    const textSizeClass = 'text-sm';

    // Helper to get element by full ID including prefix
    const getElement = (suffix) => document.getElementById(prefix + suffix);

    // Get all relevant elements using the provided prefix
    const attestationBackendElement = getElement('backend');
    const operatorCertElement = getElement('operator-cert');
    const packageHashDisplayElement = getElement('package-hash-display');
    const packageHashLinkElement = getElement('package-hash-link');
    const osHashDisplayElement = getElement('os-hash-display');
    const osHashLinkElement = getElement('os-hash-link');
    const statusIconElement = getElement('status-icon');
    const statusTextElement = getElement('status-text');
    const rawAttestationElement = getElement('raw-document');

    if (statusTextElement) statusTextElement.textContent = '';

    if (statusIconElement) statusIconElement.replaceChildren(createIcon('check-circle', `${iconSizeClass} text-green-500`));
    if (statusTextElement && is_valid_now && cluster_info) {
        statusTextElement.textContent = 'Valid';
        statusTextElement.classList.remove('text-red-500', 'text-orange-500');
        statusTextElement.classList.add('text-green-500');
    } else if (statusTextElement && cluster_info) {
        statusTextElement.textContent = 'Error. Attestation document is valid, but certificate has expired.';
        statusTextElement.classList.remove('text-red-500', 'text-orange-500');
        statusTextElement.classList.add('text-orange-500');
        statusIconElement.replaceChildren(createIcon('alert-triangle', `${iconSizeClass} text-orange-500`));
    } else {
        statusTextElement.textContent = 'Error. Attestation document is not valid.';
        statusTextElement.classList.remove('text-green-500', 'text-orange-500');
        statusTextElement.classList.add('text-red-500');
        statusIconElement.replaceChildren(createIcon('x-circle', `${iconSizeClass} text-red-500`));
        displayError(`Error verifying attestation for ${domain}: ${data.reason}`, "cluster_info");
        return // Early return because there is no cluster_info
    }

    // Show the key properties
    keyProperties.classList.remove('hidden');
    // Don't show on AzureTrustedLaunchVM    
    operatorCertificate.classList.remove('hidden');
    rawAttestationDocument.classList.remove('hidden');

    if (attestationBackendElement) attestationBackendElement.textContent = cluster_info.attestation_backend;
    if (operatorCertElement) operatorCertElement.value = cluster_info.operator_cert || 'N/A';
    if (rawAttestationElement) rawAttestationElement.value = JSON.stringify(attestation_report, null, 2) || 'N/A';

    const copyOperatorCertButton = document.getElementById(copyOpCertBtnId);
    if (copyOperatorCertButton) {
        if (cluster_info.operatorCertificate && cluster_info.operatorCertificate !== 'N/A') {
            copyOperatorCertButton.classList.remove('hidden');
        } else {
            copyOperatorCertButton.classList.add('hidden');
        }
        copyOperatorCertButton.onclick = async () => {
            if (operatorCertElement) {
                await copyToClipboard(operatorCertElement);
                const copyMessageSpan = document.getElementById(copyOpMsgId);
                if (copyMessageSpan) {
                    copyMessageSpan.classList.remove('hidden');
                    setTimeout(() => {
                        copyMessageSpan.classList.add('hidden');
                    }, 2000);
                }
            }
        };
    }

    if (packageHashDisplayElement) packageHashDisplayElement.textContent = cluster_info.provisioning_bundle_digest;
    if (osHashDisplayElement) osHashDisplayElement.textContent = cluster_info.os_measurement;


    if (safetyMsgElement && is_valid_now) {
        safetyMsgElement.classList.remove('hidden');
    }

    if (cluster_info.attestation_backend == "SvsmVtpm") {
        reportedTCBVersion.classList.remove('hidden');
        platformInfo.classList.remove('hidden');
        document.getElementById('tr-vmpl').classList.remove('hidden');
        document.getElementById('tr-measurement').classList.remove('hidden');
        document.getElementById('tr-chip-id').classList.remove('hidden');

        const vmplElement = getElement('vmpl');
        const measurementElement = getElement('measurement');
        const chipIDElement = getElement('chip-id');
        const reportedTcbMicrocodeElement = getElement('reported-tcb-microcode');
        const reportedTcbSNPElement = getElement('reported-tcb-snp');
        const reportedTcbTEEElement = getElement('reported-tcb-tee');
        const reportedTcbBootLoaderElement = getElement('reported-tcb-bootloader');
        const reportedTcbFMCElement = getElement('reported-tcb-fmc');
        const platformInfoSmtElement = getElement('platform-info-smt');
        const platformInfoTsmeElement = getElement('platform-info-tsme');
        const platformInfoEccElement = getElement('platform-info-ecc');
        const platformInfoRaplElement = getElement('platform-info-rapl');
        const platformInfoChElement = getElement('platform-info-ch');
        const platformInfoAliasCheckElement = getElement('platform-info-alias-check');
        const platformInfoSevTioElement = getElement('platform-info-sev-tio');

        if (attestation_report != null) {
            if (vmplElement) vmplElement.textContent = attestation_report.vmpl !== undefined ? attestation_report.vmpl : 'N/A';
            if (measurementElement) measurementElement.textContent = uint8ToHex(attestation_report.measurement) || 'N/A';
            if (chipIDElement) chipIDElement.textContent = uint8ToHex(attestation_report.chip_id) || 'N/A';

        }

        if (attestation_report.reported_tcb) {
            if (reportedTcbMicrocodeElement) reportedTcbMicrocodeElement.textContent = attestation_report.reported_tcb.microcode;
            if (reportedTcbSNPElement) reportedTcbSNPElement.textContent = attestation_report.reported_tcb.snp;
            if (reportedTcbTEEElement) reportedTcbTEEElement.textContent = attestation_report.reported_tcb.tee;
            if (reportedTcbBootLoaderElement) reportedTcbBootLoaderElement.textContent = attestation_report.reported_tcb.bootloader;
            if (reportedTcbFMCElement) reportedTcbFMCElement.textContent = attestation_report.reported_tcb.fmc || 'N/A';
        } else {
            if (reportedTcbMicrocodeElement) reportedTcbMicrocodeElement.textContent = 'N/A';
            if (reportedTcbSNPElement) reportedTcbSNPElement.textContent = 'N/A';
            if (reportedTcbTEEElement) reportedTcbTEEElement.textContent = 'N/A';
            if (reportedTcbBootLoaderElement) reportedTcbBootLoaderElement.textContent = 'N/A';
            if (reportedTcbFMCElement) reportedTcbFMCElement.textContent = 'N/A';
        }

        if (attestation_report.plat_info != null) {
            /// A structure with a bit-field unsigned 64 bit integer:
            /// Bit 0 representing the status of SMT enablement.
            /// Bit 1 representing the status of TSME enablement.
            /// Bit 2 indicates if ECC memory is used.
            /// Bit 3 indicates if RAPL is disabled.
            /// Bit 4 indicates if ciphertext hiding is enabled
            /// Bit 5 indicates that alias detection has completed since the last system reset and there are no aliasing addresses. Resets to 0.
            /// Bit 6 reserved
            /// Bit 7 indicates that SEV-TIO is enabled.
            /// Bits 8-63 are reserved.

            let smtEnabled = (attestation_report.plat_info & (1 << 0));
            let tsmeEnabled = (attestation_report.plat_info & (1 << 1));
            let eccEnabled = (attestation_report.plat_info & (1 << 2));
            let raplDisabled = (attestation_report.plat_info & (1 << 3));
            let ciphertextHidingEnabled = (attestation_report.plat_info & (1 << 4));
            let aliasingCheckComplete = (attestation_report.plat_info & (1 << 5));
            let sevTioEnabled = (attestation_report.plat_info & (1 << 7));

            if (platformInfoSmtElement) platformInfoSmtElement.textContent = smtEnabled !== undefined ? (smtEnabled ? 'Yes' : 'No') : 'N/A';
            if (platformInfoTsmeElement) platformInfoTsmeElement.textContent = tsmeEnabled !== undefined ? (tsmeEnabled ? 'Yes' : 'No') : 'N/A';
            if (platformInfoEccElement) platformInfoEccElement.textContent = eccEnabled !== undefined ? (eccEnabled ? 'Yes' : 'No') : 'N/A';
            if (platformInfoRaplElement) platformInfoRaplElement.textContent = raplDisabled !== undefined ? (raplDisabled ? 'Yes' : 'No') : 'N/A';
            if (platformInfoChElement) platformInfoChElement.textContent = ciphertextHidingEnabled !== undefined ? (ciphertextHidingEnabled ? 'Yes' : 'No') : 'N/A';
            if (platformInfoAliasCheckElement) platformInfoAliasCheckElement.textContent = aliasingCheckComplete !== undefined ? (aliasingCheckComplete ? 'Yes' : 'No') : 'N/A';
            if (platformInfoSevTioElement) platformInfoSevTioElement.textContent = sevTioEnabled !== undefined ? (sevTioEnabled ? 'Yes' : 'No') : 'N/A';
        } else {
            if (platformInfoSmtElement) platformInfoSmtElement.textContent = 'N/A';
            if (platformInfoTsmeElement) platformInfoTsmeElement.textContent = 'N/A';
            if (platformInfoEccElement) platformInfoEccElement.textContent = 'N/A';
            if (platformInfoRaplElement) platformInfoRaplElement.textContent = 'N/A';
            if (platformInfoChElement) platformInfoChElement.textContent = 'N/A';
            if (platformInfoAliasCheckElement) platformInfoAliasCheckElement.textContent = 'N/A';
            if (platformInfoSevTioElement) platformInfoSevTioElement.textContent = 'N/A';
        }
    } else {
        document.getElementById('tr-vmpl').classList.add('hidden');
        document.getElementById('tr-measurement').classList.add('hidden');
        document.getElementById('tr-chip-id').classList.add('hidden');
    }
    lucide.createIcons(); // Re-create lucide icons for newly added HTML
}

/**
 * Populates the detailed view for a single certificate.
 * @param {object} data - The certificate data for a single entry.
 * @param {string} domain - The domain that was looked up.
 * @param {object} response - The full API response, holding the fields shared by all entries.
 */
function displaySingleCertificateInfo(data, domain, response) {
    console.log("displaySingleCertificateInfo", data);
    singleCertificateView.classList.remove('hidden');
    certificateTableSection.classList.add('hidden');
    liveCertificateView.classList.add('hidden');
    wildcardCertificateMessage.classList.add('hidden');
    errorDisplay.classList.add('hidden'); // Hide any previous errors
    lookupAnotherButton.classList.remove('hidden'); // Show "Lookup Another" button
    backToTableButton.classList.remove('hidden');
    keyProperties.classList.add('hidden');
    reportedTCBVersion.classList.add('hidden');
    platformInfo.classList.add('hidden');
    operatorCertificate.classList.add('hidden');

    domainDisplay.textContent = domain;

    // Check if attestation data exists for the selected entry
    if (!data.certificate_info) {
        certificateDataDisplay.classList.add('hidden');
        displayError(`Error getting certificate for ${domain}: ${data.reason}`, "certificate_info"); // Pass 'false' to not hide the single view
        return;
    }

    certificateDataDisplay.classList.remove('hidden');
    errorDisplay.classList.add('hidden');

    // Populate General Information
    infoIssuer.textContent = data.certificate_info.issuer;
    infoSubject.textContent = data.certificate_info.subject;
    infoValidFrom.textContent = data.certificate_info.not_before;
    infoValidTo.textContent = data.certificate_info.not_after;

    infoDaysRemaining.textContent = data.certificate_info.time_to_expiration;
    infoDaysRemaining.classList.add('text-orange-500', 'font-bold');
    if (!data.certificate_info.is_valid_now) {
        infoDaysRemaining.classList.add('text-red-600', 'font-bold');
        infoDaysRemaining.classList.remove('text-orange-500');
    } else {
        infoDaysRemaining.classList.remove('text-red-600', 'text-orange-500', 'font-bold');
    }

    infoSerial.textContent = data.certificate_info.serial_number;

    // Populate Domain Details
    domainCn.textContent = data.certificate_info.subject_cn;
    domainSans.replaceChildren(); // Clear previous SANs
    if (data.certificate_info.san && data.certificate_info.san.length > 0) {
        data.certificate_info.san.forEach(san => {
            const li = document.createElement('li');
            li.textContent = san;
            domainSans.appendChild(li);
        });
    } else {
        const li = document.createElement('li');
        li.textContent = 'None';
        domainSans.appendChild(li);
    }

    if (attestationLink) {
        attestationLink.href = `${response.attestation_transparency_service_url}/by-hash-pub-key/${data.certificate_info.hash_public_key}`;
    }

    if (attestationPackageHashLink) {
        attestationPackageHashLink.href = `${response.provisioning_package_url}`;
    }

    if (attestationOsHashLink) {
        attestationOsHashLink.href = `${response.os_disk_url}`;
    }

    // Populate Attestation Details
    populateAttestationDetails(
        data,
        'attestation-',
        'copy-operator-cert-button',
        'copy-operator-message',
        safetyMessage,
        domain
    );


    // Populate Technical Details
    techSignatureAlgo.textContent = data.certificate_info.signing_algorithm;
    techPubkeyAlgo.textContent = data.certificate_info.public_key_algorithm;
    techPubkeyAlgoParam.textContent = data.certificate_info.public_key_algorithm_parameters;
    techPubkeySize.textContent = data.certificate_info.public_key_size ? `${data.certificate_info.public_key_size} bits` : 'N/A';

    techPubkey.value = data.certificate_info.public_key;
    techVersion.textContent = data.certificate_info.version;

    // Populate Raw Certificate
    rawCertificate.value = data.certificate_info.raw_certificate;
    if (rawCertificateLink) {
        if (data.cert_sh_certificate_entry_info) {
            rawCertificateLink.href = `https://crt.sh/?id=${data.cert_sh_certificate_entry_info.id}`;
            rawCertificateLink.classList.remove('hidden');
        } else {
            rawCertificateLink.classList.add('hidden');
        }
    }

    lucide.createIcons();
}

let has_wildcard_certificate = false;
/**
 * Displays a table of all fetched certificates.
 * @param {object[]} data - An array of certificate data objects.
 * @param {string} domain - The domain that was looked up.
 */
function displayTable(data, domain) {
    setLoadingState(false);
    resultsSection.classList.remove('hidden');
    certificateTableSection.classList.remove('hidden');
    singleCertificateView.classList.add('hidden');
    errorDisplay.classList.add('hidden');
    lookupAnotherButton.classList.remove('hidden');
    backToTableButton.classList.add('hidden');

    domainDisplay.textContent = domain;

    if (!data) {
        displayError(`No certificates were retrieved for ${domain}.`, "lookup");
        return;
    }

    if (!data.live_certificate.certificate_info) {
        liveCertificateErrorText.textContent = `Failed to retrieve the live certificate:\n${data.live_certificate.reason}`;
        liveCertificateError.classList.remove('hidden');
        liveCertificateTableContainer.classList.add('hidden');
    } else {
        liveCertificateError.classList.add('hidden');
        liveCertificateTableContainer.classList.remove('hidden');
    }

    if (data.crt_sh_error) {
        crtShErrorText.textContent = `Failed to retrieve historical certificates from crt.sh:\n${data.crt_sh_error}`;
        crtShError.classList.remove('hidden');
        crtShEmpty.classList.add('hidden');
        certificateTableContainer.classList.add('hidden');
    } else if (data.entries.length === 0) {
        crtShError.classList.add('hidden');
        crtShEmpty.classList.remove('hidden');
        certificateTableContainer.classList.add('hidden');
    } else {
        crtShError.classList.add('hidden');
        crtShEmpty.classList.add('hidden');
        certificateTableContainer.classList.remove('hidden');
    }

    // Store data globally for later use in detailed view
    allCertificateData = data.entries;
    has_wildcard_certificate = data.has_wildcard_certificate;

    certificateTableBody.replaceChildren(); // Clear previous entries
    liveCertificateTableBody.replaceChildren();
    if (has_wildcard_certificate) {
        wildcardCertificateMessage.classList.remove('hidden');
    }

    liveCertificateView.classList.remove('hidden');
    if (data.live_certificate.certificate_info) {
        liveCertificateTableBody.appendChild(createCertificateRow(data.live_certificate, domain, data));
    }

    allCertificateData.forEach(cert => {
        certificateTableBody.appendChild(createCertificateRow(cert, domain, data));
    });
    lucide.createIcons(); // Re-create icons for the new table rows
}

const dateFormatter = new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric'
});

/**
 * Creates a Lucide icon placeholder, rendered into an SVG by lucide.createIcons().
 * @param {string} name - The Lucide icon name.
 * @param {string} className - The classes to apply to the icon.
 */
function createIcon(name, className) {
    const icon = document.createElement('i');
    icon.dataset.lucide = name;
    icon.className = className;
    return icon;
}

/**
 * Formats a date string as dd/mm/yyyy, falling back to the raw string if it can't be parsed.
 * @param {string} value - The date string to format.
 */
function formatDate(value) {
    if (!value) {
        return 'N/A';
    }
    const date = new Date(value);
    return isNaN(date) ? value : dateFormatter.format(date);
}

/**
 * Builds a clickable table row for a certificate entry.
 * Live certificates have no crt.sh entry, so their fields come from certificate_info.
 * @param {object} cert - The certificate entry.
 * @param {string} domain - The domain that was looked up.
 * @param {object} data - The full API response.
 */
function createCertificateRow(cert, domain, data) {
    const row = document.createElement('tr');
    row.className = `border-b border-gray-200 hover:bg-gray-100 cursor-pointer transition-colors duration-200`;

    let attestationStatus, attestationColor, attestationIcon;
    if (!cert.certificate_info || !cert.cluster_info) {
        [attestationStatus, attestationColor, attestationIcon] = ['Error', 'text-red-600', 'x-circle'];
    } else if (cert.reason == "" && cert.certificate_info.is_valid_now) {
        [attestationStatus, attestationColor, attestationIcon] = ['Valid', 'text-green-600', 'check-circle'];
    } else {
        [attestationStatus, attestationColor, attestationIcon] = ['Invalid', 'text-red-600', 'alert-triangle'];
    }

    const statusSpan = document.createElement('span');
    statusSpan.className = `${attestationColor} font-semibold flex items-center justify-center space-x-1`;
    const statusText = document.createElement('span');
    statusText.textContent = attestationStatus;
    statusSpan.append(createIcon(attestationIcon, 'w-4 h-4'), statusText);

    const crtShEntry = cert.cert_sh_certificate_entry_info;
    const certificateInfo = cert.certificate_info || {};

    const validFrom = formatDate(crtShEntry ? crtShEntry.not_before : certificateInfo.not_before);
    const validTo = formatDate(crtShEntry ? crtShEntry.not_after : certificateInfo.not_after);
    const commonName = (crtShEntry ? crtShEntry.name_value : certificateInfo.subject_cn) || 'N/A';
    const issuer = (crtShEntry ? crtShEntry.issuer_name : certificateInfo.issuer) || 'N/A';
    const attestationBackend = data.attestation_backend || 'N/A';

    const addCell = (className, content) => {
        const cell = document.createElement('td');
        cell.className = `py-3 px-6 ${className}`;
        if (content instanceof Node) {
            cell.append(content);
        } else {
            cell.textContent = content;
        }
        row.append(cell);
    };

    if (crtShEntry) {
        addCell('text-left whitespace-nowrap', crtShEntry.id);
    }
    addCell('text-left', `${validFrom} to ${validTo}`);
    addCell('text-left', commonName);
    addCell('text-left', issuer);
    addCell('text-center', attestationBackend);
    addCell('text-center', statusSpan);

    row.addEventListener('click', () => {
        displaySingleCertificateInfo(cert, domain, data);
    });
    return row;
}


async function copyToClipboard(element) {
    if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(element.value);
    } else {
        console.log(element)
        element.select();
        document.execCommand('copy');
    }
}
// --- Event Listeners ---

lookupForm.addEventListener('submit', async (event) => {
    event.preventDefault(); // Prevent default form submission

    const domain = domainInput.value.trim();
    if (!domain) {
        inputErrorMessage.textContent = 'Please enter a domain name.';
        inputErrorMessage.classList.remove('hidden');
        return;
    }

    // Client-side validation using pattern
    const domainPattern = new RegExp(domainInput.pattern);
    if (!domainPattern.test(domain)) {
        inputErrorMessage.textContent = 'Please enter a valid domain name (e.g., https://chat.demo.mithrilsecurity.io).';
        inputErrorMessage.classList.remove('hidden');
        return;
    }

    inputErrorMessage.classList.add('hidden'); // Hide any previous input errors
    domainDisplay.textContent = domain;
    setLoadingState(true);

    try {
        const response = await fetch('/api/get_entries?' + new URLSearchParams({
            domain: domain,
        }));

        if (!response.ok) {
            const errorData = await response.text();
            throw new Error(`HTTP error! Status: ${response.status}. \n ${errorData}`);
        }
        const data = await response.json();
        displayTable(data, domain);
    } catch (error) {
        console.error('Error fetching certificate:', error);
        displayError(`Failed to fetch certificate for ${domain}: ${error.message}`, "lookup");
    }
});

copyRawCertButton.addEventListener('click', async () => {
    await copyToClipboard(rawCertificate)
    copyMessage.classList.remove('hidden');
    setTimeout(() => {
        copyMessage.classList.add('hidden');
    }, 2000);
});

// New event listener for copying operator certificate (current)
copyOperatorCertButton.addEventListener('click', async () => {
    await copyToClipboard(attestationOperatorCert);
    copyOperatorMessage.classList.remove('hidden');
    setTimeout(() => {
        copyOperatorMessage.classList.add('hidden');
    }, 2000);
});

lookupAnotherButton.addEventListener('click', () => {
    // Reset UI to initial state
    domainInput.value = '';
    resultsSection.classList.add('hidden');
    errorDisplay.classList.add('hidden');
    certificateTableSection.classList.add('hidden');
    liveCertificateView.classList.add('hidden');
    wildcardCertificateMessage.classList.add('hidden');
    singleCertificateView.classList.add('hidden');
    inputErrorMessage.classList.add('hidden');
    domainInput.focus();
});

backToTableButton.addEventListener('click', () => {
    certificateTableSection.classList.remove('hidden');
    liveCertificateView.classList.remove('hidden');
    if (has_wildcard_certificate) {
        wildcardCertificateMessage.classList.remove('hidden');
    }
    singleCertificateView.classList.add('hidden');
    lookupAnotherButton.classList.remove('hidden'); // Ensure this is always visible
    backToTableButton.classList.add('hidden');
    errorDisplay.classList.add('hidden');
    window.scrollTo({ top: 0, behavior: 'smooth' });
});

// Initial creation of Lucide icons after the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();
});