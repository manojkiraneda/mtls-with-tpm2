#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_tcti_device.h>
#include <unistd.h>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <vector>
#include <format>

/**
 * @brief Initialize OpenSSL with TPM and default providers.
 *
 * This function initializes the OpenSSL library context and loads the TPM and
 * default providers. It ensures that both providers are available for use
 * within the specified OpenSSL context.
 *
 * @param libctx A pointer to an OpenSSL library context pointer
 * (OSSL_LIB_CTX**), which will be initialized within the function.
 *
 * @throws std::runtime_error if OpenSSL context creation fails or providers
 * cannot be loaded.
 */
void initialize_openssl(OSSL_LIB_CTX** libctx)
{
    // Create a new OpenSSL library context
    *libctx = OSSL_LIB_CTX_new();

    // Check if library context creation succeeded
    if (!*libctx)
    {
        std::cerr << "Failed to create OpenSSL library context" << std::endl;
        throw std::runtime_error("Error: Initializing OpenSSL context failed.");
    }

    // Load the TPM2 provider into the OpenSSL context
    if (!OSSL_PROVIDER_load(*libctx, "tpm2"))
    {
        throw std::runtime_error("Error: Cannot load TPM2 provider.");
    }
    std::cout << " >> TPM provider loaded successfully." << std::endl;

    // Load the default provider into the OpenSSL context
    if (!OSSL_PROVIDER_load(*libctx, "default"))
    {
        throw std::runtime_error("Error: Cannot load default provider.");
    }
    std::cout << " >> Default provider loaded successfully." << std::endl;
}

/**
 * @brief Handle OpenSSL errors.
 *
 * This helper function retrieves the OpenSSL error queue and prints detailed
 * error messages. It is used for debugging and error tracing purposes.
 *
 * @param msg The message to log along with the OpenSSL error output.
 */
void handleErrors(const std::string& msg)
{
    unsigned long errCode;
    std::cerr << msg << std::endl;

    // Print each error in the OpenSSL error queue
    while ((errCode = ERR_get_error()))
    {
        char* err = ERR_error_string(errCode, nullptr);
        std::cerr << "OpenSSL error: " << err << std::endl;
    }

    throw std::runtime_error("OpenSSL error occurred.");
}

/**
 * @brief Extracts and prints the public key from an X509 certificate.
 *
 * This function retrieves the public key from a given X509 certificate and
 * prints it in PEM format. If the certificate or public key is invalid,
 * appropriate error messages are shown.
 *
 * @param cert A pointer to the X509 certificate from which the public key is
 * extracted.
 */
void printPublicKeyFromCertificate(X509* cert)
{
    // Check if the provided certificate is valid
    if (!cert)
    {
        std::cerr
            << "Error: No certificate available for public key extraction.\n";
        return;
    }

    // Extract the public key from the certificate
    EVP_PKEY* publicKey = X509_get_pubkey(cert);
    if (!publicKey)
    {
        std::cerr << "Error: Failed to extract public key from certificate.\n";
        return;
    }

    // Print the public key in PEM format
    std::cout << " >> Public Key:\n";
    if (PEM_write_PUBKEY(stdout, publicKey) != 1)
    {
        std::cerr << "Error: Failed to write public key in PEM format.\n";
    }

    // Clean up the public key object
    EVP_PKEY_free(publicKey);
}

/**
 * @brief Prints the details of an X509 certificate to the standard output.
 *
 * This function prints the details of a given X509 certificate in a single-line
 * format. If the certificate is null, an error message will be printed.
 *
 * @param cert Pointer to the X509 certificate to print.
 */
void printX509Certificate(X509* cert)
{
    // Check if the provided certificate is valid
    if (!cert)
    {
        std::cerr << "Error: No certificate to print.\n";
        return;
    }

    // Print the certificate to the standard output
    std::cout << " >> Certificate Details:\n";

    // Use X509_print_ex_fp to print the certificate in one-line format
    if (X509_print_ex_fp(stdout, cert, 0, XN_FLAG_ONELINE) <= 0)
    {
        std::cerr << "Error: Failed to print certificate.\n";
        return;
    }
    printPublicKeyFromCertificate(cert);
    // Print a newline for better formatting
    std::cout << "\n";
}

/**
 * @brief Retrieve a private key from a TPM (Trusted Platform Module) using its
 * handle.
 *
 * This function opens a TPM handle and loads the associated private key using
 * OpenSSL's `OSSL_STORE` API. The function relies on the TPM provider to be
 * loaded in the provided OpenSSL context.
 *
 * @param tpm_handle The TPM handle as a string (usually a hexadecimal
 * representation).
 * @param libctx A pointer to the OpenSSL library context (OSSL_LIB_CTX) where
 * the TPM provider is loaded.
 *
 * @return EVP_PKEY* Pointer to the private key retrieved from the TPM. Returns
 * `nullptr` if key retrieval fails.
 */
EVP_PKEY* get_private_key_from_tpm(const std::string& tpm_handle,
                                   OSSL_LIB_CTX* libctx)
{
    // Construct the handle string with the required format
    auto handle = "handle:" + tpm_handle;

    // Open the TPM handle using OSSL_STORE API
    OSSL_STORE_CTX* store_ctx =
        OSSL_STORE_open_ex(handle.c_str(), libctx, "?provider=tpm2", nullptr,
                           nullptr, nullptr, nullptr, nullptr);

    // Check if the store context was successfully opened
    if (!store_ctx)
    {
        std::cerr << "Error: Failed to open TPM handle: " << handle
                  << std::endl;
        return nullptr;
    }

    OSSL_STORE_INFO* info = nullptr;
    EVP_PKEY* privateKey = nullptr;

    // Load the keys from the store and search for the private key
    while ((info = OSSL_STORE_load(store_ctx)) != nullptr)
    {
        int type = OSSL_STORE_INFO_get_type(info);

        // Check if the loaded object is a private key
        if (type == OSSL_STORE_INFO_PKEY)
        {
            privateKey = OSSL_STORE_INFO_get1_PKEY(info);
            if (privateKey)
            {
                std::cout << " >> Private Key Retrieved from TPM Successfully"
                          << std::endl;
                break;
            }
        }
        // Free the loaded store info object
        OSSL_STORE_INFO_free(info);
    }

    // If no key was found, print an error message
    if (!privateKey)
    {
        std::cerr << "Error: No private key found in the TPM handle: " << handle
                  << std::endl;
    }

    // close the store context
    OSSL_STORE_close(store_ctx);

    return privateKey;
}

/**
 * @brief Check if the provided string represents a file path.
 *
 * This function checks if a given path is a file by trying to open it.
 *
 * @param path The path to check.
 * @return true if the path is a valid file, false otherwise.
 */
bool isFile(const std::string& path)
{
    std::ifstream file(path);
    return file.good();
}

/**
 * @brief Reads an X509 certificate from a non-volatile (NV) memory handle in
 * TPM.
 *
 * This function opens an NV handle associated with a TPM and extracts an X509
 * certificate. It uses the TPM2 provider to access the certificate stored in NV
 * memory.
 *
 * @param nv_handle The NV memory handle as a string, representing the location
 * of the certificate.
 * @param libctx A pointer to the OpenSSL library context (OSSL_LIB_CTX) where
 * the TPM provider is loaded.
 *
 * @return X509* A pointer to the X509 certificate. Returns `nullptr` if no
 * certificate is found or an error occurs.
 */
X509* read_certificate_from_nv(const std::string& nv_handle,
                               OSSL_LIB_CTX* libctx)
{
    // Construct the handle string in the correct format
    std::string handle = "handle:" + nv_handle;

    std::cerr << handle << std::endl;
    // Open the NV handle using OSSL_STORE API
    OSSL_STORE_CTX* store_ctx =
        OSSL_STORE_open_ex(handle.c_str(), libctx, "?provider=tpm2", nullptr,
                           nullptr, nullptr, nullptr, nullptr);

    // Check if the NV handle was successfully opened
    if (!store_ctx)
    {
        std::cerr << "Error: Failed to open NV handle: " << handle << std::endl;
        return nullptr;
    }

    OSSL_STORE_INFO* info = nullptr;
    X509* certificate = nullptr;

    // Loop through the objects loaded from the NV store
    while ((info = OSSL_STORE_load(store_ctx)) != nullptr)
    {
        int type = OSSL_STORE_INFO_get_type(info);

        // If a certificate is found, extract and print it
        if (type == OSSL_STORE_INFO_CERT)
        {
            certificate = OSSL_STORE_INFO_get1_CERT(
                info); // Extract a copy of the certificate
            if (certificate)
            {
                X509_up_ref(certificate);
                std::cerr
                    << " >> Certificate extracted successfully from NV handle."
                    << nv_handle << std::endl;
                printX509Certificate(certificate);
                break;
            }
        }

        // Free the current store info object before moving to the next
        OSSL_STORE_INFO_free(info);
    }

    // Cleanup: close the store context
    OSSL_STORE_close(store_ctx);

    // Return the certificate (if found) or nullptr (if not found)
    return certificate;
}

/**
 * @brief Creates an SSL context for a TLS server.
 *
 * This function initializes and returns an SSL context (`SSL_CTX`) for a server
 * using the TLS protocol. The context is configured using the
 * `TLS_server_method` to allow support for multiple TLS versions.
 *
 * @return SSL_CTX* Pointer to the newly created SSL context. Returns `nullptr`
 * if context creation fails.
 * @throws std::runtime_error if SSL context creation fails.
 */
SSL_CTX* create_ssl_server_context()
{
    // Create a new SSL context using the TLS server method
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());

    // Check if the SSL context was successfully created
    if (!ctx)
    {
        std::cerr << "Error: Failed to create server SSL_CTX\n";
        handleErrors("Error: Creating the server SSL context");
        throw std::runtime_error("Failed to create SSL server context.");
    }

    return ctx;
}

/**
 * @brief Loads a public X.509 certificate from the specified file path.
 *
 * This function reads an X.509 certificate from a PEM file and returns
 * an `X509` structure. It also prints the certificate details to the console.
 *
 * @param cert_path The file path to the PEM-formatted certificate.
 * @return X509* A pointer to the X509 certificate, or nullptr if loading fails.
 */
X509* getPublicCertFromFile(std::string_view cert_path)
{
    // Open the certificate file using smart pointer with custom deleter
    auto cert_file_deleter = [](std::FILE* f) {
        if (f)
            std::fclose(f);
    };
    std::unique_ptr<std::FILE, decltype(cert_file_deleter)> cert_file(
        std::fopen(cert_path.data(), "r"), cert_file_deleter);

    if (!cert_file)
    {
        std::cerr << "Error: Could not open certificate file: " << cert_path
                  << std::endl;
        return nullptr;
    }

    // Read the certificate from the file
    X509* cert = PEM_read_X509(cert_file.get(), nullptr, nullptr, nullptr);
    if (!cert)
    {
        std::cerr << "Error: Failed to load certificate from file: "
                  << cert_path << std::endl;
        return nullptr;
    }

    std::cerr << " >> Server certificate loaded from path: " << cert_path
              << std::endl;

    // Print the certificate details (assuming printX509Certificate is defined)
    printX509Certificate(cert);

    return cert;
}

/**
 * @brief Callback function for verifying X.509 certificates.
 *
 * This function is called during the verification process of a certificate.
 * It logs an error message if the verification fails.
 *
 * @param preverify_ok A flag indicating the result of the previous
 * verification.
 * @param x509_ctx Pointer to the X509_STORE_CTX structure containing context
 * for the verification.
 * @return int Returns the verification status; 1 for success, 0 for failure.
 */
int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
  if (!preverify_ok) {
    int err = X509_STORE_CTX_get_error(x509_ctx);
    std::cerr << "Certificate verification error: "
              << X509_verify_cert_error_string(err) << std::endl;
  }
  return preverify_ok;
}

/**
 * @brief Prints details of the peer's X.509 certificate.
 *
 * This function retrieves the peer's certificate from the SSL connection
 * and prints the subject, issuer, validity period, and verification result.
 *
 * @param ssl Pointer to the SSL structure representing the connection.
 */
void print_certificate_details(SSL* ssl)
{
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert == nullptr)
    {
        std::cerr << "No certificate provided by the peer." << std::endl;
        return;
    }

    // Print out certificate details
    std::cerr << "Peer Certificate Information:" << std::endl;

    // Retrieve and print the subject name
    char* subject = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
    if (subject)
    {
        std::cerr << "  Subject: " << subject << std::endl;
        OPENSSL_free(subject);
    }

    // Retrieve and print the issuer name
    char* issuer = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
    if (issuer)
    {
        std::cerr << "  Issuer: " << issuer << std::endl;
        OPENSSL_free(issuer);
    }

    // Print the validity period
    ASN1_TIME* not_before = X509_getm_notBefore(cert);
    ASN1_TIME* not_after = X509_getm_notAfter(cert);

    // Create a BIO for memory output
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        std::cerr << "Failed to create BIO." << std::endl;
        X509_free(cert);
        return;
    }

    std::cerr << "  Validity Period:" << std::endl;
    BIO_printf(bio, "    Not Before: ");
    ASN1_TIME_print(bio, not_before);
    BIO_printf(bio, "\n    Not After: ");
    ASN1_TIME_print(bio, not_after);
    BIO_printf(bio, "\n");

    // Get the memory buffer from BIO and print it
    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::cerr << std::string(bptr->data, bptr->length) << std::endl;

    // Free the BIO and the certificate
    BIO_free(bio);
    X509_free(cert);

    // Check and print the verification result
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result == X509_V_OK)
    {
        std::cerr << " >> Client certificate verification: SUCCESS\n";
    }
    else
    {
        std::cerr << " >> Client certificate verification: FAILED (Error code: "
                  << verify_result << ")\n";
    }
}

/**
 * @brief Convert binary data to a hexadecimal string for logging.
 *
 * This function takes a pointer to binary data and its length,
 * converting it into a formatted hexadecimal string. Each byte is
 * represented by two hexadecimal digits, and new lines are added
 * every 16 bytes for better readability.
 *
 * @param data Pointer to the binary data to be converted.
 * @param len The length of the binary data.
 * @return std::string The hexadecimal representation of the binary data.
 * @throws std::invalid_argument if the data pointer is null.
 */
std::string to_hex(const unsigned char* data, size_t len)
{
    if (!data)
    {
        throw std::invalid_argument("Data pointer cannot be null");
    }

    std::string hex_result;
    hex_result.reserve(
        len *
        3); // Reserve space to improve performance (2 chars + space per byte)

    constexpr size_t bytes_per_line =
        16; // Number of bytes per line for formatting
    for (size_t i = 0; i < len; ++i)
    {
        hex_result += std::format("{:02x} ",
                                  data[i]); // Append each byte formatted as hex

        // Add a newline after every 16 bytes for readability
        if ((i + 1) % bytes_per_line == 0)
        {
            hex_result += "\n";
        }
    }

    return hex_result;
}

/**
 * @brief Callback function to handle SSL handshake messages.
 *
 * This function is invoked during the SSL handshake process to log
 * information about sent and received messages, including their types
 * and content. It differentiates between various handshake types and
 * handles their specific logging.
 *
 * @param write_p Indicates whether the message is sent (1) or received (0).
 * @param version SSL version of the message.
 * @param content_type The type of content being processed.
 * @param buf Pointer to the message buffer.
 * @param len Length of the message buffer.
 * @param ssl Pointer to the SSL object.
 * @param arg Additional arguments, if any.
 */
void handshake_callback(int write_p, int version, int content_type,
                        const void* buf, size_t len, SSL* ssl, void* arg)
{
    std::cerr << (write_p ? "Sent: " : "Received: ");

    switch (content_type)
    {
        case SSL3_RT_CHANGE_CIPHER_SPEC:
            std::cerr << "Change Cipher Spec" << std::endl;
            break;
        case SSL3_RT_ALERT:
            std::cerr << "Alert message" << std::endl;
            break;
        case SSL3_RT_HANDSHAKE:
            std::cerr << "Handshake message" << std::endl;

            if (len > 0)
            {
                const auto* content = static_cast<const unsigned char*>(buf);
                unsigned char handshake_type = content[0];

                std::string handshake_message;

                switch (handshake_type)
                {
                    case SSL3_MT_HELLO_REQUEST:
                        handshake_message = "Hello Request";
                        break;
                    case SSL3_MT_CLIENT_HELLO:
                        handshake_message = "Client Hello";
                        break;
                    case SSL3_MT_SERVER_HELLO:
                        handshake_message = "Server Hello";
                        break;
                    case SSL3_MT_NEWSESSION_TICKET:
                        handshake_message = "New Session Ticket";
                        break;
                    case SSL3_MT_END_OF_EARLY_DATA:
                        handshake_message = "End of Early Data";
                        break;
                    case SSL3_MT_ENCRYPTED_EXTENSIONS:
                        handshake_message = "Encrypted Extensions";
                        break;
                    case SSL3_MT_CERTIFICATE:
                        handshake_message = "Certificate";
                        break;
                    case SSL3_MT_SERVER_KEY_EXCHANGE:
                        handshake_message = "Server Key Exchange";
                        break;
                    case SSL3_MT_CERTIFICATE_REQUEST:
                        handshake_message = "Certificate Request";
                        break;
                    case SSL3_MT_SERVER_DONE:
                        handshake_message = "Server Done";
                        break;
                    case SSL3_MT_CERTIFICATE_VERIFY:
                        handshake_message = "Certificate Verify";
                        break;
                    case SSL3_MT_CLIENT_KEY_EXCHANGE:
                        handshake_message = "Client Key Exchange";
                        break;
                    case SSL3_MT_FINISHED:
                        handshake_message = "Finished";
                        break;
                    case SSL3_MT_CERTIFICATE_URL:
                        handshake_message = "Certificate URL";
                        break;
                    case SSL3_MT_CERTIFICATE_STATUS:
                        handshake_message = "Certificate Status";
                        break;
                    case SSL3_MT_SUPPLEMENTAL_DATA:
                        handshake_message = "Supplemental Data";
                        break;
                    case SSL3_MT_KEY_UPDATE:
                        handshake_message = "Key Update";
                        break;
                    default:
                        handshake_message = std::format(
                            "Unknown ({})", static_cast<int>(handshake_type));
                        break;
                }

                std::cerr << "  Handshake Type: " << handshake_message
                          << std::endl;
            }
            break;
        case SSL3_RT_APPLICATION_DATA:
            std::cerr << "Application data" << std::endl;
            break;
        default:
            std::cerr << "Unknown content type: " << content_type << std::endl;
            break;
    }

    if (len > 0)
    {
        const auto* content = static_cast<const unsigned char*>(buf);
        std::cerr << "Message content (hex):" << std::endl
                  << to_hex(content, len) << std::endl;
    }
    else
    {
        std::cerr << "No message content." << std::endl;
    }
}
// Function to concatenate root into a single file
bool write_certificates_to_file(X509* root_cert, const char* filename) {
    if (!root_cert || !filename) {
        std::cerr << "Invalid certificates or filename." << std::endl;
        return false;
    }

    // Open the file for writing (will create or overwrite the file)
    FILE* file = fopen(filename, "w");
    if (!file) {
        std::cerr << "Error opening file for writing: " << filename << std::endl;
        return false;
    }

    // Write the root CA certificate to the file
    if (PEM_write_X509(file, root_cert) != 1) {
        std::cerr << "Error writing root CA certificate to file." << std::endl;
        fclose(file);
        return false;
    }

    // Close the file
    fclose(file);
    return true;
}


/**
 * @brief Configures the SSL context with specified parameters.
 *
 * This function sets up the SSL context with minimum protocol version,
 * loads CA certificates, retrieves public certificates and private keys,
 * and configures verification options.
 *
 * @param ctx Pointer to the SSL_CTX to configure.
 * @param nvIndex The NV index or filepath for the public certificate.
 * @param tpm_handle The TPM handle for retrieving the private key.
 * @param ca_cert_path Path to the CA certificates.
 * @param libctx Pointer to the OpenSSL library context.
 *
 * @throws std::runtime_error If any step in the configuration fails.
 */
void configure_ssl_context(SSL_CTX* ctx, const std::string& nvIndex,
                           const std::string& tpm_handle,
                           const std::string& ca_handle,
                           OSSL_LIB_CTX* libctx)
{
    // Set the minimum TLS protocol version to TLS 1.2.
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION))
    {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error(
            "Failed to set the minimum TLS protocol version");
    }

    // Set SSL options to improve security and compatibility.
    auto opts = SSL_OP_IGNORE_UNEXPECTED_EOF | SSL_OP_NO_RENEGOTIATION |
                SSL_OP_CIPHER_SERVER_PREFERENCE;

    SSL_CTX_set_options(ctx, opts);

    // Retrieve the public certificate based on the nvIndex type (file or NV).
    auto cert = read_certificate_from_nv(nvIndex, libctx);
    // Retrieve the private key from TPM.
    auto keys = get_private_key_from_tpm(tpm_handle, libctx);

    // Load the certificate and private key into the SSL context.
    if (SSL_CTX_use_cert_and_key(ctx, cert, keys, nullptr, 1) != 1)
    {
        throw std::runtime_error("Error loading TLS certificate and key");
    }

    std::cerr
        << " >> Loaded the TLS certificate and private key into the SSL context\n";

    // Check if the private key matches the certificate.
    if (SSL_CTX_check_private_key(ctx) != 1)
    {
        throw std::runtime_error("Private key does not match the certificate");
    }
    std::cerr << " >> Private key matches the certificate\n";


   auto root_ca_cert = read_certificate_from_nv(ca_handle, libctx);
   
   if (!root_ca_cert) {
        std::cerr << "Failed to load certificates." << std::endl;
    }

    const char* cert_filename = "ca_bundle.pem";
    if (!write_certificates_to_file(root_ca_cert, cert_filename)) {
        std::cerr << "Failed to write certificates to file." << std::endl;
    }

    std::cout << "Certificates successfully written to " << cert_filename << std::endl;

    if (SSL_CTX_load_verify_locations(ctx, cert_filename, nullptr) != 1) {
        std::cerr << "Failed to load root CA certificate into SSL context." << std::endl;
    }

    std::cerr << " >> CA certificates loaded successfully from " << ca_handle
              << std::endl;

    
    // Configure optional client certificate verification.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       verify_callback);

    // Set the message callback to print handshake messages.
    SSL_CTX_set_msg_callback(ctx, handshake_callback);
}

/**
 * @brief Prints details of the SSL session.
 *
 * This function retrieves and prints various details about the current
 * SSL session, including the negotiated cipher, session ID, master key,
 * session timeout, and session start time.
 *
 * @param ssl Pointer to the SSL object associated with the session.
 */
void print_ssl_session_details(SSL* ssl)
{
    if (!ssl)
    {
        std::cerr << "Invalid SSL pointer." << std::endl;
        return;
    }

    SSL_SESSION* session = SSL_get_session(ssl);
    if (!session)
    {
        std::cerr << "No SSL session available." << std::endl;
        return;
    }

    std::cerr << "SSL Session Information:" << std::endl;

    // Print the negotiated cipher
    if (const char* cipher = SSL_get_cipher(ssl))
    {
        std::cerr << "  Cipher: " << cipher << std::endl;
    }
    else
    {
        std::cerr << "  Cipher: Unknown" << std::endl;
    }

    // Print the session ID
    unsigned int session_id_length;
    const unsigned char* session_id =
        SSL_SESSION_get_id(session, &session_id_length);
    if (session_id && session_id_length > 0)
    {
        std::cerr << "  Session ID: " << to_hex(session_id, session_id_length)
                  << std::endl;
    }
    else
    {
        std::cerr << "  Session ID: Not available" << std::endl;
    }

    // Print the session master key
    unsigned char master_key[SSL_MAX_MASTER_KEY_LENGTH];
    size_t master_key_length =
        SSL_SESSION_get_master_key(session, master_key, sizeof(master_key));
    if (master_key_length > 0)
    {
        std::cerr << "  Master Key: " << to_hex(master_key, master_key_length)
                  << std::endl;
    }
    else
    {
        std::cerr << "  Master Key: Not available" << std::endl;
    }

    // Print session timeout
    long session_timeout = SSL_SESSION_get_timeout(session);
    std::cerr << "  Session Timeout: " << session_timeout << " seconds"
              << std::endl;

    // Print session start time
    long session_start_time = SSL_SESSION_get_time(session);
    std::cerr << "  Session Start Time: " << session_start_time << std::endl;
}

/**
 * @brief Sends the contents of a file to the connected client over SSL.
 *
 * This function reads a specified file in binary mode and sends its contents
 * to the client connected via the given SSL object. It handles file reading
 * errors and SSL write errors.
 *
 * @param ssl Pointer to the SSL object used for the connection.
 * @param file_path Path to the file to be sent.
 */
void send_file_to_client(SSL* ssl, const std::string& file_path)
{
    if (!ssl)
    {
        std::cerr << "Invalid SSL pointer." << std::endl;
        return;
    }

    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open())
    {
        std::cerr << "Failed to open file: " << file_path << std::endl;
        return;
    }

    // Read the file contents into a buffer and send it to the client
    char buffer[1024];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0)
    {
        std::streamsize bytes_read = file.gcount();
        int bytes_written =
            SSL_write(ssl, buffer, static_cast<int>(bytes_read));
        if (bytes_written <= 0)
        {
            std::cerr << "Failed to send file contents to client: "
                      << SSL_get_error(ssl, bytes_written) << std::endl;
            break;
        }
    }

    if (file.eof())
    {
        std::cerr << "File sent to client successfully." << std::endl;
    }
    else
    {
        std::cerr << "Error occurred while reading the file." << std::endl;
    }
}

int main(int argc, char** argv)
{
    if (argc != 6)
    {
        std::cerr << "Usage: " << argv[0]
                  << " <TPM_Private_Key_Handle> <CertPath / TPM_NV_Cert_Index> "
                     "<CA_Certificate_File/CA index> <Port> <File_To_Send> "
                  << std::endl;
        return 1;
    }

    std::string tpmHandle = argv[1];
    std::string nvHandle = argv[2];
    std::string caCertPath = argv[3];
    int port = std::stoi(argv[4]);
    std::string fileToSend = argv[5];
  
    OSSL_LIB_CTX *libctx = NULL;

    try
    {
        initialize_openssl(&libctx);

        // Create and configure SSL context
        SSL_CTX* ctx = create_ssl_server_context();
        configure_ssl_context(ctx, nvHandle, tpmHandle, caCertPath, libctx);

        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0)
        {
            handleErrors("Failed to create socket");
        }
        std::cerr << " >> Socket created successfully" << std::endl;

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0)
        {
            std::cerr << "Failed to bind to port " << port << std::endl;
            handleErrors("Failed to bind to port");
        }
        std::cerr << " >> Bound to port " << port << " successfully\n";

        if (listen(server_fd, 1) < 0)
        {
            std::cerr << "Failed to listen on port " << port << std::endl;
            handleErrors("Failed to listen on port");
        }
        std::cerr << " >> Server listening on port " << port << "..."
                  << std::endl;

        while (true)
        {
            int client_fd = accept(server_fd, nullptr, nullptr);
            if (client_fd < 0)
            {
                std::cerr << "Failed to accept client connection" << std::endl;
                handleErrors("main");
            }
            std::cerr << " >> Client connection accepted" << std::endl;

            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client_fd);

            if (SSL_accept(ssl) <= 0)
            {
                std::cerr << "SSL handshake failed" << std::endl;
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                close(client_fd);
                continue;
            }

            std::cerr << " >> SSL handshake succeeded" << std::endl;

            const char* version = SSL_get_version(ssl);
            printf(">> Negotiated TLS version: %s\n", version);

            print_certificate_details(ssl);

            /* Print SSL session details */
            print_ssl_session_details(ssl);

            /* Send file to the client */
            send_file_to_client(ssl, fileToSend);

            SSL_free(ssl);
            close(client_fd);
        }

        close(server_fd);
        SSL_CTX_free(ctx);
        OSSL_LIB_CTX_free(libctx);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
