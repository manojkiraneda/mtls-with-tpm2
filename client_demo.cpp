#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

// Function to print error messages and exit
/**
 * @brief Prints an error message and aborts the program.
 *
 * @param context A string describing the context in which the error occurred.
 */
void handleErrors(const std::string& context)
{
    std::cerr << "Error in " << context << ": ";
    ERR_print_errors_fp(stderr);
    abort();
}

/**
 * @brief Initializes OpenSSL and loads the TPM provider.
 *
 * @param libctx A pointer to an OpenSSL library context.
 */
void initialize_openssl(OSSL_LIB_CTX** libctx)
{
    *libctx = OSSL_LIB_CTX_new();
    if (!*libctx)
    {
        std::cerr << "Failed to create OpenSSL library context" << std::endl;
        handleErrors("Initializing OpenSSL");
    }

    // Load TPM provider
    if (!OSSL_PROVIDER_load(*libctx, "tpm2"))
    {
        throw std::runtime_error("Cannot load tpm2 provider");
    }
    std::cout << " >> TPM provider loaded successfully" << std::endl;

    // Load default provider
    if (!OSSL_PROVIDER_load(*libctx, "default"))
    {
        throw std::runtime_error("Cannot load default provider");
    }
    std::cout << " >> Default provider loaded successfully" << std::endl;
}

/**
 * @brief Extracts the private key from the TPM.
 *
 * @param TPM_Private_Key_Handle The handle of the TPM private key.
 * @param libctx The OpenSSL library context.
 * @return Pointer to the extracted private key, or nullptr on failure.
 */
EVP_PKEY* getPrivatekeyFromTPM(const std::string& TPM_Private_Key_Handle,
                               OSSL_LIB_CTX* libctx)
{
    const std::string TPMHandle = "handle:" + TPM_Private_Key_Handle;

    OSSL_STORE_CTX* storeCtx =
        OSSL_STORE_open_ex(TPMHandle.c_str(), libctx, "?provider=tpm2", nullptr,
                           nullptr, nullptr, nullptr, nullptr);

    if (!storeCtx)
    {
        std::cerr << "Failed to open store context\n";
        return nullptr;
    }

    EVP_PKEY* TPMpkey = nullptr;
    OSSL_STORE_INFO* info = nullptr;

    while (!OSSL_STORE_eof(storeCtx) &&
           (info = OSSL_STORE_load(storeCtx)) != nullptr)
    {
        int type = OSSL_STORE_INFO_get_type(info);

        if (type == OSSL_STORE_INFO_PKEY)
        {
            TPMpkey = OSSL_STORE_INFO_get1_PKEY(info);
            OSSL_STORE_INFO_free(info);

            if (TPMpkey)
            {
                std::cerr
                    << " >> PKEY object extracted from the TPM successfully\n";
                break;
            }
        }
        else
        {
            OSSL_STORE_INFO_free(info);
        }
    }

    OSSL_STORE_close(storeCtx);

    if (!TPMpkey)
    {
        std::cerr << "Failed to retrieve TPM key\n";
    }

    return TPMpkey;
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
 * @brief Reads a certificate from the specified NV handle.
 *
 * @param nv_handle The NV handle to read the certificate from.
 * @param libctx The OpenSSL library context.
 * @return Pointer to the extracted certificate, or nullptr on failure.
 */
X509* read_certificate_from_nv(const std::string& nv_handle,
                               OSSL_LIB_CTX* libctx)
{
    std::string handle = "handle:" + nv_handle;

    // Open the NV handle for the certificate
    OSSL_STORE_CTX* store_ctx =
        OSSL_STORE_open_ex(handle.c_str(), libctx, "?provider=tpm2", nullptr,
                           nullptr, nullptr, nullptr, nullptr);
    if (!store_ctx)
    {
        std::cerr << "Failed to open NV handle: " << handle << std::endl;
        return nullptr;
    }

    OSSL_STORE_INFO* info = nullptr;
    X509* certificate = nullptr;

    // Extract the certificate
    while ((info = OSSL_STORE_load(store_ctx)) != nullptr)
    {
        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PUBKEY)
        {
            auto pub = OSSL_STORE_INFO_get1_CERT(info);
            if (pub)
            {
                std::cerr << " >> Got the public key from certificate"
                          << std::endl;
            }
        }
        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_CERT)
        {
            certificate = OSSL_STORE_INFO_get1_CERT(info);
            if (certificate)
            {
                X509_up_ref(
                    certificate); // Increment ref count to retain certificate
                printX509Certificate(certificate);
                break;
            }
        }
        OSSL_STORE_INFO_free(info);
    }

    // Cleanup
    OSSL_STORE_close(store_ctx);

    return certificate;
}

/**
 * @brief Verifies the server's SSL certificate during the TLS handshake.
 *
 * This function retrieves the SSL certificate presented by the server 
 * during the TLS handshake and verifies its validity. It prints details 
 * about the server certificate, including the subject and issuer names.
 * After checking the certificate, it reports whether the verification 
 * was successful.
 *
 * @param ssl A pointer to the SSL structure containing the connection state. 
 *            This structure must have been created with SSL_new() and 
 *            must have a valid connection established with SSL_connect().
 *
 * @note If no certificate is received, or if the verification fails, an
 *       appropriate message will be printed to standard error.
 *
 * @warning The function assumes that the SSL context has been configured
 *          properly, including the CA certificates for verifying the server 
 *          certificate.
 */
bool verify_server_certificate(SSL *ssl) {
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL) {
        std::cerr << "No server certificate received\n";
    } else {
        std::cerr << " >> Server certificate received\n";

        // Extract and print some details of the server certificate
        char *line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        std::cerr << " >> Server certificate subject: " << line << std::endl;
        OPENSSL_free(line);

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        std::cerr << " >> Server certificate issuer: " << line << std::endl;
        OPENSSL_free(line);

        // Free the certificate when done
        X509_free(cert);
    }

    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result == X509_V_OK) {
        std::cerr << " >> Server certificate verification: SUCCESS\n";
      return true;
    } else {
        std::cerr << " >> Server certificate verification: FAILED\n";
    }
  return false;
}

/**
 * @brief Loads the public certificate from a specified file path.
 *
 * @param cert_path The path to the client certificate file.
 * @return Pointer to the loaded X509 certificate, or nullptr on failure.
 */
X509* getPublicCertFromTPM(const std::string& cert_path)
{
    X509* cert = X509_new();
    FILE* cert_file = fopen(cert_path.c_str(), "r");
    if (!cert_file || !PEM_read_X509(cert_file, &cert, nullptr, nullptr))
    {
        std::cerr << "Error loading client certificate\n";
        return nullptr;
    }

    std::cerr << " >> Client certificate loaded from path: " << cert_path
              << std::endl;
    fclose(cert_file);
    printX509Certificate(cert);
    return cert;
}

/**
 * @brief Converts binary data to a hexadecimal string for logging.
 *
 * @param data Pointer to the binary data.
 * @param len Length of the binary data.
 * @return A string representation of the binary data in hexadecimal format.
 */
std::string to_hex(const unsigned char* data, size_t len)
{
    std::cerr << "Length: " << len << std::endl;
    std::ostringstream hex_stream;
    hex_stream << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
    {
        hex_stream << std::setw(2) << static_cast<int>(data[i]);
        if (i % 16 == 15)
        {
            hex_stream
                << "\n"; // Add new line after every 16 bytes for readability
        }
        else
        {
            hex_stream << " ";
        }
    }
    return hex_stream.str();
}

/**
 * @brief Prints the SSL session details.
 *
 * @param ssl The SSL connection whose session details are to be printed.
 */
void print_ssl_session_details(SSL* ssl)
{
    SSL_SESSION* session = SSL_get_session(ssl);
    if (!session)
    {
        std::cerr << "No SSL session available." << std::endl;
        return;
    }

    std::cerr << "SSL Session Information:" << std::endl;

    // Print the negotiated cipher
    const char* cipher = SSL_get_cipher(ssl);
    std::cerr << "  Cipher: " << cipher << std::endl;

    // Print the session timeout
    long session_timeout = SSL_SESSION_get_timeout(session);
    std::cerr << "  Session Timeout: " << session_timeout << " seconds"
              << std::endl;

    // Print session start time
    long session_start_time = SSL_SESSION_get_time(session);
    std::cerr << "  Session Start Time: " << session_start_time << std::endl;
}

/**
 * @brief Creates a new SSL context for a TLS client.
 *
 * This function initializes and returns a new SSL context configured
 * for use by a TLS client. The context is created using the TLS protocol
 * method. If the context creation fails, an error message is printed
 * to standard error and the program is aborted.
 *
 * @return SSL_CTX* A pointer to the newly created SSL_CTX object,
 *                   or nullptr if an error occurred during creation.
 *
 * @exception std::runtime_error Thrown if the SSL context cannot be created.
 *
 * @note Ensure that OpenSSL is properly initialized before calling this
 *       function. It is the caller's responsibility to free the SSL_CTX
 *       object when it is no longer needed using SSL_CTX_free().
 */
SSL_CTX *create_ssl_client_context() {
    auto ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "Failed to create client SSL_CTX\n";
        handleErrors("Creating the client SSL context");
    }
    return ctx;
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
 * @brief Configures the SSL context with the client certificate, private key, and CA certificate.
 *
 * @param ctx The SSL context to configure.
 * @param nvIndex The NV index for the certificate.
 * @param tpm_handle The handle for the TPM private key.
 * @param ca_cert_path The path to the CA certificate file.
 * @param libctx The OpenSSL library context.
 */
void configure_ssl_context(SSL_CTX* ctx, const std::string& nvIndex,
                           const std::string& tpm_handle,
                           const std::string& ca_cert_path,
                           OSSL_LIB_CTX* libctx)
{
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION))
    {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        std::cerr << "Failed to set the minimum TLS protocol version\n";
        return;
    }

    // load the ca to the trust store
    auto ca_cert = read_certificate_from_nv(ca_cert_path, libctx);

    if (!ca_cert) {
        std::cerr << "Failed to load certificates." << std::endl;
    }

    const char* cert_filename = "ca2_bundle.pem";
    if (!write_certificates_to_file(ca_cert, cert_filename)) {
        std::cerr << "Failed to write certificates to file." << std::endl;
    }
  
    if (SSL_CTX_load_verify_locations(ctx, cert_filename, nullptr) != 1) {
        std::cerr << "Failed to load root CA certificate into SSL context." << std::endl;
    }

    //std::cout << "Certificates successfully written to " << cert_filename << std::endl;
    std::cerr << " >> CA certificates loaded successfully from " << ca_cert_path
              << std::endl;

    // load the leaf certificate
    if (SSL_CTX_use_cert_and_key(ctx, isFile(nvIndex) ? getPublicCertFromTPM(nvIndex):read_certificate_from_nv(nvIndex, libctx),
                                 getPrivatekeyFromTPM(tpm_handle, libctx), nullptr,
                                 1) != 1)
    {
        std::cerr << "Error loading certificate and key\n";
        return;
    }

    std::cerr << " >> Client certificate and private key loaded into SSL context successfully\n";

    
    // Enforce verification of the server certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
}

/**
 * @brief Creates a TCP connection to the specified server.
 *
 * @param hostname The hostname of the server.
 * @param port The port number of the server.
 * @return The socket file descriptor, or -1 on failure.
 */
int create_tcp_connection(const std::string& hostname, const std::string& port)
{
    struct addrinfo hints{}, *res, *p;
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;

    // Resolve the server address and port
    int status = getaddrinfo(hostname.c_str(), port.c_str(), &hints, &res);
    if (status != 0)
    {
        std::cerr << "getaddrinfo error: " << gai_strerror(status) << std::endl;
        return -1;
    }

    // Create a socket and connect
    int sockfd = -1;
    for (p = res; p != nullptr; p = p->ai_next)
    {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1)
            continue;

        // Connect to the server
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            sockfd = -1;
            continue;
        }
        break; // Successfully connected
    }

    freeaddrinfo(res); // Free the linked list

    if (sockfd == -1)
    {
        std::cerr << "Failed to connect to the server" << std::endl;
    }
    return sockfd;
}

void send_file(SSL* ssl, const std::string& file_path)
{
    // Open the file
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        std::cerr << "Failed to open file: " << file_path << std::endl;
        return;
    }

    // Get the file size
    std::streamsize file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    // Send the file size to the server
    uint32_t size_to_send = htonl(static_cast<uint32_t>(file_size)); // Convert to network byte order
    if (SSL_write(ssl, &size_to_send, sizeof(size_to_send)) <= 0)
    {
        std::cerr << "Error sending file size: " << SSL_get_error(ssl, 0) << std::endl;
        file.close();
        return;
    }

    // Send the file contents
    std::cerr << "Sending file: " << file_path << " (Size: " << file_size << " bytes)" << std::endl;
    char buffer[1024];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0)
    {
        int bytes_to_send = static_cast<int>(file.gcount());
        int bytes_written = SSL_write(ssl, buffer, bytes_to_send);
        if (bytes_written <= 0)
        {
            std::cerr << "Error sending file: " << SSL_get_error(ssl, bytes_written) << std::endl;
            break;
        }
    }
    file.close();
    std::cerr << "File sent successfully: " << file_path << std::endl;
}

void receive_file(SSL* ssl, const std::string& output_path)
{
    std::ofstream out_file(output_path, std::ios::binary);
    if (!out_file.is_open())
    {
        std::cerr << "Failed to open file for writing: " << output_path << std::endl;
        return;
    }

    // Step 1: Receive the file size
    uint32_t file_size_net;
    if (SSL_read(ssl, &file_size_net, sizeof(file_size_net)) <= 0)
    {
        std::cerr << "Failed to read file size." << std::endl;
        return;
    }
    uint32_t file_size = ntohl(file_size_net); // Convert from network byte order
    std::cerr << "Receiving file of size: " << file_size << " bytes." << std::endl;

    // Step 2: Receive the file contents
    char buffer[1024];
    std::streamsize bytes_received = 0;
    while (bytes_received < file_size)
    {
        int bytes_to_read = std::min(static_cast<int>(sizeof(buffer)), static_cast<int>(file_size - bytes_received));
        int bytes_read = SSL_read(ssl, buffer, bytes_to_read);
        if (bytes_read <= 0)
        {
            std::cerr << "Error reading file data." << std::endl;
            break;
        }
        out_file.write(buffer, bytes_read);
        bytes_received += bytes_read;
    }
    out_file.close();
    if (bytes_received == file_size)
    {
        std::cerr << "File received successfully: " << output_path << std::endl;
    }
    else
    {
        std::cerr << "File transfer incomplete." << std::endl;
    }
}

// Client-side logic to coordinate bidirectional transfer
void handle_server(SSL* ssl)
{
    // Step 1: Receive a file from the server
    receive_file(ssl, "received_from_server.txt");

    // Step 2: Send a file to the server
    send_file(ssl, "client_to_server.txt");

    // Step 3: Receive acknowledgment
    char ack_buffer[1024];
    int ack_bytes = SSL_read(ssl, ack_buffer, sizeof(ack_buffer) - 1);
    if (ack_bytes > 0)
    {
        ack_buffer[ack_bytes] = '\0'; // Null-terminate the acknowledgment
        std::cerr << "Acknowledgment from server: " << ack_buffer << std::endl;
    }
}


/**
 * @brief Main function to establish a secure connection and communicate with
 * the server.
 *
 * @param argc The number of command-line arguments.
 * @param argv The command-line arguments.
 * @return Exit status.
 */
int main(int argc, char* argv[])
{
    if (argc != 5)
    {
        std::cerr << "Usage: " << argv[0]
                  << " <tpmHandle> <nvIndex> <caCertPath> <hostname:port>\n";
        return 1;
    }

    const std::string nvIndex = argv[2];
    const std::string tpmHandle = argv[1];
    const std::string caCertPath = argv[3];
    const std::string hostPort = argv[4];

    size_t colonPos = hostPort.find(':');
    if (colonPos == std::string::npos)
    {
        std::cerr << "Invalid hostname:port format\n";
        return 1;
    }

    const std::string hostname = hostPort.substr(0, colonPos);
    const std::string port = hostPort.substr(colonPos + 1);

    OSSL_LIB_CTX* libctx = nullptr;
    initialize_openssl(&libctx);

    SSL_CTX* ctx = create_ssl_client_context();
    configure_ssl_context(ctx, nvIndex, tpmHandle, caCertPath, libctx);

    int sockfd = create_tcp_connection(hostname, port);
    if (sockfd < 0)
    {
        std::cerr << "Failed to create TCP connection\n";
        SSL_CTX_free(ctx);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    // Initiate SSL handshake
    if (SSL_connect(ssl) != 1)
    {
        std::cerr << "Error establishing SSL connection\n";
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }

    std::cerr << " >> SSL connection established with " << hostname << ":"
              << port << std::endl;

    // Verify server's certificate
    if (!verify_server_certificate(ssl))
    {
        std::cerr
            << "Server certificate verification failed. Closing connection.\n";
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }

    print_ssl_session_details(ssl);

    // Optionally, receive a file from the server
    handle_server(ssl);

    // Cleanup
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    OSSL_LIB_CTX_free(libctx);

    return 0;
}
