// Adapted from mmozeiko's sample: https://gist.github.com/mmozeiko/c0dfcc8fec527a90a02145d2cc0bfb6d
// Changes done to clean up compiler errors in C++ (mainly casts), print to stdout rather than a 
// file, use wide-string variant of Win32 functions and remove functions that issue security warnings.

#define WIN32_LEAN_AND_MEAN
#include <string>
#include <iostream>
#include <vector>
#include <format>
#include <winsock2.h>
#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include <shlwapi.h>
#include <assert.h>
#include <stdio.h>

#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "secur32.lib")
#pragma comment (lib, "shlwapi.lib")

constexpr uint64_t TLS_MAX_PACKET_SIZE = 16384 + 512; // payload + extra over head for header/mac/padding (probably an overestimate)

struct tls_socket 
{
    SOCKET sock;
    CredHandle handle;
    CtxtHandle context;
    SecPkgContext_StreamSizes sizes;
    int received;    // byte count in incoming buffer (ciphertext)
    int used;        // byte count used from incoming buffer to decrypt current packet
    int available;   // byte count available for decrypted bytes
    char* decrypted; // points to incoming buffer where data is decrypted inplace
    char incoming[TLS_MAX_PACKET_SIZE];
};

int socket_connect(tls_socket& s, const std::wstring& hostname, unsigned short port)
{
    // initialize windows sockets
    WSADATA wsadata;
    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
    {
        return -1;
    }

    // create TCP IPv4 socket
    s.sock = socket(AF_INET, SOCK_STREAM, 0);
    if (s.sock == INVALID_SOCKET)
    {
        WSACleanup();
        return -1;
    }

    std::wstring sport = std::to_wstring(port);

    const bool success = WSAConnectByNameW(
        s.sock,
        const_cast<LPWSTR>(hostname.data()),
        sport.data(),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    );

    // connect to server
    if (!success)
    {
        closesocket(s.sock);
        WSACleanup();
        return -1;
    }

    return 0;
}

// returns 0 on success or negative value on error
int tls_connect(tls_socket& s, const std::wstring& hostname)
{
    // initialize schannel
    {
        SCHANNEL_CRED cred =
        {
            .dwVersion = SCHANNEL_CRED_VERSION,
            .grbitEnabledProtocols = SP_PROT_TLS1_2,  // allow only TLS v1.2
            .dwFlags = SCH_USE_STRONG_CRYPTO          // use only strong crypto alogorithms
                     | SCH_CRED_AUTO_CRED_VALIDATION  // automatically validate server certificate
                     | SCH_CRED_NO_DEFAULT_CREDS,     // no client certificate authentication
        };

        if (AcquireCredentialsHandleW(nullptr, (LPWSTR)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, nullptr, &cred, nullptr, nullptr, &s.handle, nullptr) != SEC_E_OK)
        {
            closesocket(s.sock);
            WSACleanup();
            return -1;
        }
    }

    s.received = s.used = s.available = 0;
    s.decrypted = nullptr;

    // perform tls handshake
    // 1) call InitializeSecurityContext to create/update schannel context
    // 2) when it returns SEC_E_OK - tls handshake completed
    // 3) when it returns SEC_I_INCOMPLETE_CREDENTIALS - server requests client certificate (not supported here)
    // 4) when it returns SEC_I_CONTINUE_NEEDED - send token to server and read data
    // 5) when it returns SEC_E_INCOMPLETE_MESSAGE - need to read more data from server
    // 6) otherwise read data from server and go to step 1

    CtxtHandle* context = nullptr;
    int result = 0;
    for (;;)
    {
        SecBuffer inbuffers[2] = { 0 };
        inbuffers[0].BufferType = SECBUFFER_TOKEN;
        inbuffers[0].pvBuffer = s.incoming;
        inbuffers[0].cbBuffer = s.received;
        inbuffers[1].BufferType = SECBUFFER_EMPTY;

        SecBuffer outbuffers[1] = { 0 };
        outbuffers[0].BufferType = SECBUFFER_TOKEN;

        SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
        SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };

        DWORD flags = ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
        SECURITY_STATUS sec = InitializeSecurityContextW(
            &s.handle,
            context,
            context ? nullptr : const_cast<SEC_WCHAR*>(hostname.data()),
            flags,
            0,
            0,
            context ? &indesc : nullptr,
            0,
            context ? nullptr : &s.context,
            &outdesc,
            &flags,
            nullptr
        );

        // after first call to InitializeSecurityContext context is available and should be reused for next calls
        context = &s.context;

        if (inbuffers[1].BufferType == SECBUFFER_EXTRA)
        {
            RtlMoveMemory(s.incoming, s.incoming + (s.received - inbuffers[1].cbBuffer), inbuffers[1].cbBuffer);
            s.received = inbuffers[1].cbBuffer;
        }
        else
        {
            s.received = 0;
        }

        if (sec == SEC_E_OK)
        {
            // tls handshake completed
            break;
        }
        else if (sec == SEC_I_INCOMPLETE_CREDENTIALS)
        {
            // server asked for client certificate, not supported here
            result = -1;
            break;
        }
        else if (sec == SEC_I_CONTINUE_NEEDED)
        {
            // need to send data to server
            char* buffer = (char*)outbuffers[0].pvBuffer;
            int size = outbuffers[0].cbBuffer;

            while (size != 0)
            {
                int d = send(s.sock, buffer, size, 0);
                if (d <= 0)
                {
                    break;
                }
                size -= d;
                buffer += d;
            }
            FreeContextBuffer(outbuffers[0].pvBuffer);
            if (size != 0)
            {
                // failed to fully send data to server
                result = -1;
                break;
            }
        }
        else if (sec != SEC_E_INCOMPLETE_MESSAGE)
        {
            // SEC_E_CERT_EXPIRED - certificate expired or revoked
            // SEC_E_WRONG_PRINCIPAL - bad hostname
            // SEC_E_UNTRUSTED_ROOT - cannot vertify CA chain
            // SEC_E_ILLEGAL_MESSAGE / SEC_E_ALGORITHM_MISMATCH - cannot negotiate crypto algorithms
            result = -1;
            break;
        }

        // read more data from server when possible
        if (s.received == sizeof(s.incoming))
        {
            // server is sending too much data instead of proper handshake?
            result = -1;
            break;
        }

        int r = recv(s.sock, s.incoming + s.received, sizeof(s.incoming) - s.received, 0);
        if (r == 0)
        {
            // server disconnected socket
            return 0;
        }
        else if (r < 0)
        {
            // socket error
            result = -1;
            break;
        }
        s.received += r;
    }

    if (result != 0)
    {
        DeleteSecurityContext(context);
        FreeCredentialsHandle(&s.handle);
        closesocket(s.sock);
        WSACleanup();
        return result;
    }

    QueryContextAttributes(context, SECPKG_ATTR_STREAM_SIZES, &s.sizes);
    return 0;
}

// disconnects socket & releases resources (call this even if tls_write/tls_read function return error)
void tls_disconnect(tls_socket& s)
{
    DWORD type = SCHANNEL_SHUTDOWN;

    SecBuffer inbuffers[1];
    inbuffers[0].BufferType = SECBUFFER_TOKEN;
    inbuffers[0].pvBuffer = &type;
    inbuffers[0].cbBuffer = sizeof(type);

    SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
    ApplyControlToken(&s.context, &indesc);

    SecBuffer outbuffers[1];
    outbuffers[0].BufferType = SECBUFFER_TOKEN;

    SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };
    DWORD flags = 
        ISC_REQ_ALLOCATE_MEMORY 
        | ISC_REQ_CONFIDENTIALITY 
        | ISC_REQ_REPLAY_DETECT 
        | ISC_REQ_SEQUENCE_DETECT 
        | ISC_REQ_STREAM;
    if (InitializeSecurityContextW(&s.handle, &s.context, nullptr, flags, 0, 0, &outdesc, 0, nullptr, &outdesc, &flags, nullptr) == SEC_E_OK)
    {
        char* buffer = (char*)outbuffers[0].pvBuffer;
        int size = outbuffers[0].cbBuffer;
        while (size != 0)
        {
            int d = send(s.sock, buffer, size, 0);
            if (d <= 0)
            {
                // ignore any failures socket will be closed anyway
                break;
            }
            buffer += d;
            size -= d;
        }
        FreeContextBuffer(outbuffers[0].pvBuffer);
    }
    shutdown(s.sock, SD_BOTH);

    DeleteSecurityContext(&s.context);
    FreeCredentialsHandle(&s.handle);
    closesocket(s.sock);
    WSACleanup();
}

// returns 0 on success or negative value on error
int tls_write(tls_socket* s, const void* buffer, uint64_t size)
{
    while (size != 0)
    {
        int use = (std::min)(static_cast<unsigned long>(size), s->sizes.cbMaximumMessage);

        char wbuffer[TLS_MAX_PACKET_SIZE];
        assert(s->sizes.cbHeader + s->sizes.cbMaximumMessage + s->sizes.cbTrailer <= sizeof(wbuffer));

        SecBuffer buffers[3];
        buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
        buffers[0].pvBuffer = wbuffer;
        buffers[0].cbBuffer = s->sizes.cbHeader;
        buffers[1].BufferType = SECBUFFER_DATA;
        buffers[1].pvBuffer = wbuffer + s->sizes.cbHeader;
        buffers[1].cbBuffer = use;
        buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
        buffers[2].pvBuffer = wbuffer + s->sizes.cbHeader + use;
        buffers[2].cbBuffer = s->sizes.cbTrailer;

        RtlCopyMemory(buffers[1].pvBuffer, buffer, use);

        SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };
        SECURITY_STATUS sec = EncryptMessage(&s->context, 0, &desc, 0);
        if (sec != SEC_E_OK)
        {
            // this should not happen, but just in case check it
            return -1;
        }

        int total = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
        int sent = 0;
        while (sent != total)
        {
            int d = send(s->sock, wbuffer + sent, total - sent, 0);
            if (d <= 0)
            {
                // error sending data to socket, or server disconnected
                return -1;
            }
            sent += d;
        }

        buffer = (char*)buffer + use;
        size -= use;
    }

    return 0;
}

// blocking read, waits & reads up to size bytes, returns amount of bytes received on success (<= size)
// returns 0 on disconnect or negative value on error
int tls_read(tls_socket* s, void* buffer, uint64_t size)
{
    int result = 0;

    while (size != 0)
    {
        if (s->decrypted)
        {
            // if there is decrypted data available, then use it as much as possible
            int use = (std::min)(static_cast<int>(size), s->available);
            RtlCopyMemory(buffer, s->decrypted, use);
            buffer = (char*)buffer + use;
            size -= use;
            result += use;

            if (use == s->available)
            {
                // all decrypted data is used, remove ciphertext from incoming buffer so next time it starts from beginning
                RtlMoveMemory(s->incoming, s->incoming + s->used, s->received - s->used);
                s->received -= s->used;
                s->used = 0;
                s->available = 0;
                s->decrypted = nullptr;
            }
            else
            {
                s->available -= use;
                s->decrypted += use;
            }
        }
        else
        {
            // if any ciphertext data available then try to decrypt it
            if (s->received != 0)
            {
                SecBuffer buffers[4];
                assert(s->sizes.cBuffers == ARRAYSIZE(buffers));

                buffers[0].BufferType = SECBUFFER_DATA;
                buffers[0].pvBuffer = s->incoming;
                buffers[0].cbBuffer = s->received;
                buffers[1].BufferType = SECBUFFER_EMPTY;
                buffers[2].BufferType = SECBUFFER_EMPTY;
                buffers[3].BufferType = SECBUFFER_EMPTY;

                SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };

                SECURITY_STATUS sec = DecryptMessage(&s->context, &desc, 0, nullptr);
                if (sec == SEC_E_OK)
                {
                    assert(buffers[0].BufferType == SECBUFFER_STREAM_HEADER);
                    assert(buffers[1].BufferType == SECBUFFER_DATA);
                    assert(buffers[2].BufferType == SECBUFFER_STREAM_TRAILER);

                    s->decrypted = (char*)buffers[1].pvBuffer;
                    s->available = buffers[1].cbBuffer;
                    s->used = s->received - (buffers[3].BufferType == SECBUFFER_EXTRA ? buffers[3].cbBuffer : 0);

                    // data is now decrypted, go back to beginning of loop to copy memory to output buffer
                    continue;
                }
                else if (sec == SEC_I_CONTEXT_EXPIRED)
                {
                    // server closed TLS connection (but socket is still open)
                    s->received = 0;
                    return result;
                }
                else if (sec == SEC_I_RENEGOTIATE)
                {
                    // server wants to renegotiate TLS connection, not implemented here
                    return -1;
                }
                else if (sec != SEC_E_INCOMPLETE_MESSAGE)
                {
                    // some other schannel or TLS protocol error
                    return -1;
                }
                // otherwise sec == SEC_E_INCOMPLETE_MESSAGE which means need to read more data
            }
            // otherwise not enough data received to decrypt

            if (result != 0)
            {
                // some data is already copied to output buffer, so return that before blocking with recv
                break;
            }

            if (s->received == sizeof(s->incoming))
            {
                // server is sending too much garbage data instead of proper TLS packet
                return -1;
            }

            // wait for more ciphertext data from server
            int r = recv(s->sock, s->incoming + s->received, sizeof(s->incoming) - s->received, 0);
            if (r == 0)
            {
                // server disconnected socket
                return 0;
            }
            else if (r < 0)
            {
                // error receiving data from socket
                result = -1;
                break;
            }
            s->received += r;
        }
    }

    return result;
}

int main()
{
    const std::wstring hostname = L"www.google.com";
    const std::string hostnameA = "www.google.com";
    //const char* hostname = "badssl.com";
    //const char* hostname = "expired.badssl.com";
    //const char* hostname = "wrong.host.badssl.com";
    //const char* hostname = "self-signed.badssl.com";
    //const char* hostname = "untrusted-root.badssl.com";
    const char* path = "/";

    tls_socket s;
    if (socket_connect(s, hostname, 443) != 0)
    {
        std::wcout << std::format(L"Error connecting socket to {}\n", hostname);
        return -1;
    }

    if (tls_connect(s, hostname) != 0)
    {
        std::wcout << std::format(L"Error connecting to {}\n", hostname);
        return -1;
    }

    std::wcout << L"Connected!\n";

    // send request
    std::string req = std::format("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", hostnameA);
    if (tls_write(&s, req.c_str(), req.size()) != 0)
    {
        tls_disconnect(s);
        return -1;
    }

    // write response to file
    std::string data;
    std::vector<char> buf(65536);
    for (;;)
    {
        int r = tls_read(&s, buf.data(), buf.size());
        if (r < 0)
        {
            std::wcout << L"Error receiving data\n";
            break;
        }
        else if (r == 0)
        {
            std::wcout << L"Socket disconnected\n";
            break;
        }
        else
        {
            data += std::string(buf.data(), r);
        }
    }

    std::wcout << data.c_str() << std::endl;
    std::wcout << std::format(L"Received {} bytes\n", data.size());

    tls_disconnect(s);

    return 0;
}
