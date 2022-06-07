#include <cstdlib>
#include <fstream>
#include <sstream>
#include <iostream>
#include <string>
#include <stdexcept>
#include <memory>

#include <grpcpp/grpcpp.h>
#include <grpcpp/channel.h>
#include <grpcpp/support/channel_arguments.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/opensslv.h>

#include <demo.pb.h>
#include <demo.grpc.pb.h>

namespace {

    std::string endpoint(std::string host, int port) {
        std::ostringstream oss;
        oss << host << ":" << port;
        return oss.str();
    }

    std::string streamContent(std::istream &in) {
        std::istreambuf_iterator<char> it(in);
        std::istreambuf_iterator<char> eos;
        return std::string(it, eos);
    }
    std::string readPrivateKey(std::istream &in, std::string const &passphrase) {
        struct bio_deleter {
            void operator()(BIO *p) {
                if (p)
                    BIO_free_all(p);
            }
        };
        struct evp_pkey_deleter {
            void operator()(EVP_PKEY *p) {
                if (p)
                    EVP_PKEY_free(p);
            }
        };

        std::string const &key_content = streamContent(in);
        std::shared_ptr<BIO> bin(
                BIO_new_mem_buf(key_content.data(), key_content.size()),
                bio_deleter());
        std::shared_ptr<EVP_PKEY> pkey(PEM_read_bio_PrivateKey(
                bin.get(),
                NULL,
                NULL,
                const_cast<char*>(passphrase.c_str())),
                evp_pkey_deleter());
        if (!pkey)
            throw std::runtime_error("read private key failed!");
        std::shared_ptr<BIO> bout(BIO_new(BIO_s_mem()), bio_deleter());
        int rc = PEM_write_bio_PrivateKey(
                bout.get(),
                pkey.get(),
                NULL,
                NULL,
                0,
                NULL,
                NULL);
        if (!rc)
            throw std::runtime_error("PEM_write_bio_PrivateKey failed");
        char *p = NULL;
        long size = 0;
        size = BIO_get_mem_data(bout.get(), &p);
        return std::string(p, size);
    }

    class DemoServiceImpl : public DemoService::Service {
        virtual ::grpc::Status sayHi(
                ::grpc::ServerContext* context,
                const ::DemoRequest* request,
                ::DemoResponse* response) {
            std::cout << "handle request" << std::endl;
            return grpc::Status::OK;
        }
    };

    class MyServer {
        public:
            explicit MyServer()
                : _M_port(0)
                , _M_bound_port(-1)
                , _M_service()
                , _M_server() {
            }

            virtual ~MyServer() {
                this->stop();
            }

            void start() {
                if (!_M_service)
                    throw std::runtime_error("No service specified yet!");
                std::shared_ptr<grpc::ServerCredentials> creds =
                    this->createCredentials();
                int selected_port = 0;
                std::string ep = endpoint("localhost", _M_port);
                _M_server = grpc::ServerBuilder()
                    .AddListeningPort(ep, creds, &selected_port)
                    .RegisterService(_M_service.get())
                    .BuildAndStart();
                if (selected_port <= 0 || !_M_server)
                    throw std::runtime_error("server start failed!");
                _M_bound_port = selected_port;
                std::clog
                    << "server is running at port "
                    << _M_bound_port
                    << std::endl;
            }

            void stop() {
                if (!_M_server || _M_bound_port < 0)
                    return;
                std::clog
                    << "server is shutdown at port "
                    << _M_bound_port
                    << std::endl;
                _M_server->Shutdown();
                _M_server->Wait();
                _M_bound_port = -1;
            }

            int getPort() {
                return _M_port;
            }

            void setPort(int value) {
                _M_port = value;
            }

            int getLocalPort() {
                return _M_bound_port;
            }

            void setService(std::shared_ptr<grpc::Service> service) {
                _M_service = service;
            }

            std::shared_ptr<grpc::Service> getService() {
                return _M_service;
            }
        protected:
            virtual
            std::shared_ptr<grpc::ServerCredentials> createCredentials() {
                return grpc::InsecureServerCredentials();
            }

        private:
            int _M_port;
            int _M_bound_port;
            std::shared_ptr<grpc::Service> _M_service;
            std::unique_ptr<grpc::Server> _M_server;
    };

    class MySslServer : public MyServer {
        public:
            MySslServer() {
            }

            virtual ~MySslServer() {
            }

            void setSsl(
                    std::istream &key,
                    std::istream &crt,
                    std::string const &passphrase) {
                _M_ssl_key = readPrivateKey(key, passphrase);
                _M_ssl_crt = streamContent(crt);
            }

            void setSsl(std::string const &key, std::string const &crt) {
                _M_ssl_key = key;
                _M_ssl_crt = crt;
            }

            void setSslKey(std::string const &key) {
                _M_ssl_key = key;
            }

            void setSslCertificate(std::string const &crt) {
                _M_ssl_crt = crt;
            }
        protected:
            virtual
            std::shared_ptr<grpc::ServerCredentials> createCredentials() {
                if (_M_ssl_key.empty() || _M_ssl_crt.empty())
                    throw std::runtime_error("key or certificate is empty!");
                grpc::SslServerCredentialsOptions opts;
                opts.force_client_auth = false;
                // allow client certificate absent
                opts.client_certificate_request =
                    GRPC_SSL_REQUEST_CLIENT_CERTIFICATE_BUT_DONT_VERIFY;
                grpc::SslServerCredentialsOptions::PemKeyCertPair pair;
                pair.private_key = _M_ssl_key;
                pair.cert_chain = _M_ssl_crt;
                opts.pem_key_cert_pairs.push_back(pair);
                std::shared_ptr<grpc::ServerCredentials> creds =
                    grpc::SslServerCredentials(opts);
                return creds;
            }
        private:
            std::string _M_ssl_key;
            std::string _M_ssl_crt;
    };

    template <typename T>
    class MyClient {
        public:
            typedef typename T::Stub stub_type;

            MyClient() {
            }

            virtual ~MyClient() {
                disconnect();
            }

            void connect() {
                std::shared_ptr<grpc::ChannelCredentials> creds =
                    createCredentials();
                grpc::StubOptions options;
                std::string target = endpoint(_M_host, _M_port);
                grpc::ChannelArguments args = createChannelArguments();
                std::shared_ptr<grpc::Channel> channel =
                    grpc::CreateCustomChannel(target, creds, args);
                _M_stub = T::NewStub(channel, options);
            }

            stub_type* operator->() {
                return _M_stub.get();
            }

            void disconnect() {
                _M_stub = NULL;
            }

            void setHost(std::string const &value) {
                _M_host = value;
            }

            std::string getHost() const {
                return _M_host;
            }

            void setPort(int value) {
                _M_port = value;
            }

            int getPort() const {
                return _M_port;
            }

            void setEndpoint(std::string const &host, int port) {
                setHost(host);
                setPort(port);
            }
        protected:
            virtual
            std::shared_ptr<grpc::ChannelCredentials>
            createCredentials() {
                return grpc::InsecureChannelCredentials();
            }

            virtual
            grpc::ChannelArguments createChannelArguments() {
                return grpc::ChannelArguments();
            }
        private:
            std::string _M_host;
            int _M_port;
            std::unique_ptr<stub_type> _M_stub;
    };

    template <typename T>
    class MySslClient : public MyClient<T> {
        public:
            void setSsl(
                    std::istream &kstream,
                    std::istream &cstream,
                    std::string const &passphrase,
                    std::istream &trust_stream) {
                _M_ssl_key = readPrivateKey(kstream, passphrase);
                _M_ssl_crt = streamContent(cstream);
                _M_ssl_trust_crts = streamContent(trust_stream);
            }

            void setSslTrustCertificates(std::string const &value) {
                _M_ssl_trust_crts = value;
            }

            void setSslTrustCertificates(std::istream &in) {
                _M_ssl_trust_crts = streamContent(in);
            }

            void setSslCertificateChain(std::istream &in) {
                _M_ssl_crt = streamContent(in);
            }

            void setSslKey(std::istream &in, std::string const &passphrase) {
                _M_ssl_key = readPrivateKey(in, passphrase);
            }

            void setSslTargetNameOverride(std::string const &value) {
                _M_ssl_target_name_override = value;
            }

            std::string getSslTargetNameOverride() const {
                return _M_ssl_target_name_override;
            }

            virtual
            std::shared_ptr<grpc::ChannelCredentials> createCredentials() {
                grpc::SslCredentialsOptions options;
                if (!_M_ssl_key.empty() && !_M_ssl_crt.empty()) {
                    options.pem_private_key = _M_ssl_key;
                    options.pem_cert_chain = _M_ssl_crt;
                }
                if (!_M_ssl_trust_crts.empty())
                    options.pem_root_certs = _M_ssl_trust_crts;
                return grpc::SslCredentials(options);
            }

            virtual
            grpc::ChannelArguments createChannelArguments() {
                grpc::ChannelArguments args;
                args.SetSslTargetNameOverride(_M_ssl_target_name_override);
                return args;
            }

        protected:
        private:
            std::string _M_ssl_key;
            std::string _M_ssl_crt;
            std::string _M_ssl_trust_crts;
            std::string _M_ssl_target_name_override;
    };
}

int main(int argc, char* argv[]) try {
    using namespace std;

    MySslServer server;
    server.setService(std::make_shared<DemoServiceImpl>());
    // in "bin" directory
    std::ifstream key_stream("../../tests/data/key.pem");
    std::ifstream crt_stream("../../tests/data/crt.pem");
    if (!key_stream || !crt_stream)
        throw std::runtime_error("key_stream, crt_stream open failed!");
    server.setSsl(key_stream, crt_stream, "123");
    server.start();

    MySslClient<DemoService> client;
    client.setEndpoint("localhost", server.getLocalPort());
    std::ifstream trust_stream("../../tests/data/crt.pem");
    if (!trust_stream)
        throw std::runtime_error("trust_stream open failed!");
    client.setSslTrustCertificates(trust_stream);
    client.setSslTargetNameOverride("www.xyz.com");
    client.connect();
    for (int i = 0, n = 10; i < n; ++i) {
        grpc::ClientContext ctx;
        DemoRequest req;
        DemoResponse res;
        grpc::Status status = client->sayHi(&ctx, req, &res);
        if (!status.ok())
            throw std::runtime_error(status.error_message());
    }
    client.disconnect();
} catch (std::exception const &e) {
    std::cerr << "[c++ exception] " << e.what() << std::endl;
    return EXIT_FAILURE;
} catch (...) {
    std::cerr << "[c++ exception] " << "<UNKNOWN CAUSE>" << std::endl;
    return EXIT_FAILURE;
}
