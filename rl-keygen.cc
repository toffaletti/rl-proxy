#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include <iostream>
#include <boost/program_options.hpp>
#include <boost/program_options/parsers.hpp>

#include "fw/descriptors.hh"
#include "fw/logging.hh"
#include "fw/encoders.hh"

namespace po = boost::program_options;

struct options {
    po::options_description generic;
    po::options_description configuration;
    po::options_description hidden;
    po::positional_options_description pdesc;

    po::options_description cmdline_options;
    po::options_description config_file_options;
    po::options_description visible;


    options() :
        generic("Generic options"),
        configuration("Configuration"),
        hidden("Hidden options"),
        visible("Allowed options")
    {
        generic.add_options()
            ("help", "Show help message")
            ;
    }

    void setup() {
        cmdline_options.add(generic).add(configuration).add(hidden);
        config_file_options.add(configuration).add(hidden);
        visible.add(generic).add(configuration);
    }
};

static void showhelp(options &opts, std::ostream &os = std::cerr) {
    std::cerr << opts.visible << std::endl;
}

static void parse_args(options &opts, int argc, char *argv[]) {
    po::variables_map vm;
    try {
        opts.setup();

        po::store(po::command_line_parser(argc, argv)
            .options(opts.cmdline_options).positional(opts.pdesc).run(), vm);
        po::notify(vm);

        if (vm.count("help")) {
            showhelp(opts);
            exit(1);
        }

    } catch (std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl << std::endl;
        showhelp(opts);
        exit(1);
    }
}

struct config {
    std::string secret;
};

static config conf;

int verify_key(const char *secret, size_t slen, unsigned char *key_data) {
    unsigned char md[20];
    unsigned int mdlen = sizeof(md);
    HMAC(EVP_sha1(), secret, slen, key_data, 10, md, &mdlen);
    return memcmp(md, &key_data[10], 10) == 0;
}

int main(int argc, char *argv[]) {
    options opts;

    opts.configuration.add_options()
        ("secret", po::value<std::string>(&conf.secret), "hmac secret key")
    ;

    parse_args(opts, argc, argv);

    if (conf.secret.empty()) {
        std::cerr << "Error: secret key is required\n\n";
        showhelp(opts);
        exit(1);
    }

    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();

    fw::file_fd urnd("/dev/urandom", 0, O_RDONLY);
    unsigned char rand_data[32];
    ssize_t nr = urnd.read(rand_data, sizeof(rand_data));
    if (nr != sizeof(rand_data)) abort();

    unsigned char key_data[20];

    SHA1(rand_data, sizeof(rand_data), key_data);

    unsigned char md[20];
    unsigned int mdlen = sizeof(md);

    // only use the first 10 bytes of key data
    HMAC(EVP_sha1(), conf.secret.data(), conf.secret.size(),
        key_data, 10, md, &mdlen);

    if (mdlen != sizeof(md)) abort();

    memcpy(&key_data[10], md, 10);

    if (verify_key(conf.secret.data(), conf.secret.size(), key_data)) {
        char b32key[33];
        b32key[32] = 0;
        stlencoders::base32<char>::encode_upper(&key_data[0], &key_data[20], b32key);
        std::cout << b32key << "\n";
        memset(key_data, 0, sizeof(key_data));
        stlencoders::base32<char>::decode(&b32key[0], &b32key[32], key_data);
        if (verify_key(conf.secret.data(), conf.secret.size(), key_data)) {
            std::cout << "verified\n";
        }
    }
    return 0;
}