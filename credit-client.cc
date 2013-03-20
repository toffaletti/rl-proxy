#include "credit-client.hh"

#include <iostream>
#include <boost/program_options.hpp>
#include <boost/program_options/parsers.hpp>

using namespace ten;

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
    std::string grandfather_file;
    std::string blacklist_file;
    std::string secret;
    std::string server_host;
    uint16_t server_port;
    std::string ip;
    std::string rawkey;
    std::string db;
    uint64_t key;
    uint64_t value;
};

// globals
static config conf;
static key_engine keng{""};

static void startup() {
    credit_client cc{conf.server_host, conf.server_port,
        conf.blacklist_file, conf.grandfather_file};
    if (conf.db.empty()) {
        if (conf.secret.empty()) {
            std::cerr << "Error: secret key is required\n\n";
            kernel::shutdown();
            return;
        }
        keng.secret = conf.secret;
        apikey akey = {};
        cc.full_query(conf.ip, conf.rawkey, conf.key, akey, conf.db, conf.value, keng, 1);
    } else {
        if (!cc.query(conf.db, conf.key, conf.value)) {
            std::cerr << "timeout\n";
        }
    }
    std::cout << conf.db << "[" << conf.key << "]=" << conf.value << "\n";
    cc.close();
}

int main(int argc, char *argv[]) {
    return task::main([&] {
        options opts;

        opts.configuration.add_options()
            ("credit-server", po::value<std::string>(&conf.server_host)->default_value("localhost"), "credit-server host:port")
            ("secret", po::value<std::string>(&conf.secret), "hmac secret key")
            ("grandfather", po::value<std::string>(&conf.grandfather_file), "grandfathered keys file")
            ("blacklist", po::value<std::string>(&conf.blacklist_file), "blacklisted keys file")
            ("ip", po::value<std::string>(&conf.ip)->default_value(""), "use ip key and ip database")
            ("db", po::value<std::string>(&conf.db)->default_value(""), "database name")
            ("rawkey", po::value<std::string>(&conf.rawkey)->default_value(""), "rawkey")
            ("key", po::value<uint64_t>(&conf.key)->default_value(0), "64bit numeric key")
            ("value", po::value<uint64_t>(&conf.value)->default_value(0), "value")
        ;

        parse_args(opts, argc, argv);

        conf.server_port = 9876;
        parse_host_port(conf.server_host, conf.server_port);

        task::spawn(startup);
    });
}
