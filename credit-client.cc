#include "credit-client.hh"

#include <iostream>
#include <boost/program_options.hpp>
#include <boost/program_options/parsers.hpp>

using namespace ten;
const size_t default_stacksize=8*1024;

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
    std::string server_host;
    uint16_t server_port;
    std::string db;
    uint64_t key;
    uint64_t value;
};

// globals
static config conf;

static void startup() {
    taskname("startup");
    credit_client cc{conf.server_host, conf.server_port};
    if (cc.query(conf.db, conf.key, conf.value)) {
        std::cout << conf.db << "[" << conf.key << "]=" << conf.value << "\n";
    } else {
        std::cerr << "timeout\n";
    }
    cc.close();
}

int main(int argc, char *argv[]) {
    procmain p;
    options opts;

    opts.configuration.add_options()
        ("credit-server", po::value<std::string>(&conf.server_host)->default_value("localhost"), "credit-server host:port")
        ("db", po::value<std::string>(&conf.db)->default_value("default"), "database name")
        ("key", po::value<uint64_t>(&conf.key)->default_value(0), "key")
        ("value", po::value<uint64_t>(&conf.value)->default_value(0), "value")
    ;

    parse_args(opts, argc, argv);

    conf.server_port = 9876;
    parse_host_port(conf.server_host, conf.server_port);

    taskspawn(startup, 8*1024*1024);
    return p.main(argc, argv);
}
