#include <iostream>
#include <boost/program_options.hpp>
#include <boost/program_options/parsers.hpp>

#include <boost/date_time/gregorian/gregorian.hpp>
#include <boost/algorithm/string.hpp>

#include "keygen.hh"

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

static boost::posix_time::ptime expire_string_to_time(const std::string &expire) {
    using namespace boost::gregorian;
    using namespace boost::posix_time;

    if (expire.size() < 2) {
        throw ten::errorx("invalid expire time: %s", expire.c_str());
    }

    std::vector<std::string> splits;
    boost::split(splits, expire, boost::is_any_of("/-"));
    if (splits.size() == 3) {
        date expire_date(
            boost::lexical_cast<unsigned int>(splits[0]),
            boost::lexical_cast<unsigned int>(splits[1]),
            boost::lexical_cast<unsigned int>(splits[2])
        );
        return ptime(expire_date);
    } else {
        unsigned int count = boost::lexical_cast<unsigned int>(expire.substr(0, expire.size()-1));
        char scale = expire[expire.size()-1];

        ptime now(second_clock::local_time());

        switch (scale) {
            case 'd':
                {
                    ptime expire_time(now.date());
                    expire_time += days(count);
                    return expire_time;
                }
            case 'm':
                {
                    ptime expire_time(now.date());
                    expire_time += months(count);
                    return expire_time;
                }
            case 'y':
                {
                    ptime expire_time(now.date());
                    expire_time += years(count);
                    return expire_time;
                }
            case 'H':
                {
                    ptime expire_time(now);
                    expire_time += hours(count);
                    return expire_time;
                }
            case 'M':
                {
                    ptime expire_time(now);
                    expire_time += minutes(count);
                    return expire_time;
                }
            case 'S':
                {
                    ptime expire_time(now);
                    expire_time += seconds(count);
                    return expire_time;
                }
            default:
                throw ten::errorx("invalid expire time: %s", expire.c_str());
                break;
        }
    }
    throw ten::errorx("invalid expire time: %s", expire.c_str());
}

struct config {
    std::string secret;
    std::string expire;
    uint64_t org_id;
    uint16_t app_id;
    uint32_t credits;
};

static config conf;

int main(int argc, char *argv[]) {
    options opts;

    opts.configuration.add_options()
        ("secret", po::value<std::string>(&conf.secret), "hmac secret key")
        ("expire", po::value<std::string>(&conf.expire)->default_value("1y"), "expire time (1d, 1m, 1y)")
        ("org_id", po::value<uint64_t>(&conf.org_id)->default_value(0), "organization id the key is issued to")
        ("app_id", po::value<uint16_t>(&conf.app_id)->default_value(0), "app id within org the key is issued to")
        ("credits", po::value<uint32_t>(&conf.credits)->default_value(0), "credits given to the key for the reset duration")
    ;

    parse_args(opts, argc, argv);

    if (conf.secret.empty()) {
        std::cerr << "Error: secret key is required\n\n";
        showhelp(opts);
        exit(1);
    }

    if (conf.org_id == 0) {
        std::cerr << "Error: org_id is required\n\n";
        showhelp(opts);
        exit(1);
    }

    try {
        uint64_t expires = 0;
        if (!conf.expire.empty()) {
            boost::posix_time::ptime expire_ptime = expire_string_to_time(conf.expire);
            expires = to_time_t(expire_ptime);
        }

        key_engine eng(conf.secret);
        std::string key = eng.generate(conf.org_id, conf.app_id, conf.credits, expires);
        apikey akey;
        if (eng.verify(key, akey)) {
            std::cout << key << "\n";
            std::cerr << akey.data << "\n";
        } else {
            exit(1);
        }
    } catch (std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
    return 0;
}
