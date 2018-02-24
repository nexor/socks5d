import std.stdio, std.getopt, std.file;
import socks5d.server, socks5d.config;
import socks5d.factory : f, logger;

import core.thread : Thread;

immutable string versionString = "0.0.4-dev";
immutable string defaultAddress = "127.0.0.1";
immutable ushort defaultPort = 1080;

ushort port = defaultPort;
string address = defaultAddress;
string authString;
string configFile;
byte   verbosity = 2; // log verbosity level
bool   ver;

int main(string[] args)
{
    if (processHelpInformation(args)) {
        return 0;
    }

    bool correctLevel = logger.level(verbosity);
    if (!correctLevel) {
        logger.warning("Unknown verbosity level: %d", verbosity);
    }

    logger.info("Starting socks5d server v. %s", versionString);

    Server[uint] servers;
    if (configFile is null) {
        logger.warning("config file not found, using default settings");

        auto server = new Server;
        server.addListenItem(address, port);
        servers[0] = server;

    } else if (!configFile.exists()) {
        logger.fatal("Config file '%s' not found, terminating.", configFile);
        return 1;
    } else {
        servers = configFile.loadConfig.getServers();
    }

    foreach (serverId, server; servers) {
        logger.trace("Running server %d", serverId);
        server.run();
    }

    return 0;
}

bool processHelpInformation(string[] args)
{
    import std.conv;
    const string helpString = "Socks5d SOCKS 5 proxy server version " ~ versionString ~ ".\n\n" ~
        "Usage: socks5d [OPTIONS]";

    auto helpInformation = getopt(args,
        std.getopt.config.caseSensitive,
        "address", "[IP address] Address to bind to (" ~ defaultAddress ~ " by default).",   &address,
        "port",    "[1..65535] Port number to listen to (" ~ to!string(defaultPort) ~ " by default).", &port,
        "auth",    "[login:password] Authentication string if required.",  &authString,
        "config",  "[path] Path to config file.", &configFile,
        "version|V",  "Print version and exit.",     &ver,
        "verbose|v",  "[0..3] Use verbose output level. Available levels: " ~
            "0(default, least verbose), 1, 2, 3(most verbose).",         &verbosity
    );

    if (ver) {
        writefln("Socks5d version %s", versionString);

        return true;
    }

    if (helpInformation.helpWanted) {
        defaultGetoptPrinter(helpString, helpInformation.options);
        return true;
    }

    return false;
}
