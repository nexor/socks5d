import std.stdio, std.getopt;
import socks5d.server;

immutable string versionString = "0.0.1";
immutable string defaultAddress = "127.0.0.1";
immutable ushort defaultPort = 1080;

ushort port = defaultPort;
string address = defaultAddress;
bool   verbose;
bool   ver;

int main(string[] args)
{
    if (processHelpInformation(args)) {
        return 0;
    }

    startServer(address, port);

    return 0;
}

void startServer(string address, ushort port)
{
    writefln("Starting socks5d server v. %s", versionString);

    auto server = new Server(address, port);
    server.start();
}


bool processHelpInformation(string[] args)
{
    import std.conv;
    const string helpString = "Socks5d SOCKS 5 proxy server version " ~ versionString ~ ".\n\n" ~
        "Usage: socks5d [OPTIONS]";

    auto helpInformation = getopt(args,
        std.getopt.config.caseSensitive,
        "address", "Address to bind to (" ~ defaultAddress ~ " by default).",   &address,
        "port",    "Port number to listen to (" ~ to!string(defaultPort) ~ " by default).", &port,

        "version|V",   "Print version and exit.",    &ver,
        "verbose|v", "Use verbose output.",        &verbose,
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
