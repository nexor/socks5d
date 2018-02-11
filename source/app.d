import socks5d.server, socks5d.config;
import vibe.core.core;
import vibe.core.log;
import vibe.core.args;
import vibe.core.file;

immutable string versionString = "0.0.4-dev";

ushort port = 1080;
string address = "127.0.0.1";
string configFile;
bool   ver;

int main(string[] args)
{
    readOption("config", &configFile, "config file");

    logInfo("Starting socks5d server v. %s", versionString);

    Server[uint] servers;
    if (configFile is null) {
        logWarn("config file not found, using default settings");

        auto server = new Server;

        server.addListenItem(address, port);
        servers[0] = server;

    } else if (!configFile.existsFile()) {
        logFatal("Config file '%s' not found, terminating.", configFile);
        return 1;
    } else {
        servers = configFile.loadConfig.getServers();
    }

    foreach (serverId, server; servers) {
        logDiagnostic("Running server %d", serverId);
        server.run();
    }

    return runApplication();
}
