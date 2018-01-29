import socks5d.server, socks5d.config;
import vibe.core.core;
import vibe.core.log;
import vibe.core.args;
import vibe.core.file;

immutable string versionString = "0.0.4";

ushort port = 1080;
string address = "127.0.0.1";
string configFile = "config.sdl";
bool   ver;

int main(string[] args)
{
    logInfo("Starting socks5d server v. %s", versionString);

    Server[uint] servers;
    if (configFile.existsFile()) {
        servers = configFile.loadConfig.getServers();
    } else {
        logInfo("config.sdl not found, using default settings");

        auto server = new Server;

        server.addListenItem(address, port);
        servers[0] = server;
    }

    foreach (serverId, server; servers) {
        logDiagnostic("Running server %d", serverId);
        server.run();
    }

    return runApplication();
}
