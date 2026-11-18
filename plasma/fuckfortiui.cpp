// Metadata-only plasma-nm VPN plugin for fuckforti.
//
// plasma-nm refuses to activate a VPN connection ("Plasma is missing support for
// '<type>' VPN connections") unless a plugin in plasma/network/vpn declares the
// connection's service type in its metadata. This stub provides just that, so
// connecting from the tray works. It has no settings editor: plasma-nm cannot
// edit the connection (create it with nmcli), and loading it as an editor fails
// cleanly because it is not a KPluginFactory.

#include <QObject>
#include <QtPlugin>

class FuckfortiUiStub : public QObject
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.kde.KPluginFactory" FILE "plasmanetworkmanagement_fuckfortiui.json")
};

#include "fuckfortiui.moc"
