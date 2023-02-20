# Unbound-Blacklist
A python script to download hosts files and block-lists and load them into a unbound (DNS Resolver)

# Path
location = /etc/unbound/blacklist/

# Phishtank
For the phishtank list you need an API key from phishtank.org. Please replaye the [API Key] with your API Key and the [PhishtankUser] with the Phishtank user.

# MISC
- With the whitelist.conf file you could whitelist domains over all Blacklists. Wildcards are allowed.
- Each blacklist will be split in it's own *.conf file in the file path /etc/unbound/unbound.conf.d/
- The configuration will be checked with the unbound checkconf script
- The script generates per blacklist it's own localhost pointer (127.0.0.2, 127.0.0.3..). On a positive match you could fastly identify which blacklist has triggered

# Compatibility
Tested with Debian 11 and Python 3.9
