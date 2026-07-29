# Authorized Use

`cf-ufw-sync` modifies the local firewall of the machine it runs on.

Run it only on systems you own or are explicitly authorized to administer. Do not run it on shared or
managed infrastructure without the operator's agreement — a firewall change that is correct for your
service may break someone else's on the same host.

The tool performs no scanning, no probing, and no outbound requests other than fetching Cloudflare's
publicly documented IP range lists.
