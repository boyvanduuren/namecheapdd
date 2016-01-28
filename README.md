namecheap_updater
=================

A simple tool to update A records registered with namecheap, using [this][1] method.
Configuration is done in a YAML file that has to be named `config.yaml` and exist
in the same directory as the binary. An example config file is shipped as `config.yaml.example`.

Compile with `go build`.

[1]: https://www.namecheap.com/support/knowledgebase/article.aspx/29/11/how-do-i-use-the-browser-to-dynamically-update-hosts-ip "Namecheap.com - How do I use the browser to dynamically update host's IP?"
