# Scopas
Linux kernel build infrastructure for developers.

Scopes is a tool to build Linux kernels locally or remotely. It handles
provisioning remote infrastructure in the Cloud, making it ideal for
developers that don't own or want noisy build servers in their homes.

**The number one rule is that it is designed to be fast.**

Because the primary use case is use cloud computing platforms to build
kernels, every second spent deploying machines and building the kernel
costs money.

It's also light on dependencies so that it can be installed on a fresh
system without having to wait for software to install.

# Limitations

The current implementation is a proof of concept, and is hilariously
tied to the Linode cloud. Even the configuration file syntax (described
below) is based on the Linode API.

The plan is to remove these limitations in the future.

# Configuration

Scopas will look for its configuration file in ~/.scopas. Here are the
supported keywords (all are required):

- API_TOKEN - Linode API token
- INSTANCE_TYPE - Linode instance type
- INSTANCE_IMAGE - Linode image type
- INSTANCE_REGION - Linode data center region
- BUILDER_NAME - Name of the builder Linode
- SSH_KEY_PATH - Path to the SSH key for the Linode builder

## Example configuration file

Here's an example configuration to use a g6-dedicated-1 Linode running
openSUSE 15.1:

```
API_TOKEN=abc1234...
INSTANCE_TYPE=g6-dedicated-1
INSTANCE_IMAGE=linode/opensuse15.1
INSTANCE_REGION=eu-west
BUILDER_NAME=builder
SSH_KEY_PATH=/home/matt/.ssh/id_rsa.linode.pub
```
