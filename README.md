# Tinfoil Confidential VM

Tinfoil CVM is an AMD SEV-SNP confidential virtual machine for secure inference and custom compute workloads.

## Configuration

The CVM image expects a YAML config file mounted as the second disk (/dev/sdb in the guest). The SHA256 hash of the config file must be provided as the `tinfoil-config-hash=HASH` kernel cmdline parameter to the VM for boot-time verification. The VM will fail startup if the hash does not match the config file.

```yaml
models:
  - [model_name]:[version]  # OLLAMA model identifier and tag

shim:
  upstream-port: 8080       # Shim upstream proxy port
  paths:                    # API paths to handle (optional)
    - /api/chat
    - /v1/chat/completions
    - /api/generate

containers:
  - image: [container_image]  # Docker image
```
