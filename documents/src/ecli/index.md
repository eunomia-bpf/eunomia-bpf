# ecli: run ebpf programs as json or tar

## Usage

```sh
ecli <COMMAND>
```

### example
```sh
ecli run client.tar #
# or
ecli run package.json
```

The ecc packaged tar contains custom btf files and `package.json`,
which can be run on older kernels.
For details, see [ecc-btfgen](../ecc/usage.md#options)

## Commands

- run - Run the ebpf program as tar or json.
- push - Push a container to an OCI registry.
- pull - Pull a container from an OCI registry.
- login - Login to an OCI registry.
- logout - Logout from an OCI registry. 
