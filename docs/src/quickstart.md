# Quick Start

- Github Template：[eunomia-bpf/ebpm-template](https://github.com/eunomia-bpf/ebpm-template)
- example bpf programs: [examples/bpftools](examples/bpftools/)
- tutorial: [eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial)

You can get pre-compiled eBPF programs running from the cloud to the kernel in `1` line of bash:

    ```bash
    # download the release from https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecli
    $ wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli
    $ sudo ./ecli https://eunomia-bpf.github.io/eunomia-bpf/sigsnoop/package.json # simply run a pre-compiled ebpf code from a url
    $ sudo ./ecli sigsnoop:latest # run with a name and download the latest version bpf tool from our repo
    ```
