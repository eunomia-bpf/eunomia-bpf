# 使用 Eunomia 实现通过 http API 完成 ebpf 程序的极速热更新

目前 ebpf 程序的热更新还在测试阶段，我们还在探索更好的实现方式。

源代码实现，请参考：[../bpftools/hot-update](../bpftools/hot-update)

## ebpf 程序框架

libbpf 采用特定的结构来存储 ebpf 程序框架，例如：

```c
struct update_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *rb;
	} maps;
	struct {
		struct bpf_program *handle_exec;
	} progs;
	struct {
		struct bpf_link *handle_exec;
	} links;
};
```
它会在 bpf__create_skeleton 函数中完成 ebpf 编译过后的代码的加载工作，类似这样：

```c
static inline int
update_bpf__create_skeleton(struct update_bpf *obj)
{
	struct bpf_object_skeleton *s;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)
		return -1;
	obj->skeleton = s;

	s->sz = sizeof(*s);
	s->name = "update_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 1;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps)
		goto err;

	s->maps[0].name = "rb";
	s->maps[0].map = &obj->maps.rb;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs)
		goto err;

	s->progs[0].name = "handle_exec";
	s->progs[0].prog = &obj->progs.handle_exec;
	s->progs[0].link = &obj->links.handle_exec;

	s->data_sz = 26160;
	s->data = (void *)"\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xf0\x62\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x0d\0\
\x0c\0\xbf\x16\0\0\0\0\0\0\x85\0\0\0\x0e\0\0\0\xbf\x08\0\0\0\0\0\0\xb7\x09\0\0\
\0\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\xa8\0\0\0\xb7\x03\0\0\
\0\0\0\0\x85\0\0\0\x83\0\0\0\xbf\x07\0\0\0\0\0\0\x15\x07\x25\0\0\0\0\0\x85\0\0\
....
```

其中 s->data 是编译好的，可重定位的 ebpf 字节码。

## 我们的实现

[../bpftools/hot-update](../bpftools/hot-update) 该程序将 libbpf 加载骨架和 exec 代码分成两部分，并使用 json 在它们之间传递 base64 编码的 ebpf 程序：

the load skeleton part:

```c
obj = (struct update_bpf *)calloc(1, sizeof(*obj));
  if (!obj)
    return 1;
  if (update_bpf__create_skeleton(obj))
    goto err;

  data.name = obj->skeleton->name;
  data.data_sz = obj->skeleton->data_sz;
  base64_data = base64_encode((const unsigned char *)obj->skeleton->data, data.data_sz, &base64_len);
  data.data = (const char*)base64_data;
  for (int i = 0; i < obj->skeleton->map_cnt; i++)
  {
    data.maps_name.push_back(obj->skeleton->maps[i].name);
  }
  for (int i = 0; i < obj->skeleton->prog_cnt; i++)
  {
    data.progs_name.push_back(obj->skeleton->progs[i].name);
  }
  std::cout << data.to_json();
```

the exec ebpf code part:

```c
/* Load and verify BPF application */
	struct ebpf_update_data ebpf_data;
	ebpf_data.from_json_str(json_str);
	skel = update_bpf__open_from_json(ebpf_data);
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = update_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
```

这样就可以将 ebpf 程序的编译和加载分开，配合 eunomia 框架：

- 在本地生成 ebpf 字节码，并通过 json http API 推送给远端；
- 在远端直接获取 ebpf 字节码并且加载执行，速度非常快；

优点：
- 远端只需要一个 eunomia 二进制 server，以及内核的 BTF 重定位信息，不需要 BCC 编译工具链，非常轻量级；
- 速度极快，仅需网络传输时间+base64编解码时间+内核验证器和安装时间，不需要额外编译；

限制：
- 可以使用不同的 tracepoint，但 ebpf 程序数量和 map 数量有限制必须相同；
- 必须事先有 libbpf 的用户态框架；

## 测试

概念性验证：在 bpftools\hot-update 目录中

after compile, you will get a client an a server：

```sh
./client > update.json
sudo ./update $(cat update.json)
```

with the http API of eunomia, we can hot update the ebpf code using POST json to this program:

(hot update example is not enabled by default, so you may need to add it in config file.)

```sh
sudo ./eunomia server
./client 127.0.0.1:8527
```
