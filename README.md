# Crypto Binary Corpus for vSim

这个项目的第一阶段目标是：收集常用加密算法库的可复现二进制样本，并为后续 vSim feature 提取和相似性匹配建立基础数据。

## 当前建议路线

先只做一个最小闭环：

1. 选择 `OpenSSL`、`libsodium`、`mbedTLS` 三个库。
2. 每个库选择 2 个版本。
3. 每个版本构建 `O0/O2/O3`、`shared/static`、`stripped/unstripped` 组合。
4. 为每个产物写入 `corpus/metadata/samples.jsonl`。
5. 后续再把 `corpus/binaries` 里的二进制交给 vSim 提取 feature。

## 运行前依赖

Linux 环境中需要：

```bash
gcc
make
perl
strip
tar
```

`OpenSSL` 的构建通常需要 `perl`。`libsodium` 和 `mbedTLS` 的官方发布包通常可以直接 `make`/`configure`。

## 第一次只构建一个样本

建议先从一个库、一个版本、一个优化等级开始：

```bash
python3 scripts/collect_crypto_corpus.py \
  --library openssl \
  --version 1.1.1w \
  --opt O2 \
  --mode shared
```

如果网络受限，可以先手动把源码包下载到：

```text
corpus/sources/<library>/<archive-name>
```

然后加 `--no-download`：

```bash
python3 scripts/collect_crypto_corpus.py \
  --library openssl \
  --version 1.1.1w \
  --opt O2 \
  --mode shared \
  --no-download
```

## 构建全部初始语料

```bash
python3 scripts/collect_crypto_corpus.py
```

生成结果会放在：

```text
corpus/binaries/
corpus/metadata/samples.jsonl
```

## metadata 字段

`samples.jsonl` 每一行对应一个二进制产物，例如：

```json
{
  "library": "openssl",
  "version": "1.1.1w",
  "compiler": "gcc",
  "opt": "O2",
  "linkage": "shared",
  "stripped": false,
  "artifact": "corpus/binaries/openssl/1.1.1w/gcc/O2/shared/unstripped/libcrypto.so.1.1",
  "artifact_sha256": "..."
}
```

这些字段之后会和 vSim feature 一起进入匹配库，用来回答“像哪个库”和“像哪个版本”。

## 下一步

完成第一批二进制收集后，下一步应该做两件事：

1. 接入 vSim，对 `corpus/binaries` 中每个产物提取函数级 feature。
2. 写一个 SQLite 建库脚本，把 `library/version/compiler/opt/linkage/stripped/feature` 存起来。

## OpenSSL 静态 harness

静态库 `.a` 不是完整 ELF 程序，不适合直接交给 vSim。项目里提供了一个
OpenSSL harness，用来把 `libssl.a` 和 `libcrypto.a` 静态链接进一个可执行文件：

```bash
python3 scripts/build_openssl_static_harnesses.py
```

生成结果位于：

```text
corpus/harness/openssl/<version>/<compiler>/<opt>/api-smoke/unstripped/openssl_static_harness
```

准备静态 harness 的 vSim 输入 CSV：

```bash
python3 scripts/prepare_vsim_crypto_dataset.py \
  --linkage static \
  --csv-name crypto_static_harness_elf.csv
```

之后可以按普通 ELF 流程提取：

```bash
source scripts/vsim_env.sh
python scripts/run_vsim_value_extraction.py \
  --csv corpus/vsim/crypto_static_harness_elf.csv \
  --workers 1
python scripts/generate_vsim_fingerprints.py \
  --csv corpus/vsim/crypto_static_harness_elf.csv \
  --fingerprint-dir corpus/vsim/static_harness_fingerprints \
  --workers 1 \
  --expr-workers 1
```
