# Crypto Binary Corpus for vSim

这个项目的第一阶段目标是：收集常用加密算法库的可复现二进制样本，并为后续 vSim feature 提取和相似性匹配建立基础数据。

## 仓库内容说明

本仓库只保存项目源码、配置、脚本和文档，不直接保存本地生成的大型数据目录。

以下目录需要在本地准备或重新生成，已在 `.gitignore` 中排除：

```text
vSim/        # vSim 上游项目，本地 clone
corpus/      # 二进制语料、源码包、构建目录、vSim dump/cache/fingerprint
.venv/       # Python 虚拟环境
.vsim310-venv/
.uv-python/
```

`corpus/` 当前可能达到数 GB 到十几 GB，普通 Git 仓库不适合直接管理这些文件。需要共享完整语料时，建议使用 GitHub Release、Git LFS、Zenodo、Hugging Face Dataset 或其他对象存储；本仓库默认提供脚本来复现生成过程。

## 克隆后准备 vSim

项目脚本默认认为 vSim 位于仓库根目录的 `vSim/`：

```bash
git clone https://github.com/Blame-K/CryptoLibScout.git
cd CryptoLibScout
git clone https://github.com/OSUSecLab/vSim.git vSim
```

建议使用 Python 3.10 为 vSim 准备独立虚拟环境：

```bash
python3.10 -m venv .vsim310-venv
source .vsim310-venv/bin/activate
python -m pip install --upgrade pip
```

如果 vSim 上游仓库提供依赖文件，请优先按上游说明安装。例如：

```bash
python -m pip install -r vSim/requirements.txt
```

项目提供了一个环境脚本，用来设置 `VSIM_HOME`、`PYTHONPATH` 和 vSim 虚拟环境路径：

```bash
source scripts/vsim_env.sh
```

如果你的 vSim 路径或虚拟环境路径不同，请同步修改 `scripts/vsim_env.sh`。

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

## 生成 corpus/

`corpus/` 是本地生成目录，不会提交到 GitHub。它主要包含：

```text
corpus/sources/     # 下载或手动放置的源码包
corpus/work/        # 解压、构建、安装中间目录
corpus/binaries/    # 收集到的 shared/static、stripped/unstripped 产物
corpus/metadata/    # samples.jsonl 等元数据
corpus/vsim/        # vSim CSV、dump、cache、fingerprint 输出
corpus/harness/     # 静态库 harness 可执行文件
```

## 第一次只构建一个样本

建议先从一个库、一个版本、一个优化等级开始：

```bash
python3 scripts/collect_crypto_corpus.py \
  --library openssl \
  --version 1.1.1w \
  --opt O2 \
  --mode shared \
  --reset-metadata
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
  --no-download \
  --reset-metadata
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

如果想重新生成 metadata，可以加 `--reset-metadata`：

```bash
python3 scripts/collect_crypto_corpus.py --reset-metadata
```

如果已经存在构建安装目录，只想重新收集产物和 metadata，可以使用：

```bash
python3 scripts/collect_crypto_corpus.py --collect-only --reset-metadata
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

## 生成 vSim 输入与特征

先从 metadata 生成 vSim CSV。默认只选择 `shared` 且未 strip 的 ELF：

```bash
python3 scripts/prepare_vsim_crypto_dataset.py
```

生成结果位于：

```text
corpus/vsim/crypto_shared_elf.csv
corpus/vsim/crypto_shared_elf.selected.jsonl
corpus/vsim/crypto_shared_elf.skipped.jsonl
```

然后加载 vSim 环境并运行 value extraction：

```bash
source scripts/vsim_env.sh
python scripts/run_vsim_value_extraction.py \
  --csv corpus/vsim/crypto_shared_elf.csv \
  --workers 1
```

生成 fingerprint：

```bash
python scripts/generate_vsim_fingerprints.py \
  --csv corpus/vsim/crypto_shared_elf.csv \
  --fingerprint-dir corpus/vsim/fingerprints \
  --workers 1 \
  --expr-workers 1
```

调试时可以先限制样本数量：

```bash
python scripts/run_vsim_value_extraction.py \
  --csv corpus/vsim/crypto_shared_elf.csv \
  --limit 1 \
  --workers 1
```

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
