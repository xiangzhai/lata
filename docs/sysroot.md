# Linux AArch64 sysroot 制作记录

## 结果概览

| 项目 | 内容 |
| --- | --- |
| sysroot 路径 | `/home/zhaixiang/linux-aarch64` |
| 目标系统 | AOSC OS 14.0.1, `arm64` (AArch64) |
| 宿主系统 | AOSC OS 14.0.1, `loongarch64` |
| 软件源 | `https://repo.aosc.io/anthon/debs stable main`（实际重定向到 `mirrors.jlu.edu.cn`） |
| 包数量 | 158 个 |
| sysroot 大小 | 约 2.3 GiB |
| APT 缓存大小 | 约 581 MiB |
| 关键组件 | glibc 1:2.44-1, gcc 1:16.2.0, binutils 2.47-7, linux+api 2:6.18.35, bash 5.2.37-2, dpkg 1.23.5-3, apt 2:3.2.1 |
| 包清单 | `/home/zhaixiang/linux-aarch64/sysroot-packages.txt` |

整个制作过程**没有使用 root / sudo**：APT 只用于解析依赖和下载 `.deb`，随后用 `dpkg-deb -x` 解包到用户目录。

---

## 1. 准备用户可写的 APT 状态目录

由于目标 arch 与宿主不同，并且不希望污染宿主 APT 状态，这里用 `-o Dir=...` 把 APT 的状态、缓存、配置全部重定向到一个独立目录。

```bash
WORK=/home/zhaixiang/.cache/aarch64-sysroot-build
mkdir -p "$WORK"/etc/apt/{trusted.gpg.d,preferences.d,apt.conf.d}
mkdir -p "$WORK"/var/lib/apt/lists/partial
mkdir -p "$WORK"/var/cache/apt/archives/partial
mkdir -p "$WORK"/var/lib/dpkg
```

在独立目录中写入只包含 arm64 的软件源：

```bash
printf 'deb [arch=arm64] https://repo.aosc.io/anthon/debs stable main\n' \
  > "$WORK/etc/apt/sources.list"
```

复制宿主的 AOSC 签名公钥（注意用 `cp -L` 解引用符号链接，否则在新目录里会是坏链接）：

```bash
cp -L /usr/share/keyrings/aosc-archive-keyring.gpg \
  "$WORK/etc/apt/trusted.gpg.d/aosc.gpg"
chmod 644 "$WORK/etc/apt/trusted.gpg.d/aosc.gpg"
: > "$WORK/var/lib/dpkg/status"
```

> 注意：在 `Dir` 被重定向后，`apt.conf` 中的 `APT::Architecture` 不一定生效，实际必须通过命令行 `-o APT::Architecture=arm64` 指定。

## 2. 更新 arm64 软件包索引

```bash
apt-get \
  -o Dir="$WORK" \
  -o APT::Architecture=arm64 \
  -o Dir::State::status="$WORK/var/lib/dpkg/status" \
  update
```

## 3. 解析依赖并只下载 `.deb`

选择一套可直接运行/开发的 AArch64 基础系统。顶层包如下，APT 会自动补全依赖（最终 158 个包）：

```bash
PKGS="aosc-os-keyring ca-certs tzdata iana-etc \
glibc libxcrypt linux+api \
bash coreutils sed grep gawk findutils diffutils \
tar gzip xz zstd bzip2 patch less util-linux shadow \
dpkg apt \
gcc gcc-runtime binutils make pkgconf \
zlib ncurses readline libffi openssl \
gmp isl mpc mpfr"

apt-get \
  -o Dir="$WORK" \
  -o APT::Architecture=arm64 \
  -o Dir::State::status="$WORK/var/lib/dpkg/status" \
  -o Debug::NoLocking=1 \
  install --no-install-recommends --download-only -y $PKGS
```

下载完成后 `.deb` 位于：

```bash
$WORK/var/cache/apt/archives/
```

## 4. 解包到 sysroot

```bash
ROOT=/home/zhaixiang/linux-aarch64
CACHE="$WORK/var/cache/apt/archives"
mkdir -p "$ROOT"
```

`ca-certs` 包里有 `0555` 的只读目录（`/etc/ssl/certs`），直接用 `dpkg-deb -x` 会因非 root 无法在只读目录中创建符号链接而失败。解决方法是使用 tar 的 `--delay-directory-restore`，让目录权限在解包结束后才恢复，并把 `ca-certs` 放到最后解包：

```bash
extract() {
  dpkg-deb --fsys-tarfile "$1" \
    | tar -x -C "$ROOT" --delay-directory-restore --no-same-owner
}

# aosc-aaa 提供 /bin -> usr/bin、/lib -> usr/lib 等顶层 usrmerge 符号链接，必须最先解包
extract "$CACHE"/aosc-aaa_*.deb

for d in "$CACHE"/*.deb; do
  case "$d" in
    *aosc-aaa_*|*ca-certs_*) continue ;;
  esac
  extract "$d"
done

# 只读目录的包最后解包
extract "$CACHE"/ca-certs_*.deb
```

> 这一步没有执行 Debian maintainer scripts，因此仅解包文件。对 sysroot / qemu-user 使用来说这是期望行为。

## 5. 生成 dpkg 数据库

解包不会自动生成 `/var/lib/dpkg/status` 和 `.list`。这里根据 `.deb` 的 control 信息补全，使 `dpkg-query` 等工具可以正常读取：

```bash
D="$ROOT/var/lib/dpkg"
mkdir -p "$D/info" "$D/updates" "$D/parts"
: > "$D/status"

for d in "$CACHE"/*.deb; do
  pkg=$(dpkg-deb -f "$d" Package)

  # 在 Package 字段后插入 Status 字段
  dpkg-deb -f "$d" \
    | awk 'NR==1{print; print "Status: install ok installed"; next} {print}' \
    >> "$D/status"
  echo >> "$D/status"

  # 生成 <pkg>.list
  {
    echo "/."
    dpkg-deb --fsys-tarfile "$d" | tar -tf - \
      | sed -e 's#^\./##' -e 's#/$##' \
      | awk 'NF{print "/"$0}'
  } > "$D/info/$pkg.list"

  # 如 .deb 自带 md5sums 则一并复制
  if dpkg-deb --ctrl-tarfile "$d" | tar -tf - 2>/dev/null | grep -qx './md5sums'; then
    dpkg-deb --ctrl-tarfile "$d" | tar -xOf - ./md5sums \
      > "$D/info/$pkg.md5sums"
  fi
done
```

验证：

```bash
dpkg-query --admindir="$ROOT/var/lib/dpkg" -W | wc -l
# 158
```

## 6. 补充基础 `/etc` 文件

部分文件通常由 maintainer script 生成，解包方式不会自动创建。这里补上最小可用版本：

```bash
printf '%s\n' \
  'root:x:0:0:root:/root:/usr/bin/bash' \
  'nobody:x:65534:65534:nobody:/nonexistent:/usr/bin/nologin' \
  > "$ROOT/etc/passwd"

printf '%s\n' \
  'root:x:0:' 'wheel:x:998:' 'audio:x:11:' 'video:x:12:' \
  'cdrom:x:15:' 'plugdev:x:999:' 'users:x:1000:' 'zhaixiang:x:1001:' \
  > "$ROOT/etc/group"

printf '%s\n' 'aarch64-sysroot' > "$ROOT/etc/hostname"

printf '%s\n' \
  '# Generated for AArch64 sysroot' \
  'nameserver 223.5.5.5' \
  'nameserver 1.1.1.1' \
  'nameserver 8.8.8.8' \
  > "$ROOT/etc/resolv.conf"

printf '%s\n' \
  'root:!:19000:0:99999:7:::' \
  'nobody:!:19000:0:99999:7:::' \
  > "$ROOT/etc/shadow"
chmod 0640 "$ROOT/etc/shadow"
```

## 7. 生成 `ld.so.cache`

宿主的 `ldconfig` 只识别宿主架构的 ELF，用它生成会得到 0 个库，因此必须用 **目标架构的 `ldconfig`** 在 qemu-user 下执行。

本机已有 QEMU aarch64 linux-user 构建：

```bash
QEMU=/mnt/zhaixiang/lata/build_aarch64/lata-aarch64   # qemu-aarch64 8.1.50
```

先在 sysroot 中预创建缓存文件，并给 `ldconfig` 加 `-X`（不更新符号链接，避免 `-L` 模式下对不存在路径的操作失败）：

```bash
: > "$ROOT/etc/ld.so.cache"
: > "$ROOT/etc/ld.so.cache~"

"$QEMU" -L "$ROOT" -0 /usr/bin/ldconfig \
  "$ROOT/usr/bin/ldconfig" -X || true
```

qemu-user 的 `-L` 只对“已存在的绝对路径”做前缀映射；`ldconfig` 最后对 `/etc/ld.so.cache~` 执行 `chmod` 时不会映射，因此会报错退出。不过此时完整的缓存已经写入 `ld.so.cache~`，手动替换即可：

```bash
mv -f "$ROOT/etc/ld.so.cache~" "$ROOT/etc/ld.so.cache"
chmod 0644 "$ROOT/etc/ld.so.cache"
```

验证（在目标 `ldconfig` 下应能看到 656 个库）：

```bash
"$QEMU" -L "$ROOT" -0 /usr/bin/ldconfig \
  "$ROOT/usr/bin/ldconfig" -p | head
```

示例输出：

```text
在缓存 "/etc/ld.so.cache" 中找到 656 个库
    libzstd.so.1 (libc6,AArch64) => /usr/lib/libzstd.so.1
    libzstd.so (libc6,AArch64) => /usr/lib/libzstd.so
    ...
```

## 8. 记录包清单

```bash
{ echo "# AOSC OS AArch64 sysroot package manifest"
  echo "# generated $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  printf '# %s\t%s\t%s\n' package version architecture
  for d in "$CACHE"/*.deb; do
    printf '%s\t%s\t%s\n' \
      "$(dpkg-deb -f "$d" Package)" \
      "$(dpkg-deb -f "$d" Version)" \
      "$(dpkg-deb -f "$d" Architecture)"
  done | sort
} > "$ROOT/sysroot-packages.txt"
```

---

## 验证结果

### 文件架构

```bash
file "$ROOT/usr/bin/bash" "$ROOT/usr/lib/ld-linux-aarch64.so.1"
```

```text
.../usr/bin/bash: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV),
  dynamically linked, interpreter /lib/ld-linux-aarch64.so.1 ...
.../usr/lib/ld-linux-aarch64.so.1: ELF 64-bit LSB shared object, ARM aarch64 ...
```

usrmerge 符号链接正常：

```text
bin -> usr/bin
lib -> usr/lib
lib64 -> usr/lib
sbin -> usr/bin
```

### 用 qemu-user 运行目标程序

```bash
"$QEMU" -L "$ROOT" "$ROOT/usr/bin/true"; echo $?          # 0
"$QEMU" -L "$ROOT" -0 /usr/bin/bash "$ROOT/usr/bin/bash" -c 'echo hello from bash'
"$QEMU" -L "$ROOT" -0 /usr/bin/cat "$ROOT/usr/bin/cat" /etc/hostname
"$QEMU" -L "$ROOT" -0 /usr/bin/cat "$ROOT/usr/bin/cat" /etc/os-release
```

```text
hello from bash
aarch64-sysroot
PRETTY_NAME="AOSC OS (14.0.1)"
NAME="AOSC OS"
VERSION_ID="14.0.1"
...
```

`/etc/hostname`、`/etc/os-release` 均从 sysroot 读取。glibc、动态链接器、基础命令（bash / coreutils / ls / cat 等）可正常执行。

> 注意：上面用目标 `cat` 直接作为 qemu 的入口程序来验证路径映射。如果在 guest bash 中直接执行 `cat`，由于未注册 binfmt_misc，bash 的 `execve("cat")` 会落到宿主的 `cat`，看到的是宿主文件系统。

### `bin/` 二进制批量测试

使用以下形式直接运行 sysroot 中的 AArch64 二进制（`/bin` 是 `usr/bin` 的 usrmerge 符号链接）：

```bash
cd /mnt/zhaixiang/lata
QEMU=./build_aarch64/lata-aarch64
ROOT=$HOME/linux-aarch64

"$QEMU" -L "$ROOT" "$ROOT/bin/<prog>" [args]
```

共测试 20 个程序，退出码均为 0：

```text
true  echo  uname  id  date  pwd  cat  ls  sed  grep
find  tar  gzip  make  as  ld  bash  dpkg  apt  ldconfig
```

关键输出：

```text
uname -a          -> Linux ... aarch64 GNU/Linux
bash -c ...       -> BASH_VERSION=5.2.37(1)-release, calc=42
make --version    -> GNU Make 4.4.1，为 aarch64-aosc-linux-gnu 编译
as --version      -> target aarch64-aosc-linux-gnu
ld --version      -> GNU ld (GNU Binutils) 2.47.20260726
dpkg --version    -> dpkg 1.23.5 (arm64)
apt --version     -> apt 3.2.1 (arm64)
ldconfig -p       -> 找到 656 个库
```

管道测试也正常（宿主 `echo` 通过 stdin 管道输入给 guest `sed` / `grep`）：

```bash
echo "aarch64 sysroot test 123" | "$QEMU" -L "$ROOT" "$ROOT/bin/sed" -E 's/[0-9]+/NUM/'
printf 'alpha\nbeta\ngamma\n' | "$QEMU" -L "$ROOT" "$ROOT/bin/grep" 'a$'
```

> 按要求，`gcc` 未纳入本次验证范围，因此上表不包含 `gcc`。

## 使用方式

```bash
export QEMU_LD_PREFIX=/home/zhaixiang/linux-aarch64
/path/to/qemu-aarch64 /home/zhaixiang/linux-aarch64/usr/bin/bash
```

或显式传 `-L`：

```bash
qemu-aarch64 -L /home/zhaixiang/linux-aarch64 \
  /home/zhaixiang/linux-aarch64/usr/bin/程序
```

交叉编译时，把该目录作为 `--sysroot`：

```bash
aarch64-...-gcc --sysroot=/home/zhaixiang/linux-aarch64 ...
```

## 注意事项 / 限制

1. **没有运行 maintainer scripts**：alternatives、服务、部分配置未生成；`/etc/passwd`、`/etc/group` 等是本记录手工补的最小版本。
2. **这不是 chroot**：QEMU 的 `-L` 只对 sysroot 中已存在的绝对路径做前缀替换。实测读取目标路径会映射到 sysroot，但**创建新的绝对路径文件仍会落到宿主**（例如 guest `touch /tmp/x` 实际创建了宿主的 `/tmp/x`）。需要隔离时请用 `bwrap` / `chroot` + qemu-static + binfmt_misc。
3. **嵌套 exec 需要 binfmt_misc**：qemu-user 的 guest `execve` 最终调用宿主 `execve`。没有注册 aarch64 binfmt 时，guest 程序再执行另一个 guest 程序（例如在 guest shell 中直接运行 `cat`）会落到宿主同名程序，或返回 `ENOEXEC`。因此测试时应直接把目标二进制作为 qemu 的入口程序；需要完整目标工具链自举时请注册 binfmt_misc 或使用 qemu-static + chroot。本次验证按要求未包含 `gcc`。
4. **ldconfig 缓存**：用目标 `ldconfig -X` 生成，缓存中 656 个库，路径为 `/usr/lib/...`（正确的目标路径）。
5. 系统文件全部属于 `zhaixiang:zhaixiang`，未使用 root。部分包内目录/文件保留了上游权限（例如 `/etc/ssl/certs` 为 `0555`、证书文件为 `0444`）。

## 清理与扩展

下载缓存可以删除以释放约 581 MiB：

```bash
rm -rf /home/zhaixiang/.cache/aarch64-sysroot-build
```

如需增加软件包，复用第 1–4 节：把新包加入 `PKGS`，重新 `apt-get ... --download-only`，再对新增的 `.deb` 执行解包；建议同时重新生成 dpkg status / `.list` 和 `ld.so.cache`。
