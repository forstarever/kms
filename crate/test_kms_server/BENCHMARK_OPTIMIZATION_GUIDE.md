# 基准测试加速配置指南

## 当前配置分析

在 `crate/test_kms_server/benches/benches.rs` 中，各个基准测试组的配置如下：

### 1. 对称密钥创建测试 (symmetric_key_benches)
```rust
config = Criterion::default().sample_size(150).measurement_time(Duration::from_secs(45));
```
- **样本数量**: 150
- **测量时间**: 45 秒
- **预计总时间**: ~2-3 分钟（包括预热）

### 2. 对称加密测试 (symmetric_encryption_benches)
```rust
config = Criterion::default().sample_size(1000).measurement_time(Duration::from_secs(10));
```
- **样本数量**: 1000
- **测量时间**: 10 秒
- **测试数量**: 4 个（FIPS 模式）或 8 个（非 FIPS）
- **预计总时间**: ~1-2 分钟

### 3. 批量对称加密测试 (bulk_symmetric_encryption_benches)
```rust
config = Criterion::default().sample_size(15).measurement_time(Duration::from_secs(10));
```
- **样本数量**: 15
- **测量时间**: 10 秒
- **测试数量**: 2 个（100000 个明文的加密/解密）
- **预计总时间**: ~2 分钟

### 4. RSA 密钥对创建测试 (rsa_keypair_benches)
```rust
config = Criterion::default().sample_size(150).measurement_time(Duration::from_secs(45));
```
- **样本数量**: 150
- **测量时间**: 45 秒
- **预计总时间**: ~2-3 分钟

### 5. RSA 加密测试 (rsa_encryption_benches)
```rust
config = Criterion::default().sample_size(1000).measurement_time(Duration::from_secs(10));
```
- **样本数量**: 1000
- **测量时间**: 10 秒
- **测试数量**: 8 个（FIPS 模式）或 12 个（非 FIPS）
- **预计总时间**: ~2-3 分钟

### 6. 参数化加密测试 (symmetric_encryption_benches_parametrized)
```rust
config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(10));
```
- **样本数量**: 10
- **测量时间**: 10 秒
- **循环参数**:
  - `num_plaintexts`: [1, 10, 50, 100, 500, 1000] (6 个值)
  - `num_bits`: [128, 256] (2 个值)
  - 每个组合测试加密和解密 (2 个操作)
- **总测试数**: 6 × 2 × 2 = 24 个测试
- **预计总时间**: ~4-5 分钟

---

## 加速方案

### 方案 1: 快速验证配置（推荐用于开发）

适用场景：快速验证代码修改，不需要精确的性能数据。

修改 `benches.rs` 中的配置：

```rust
// 对称密钥创建测试 - 从 150 个样本减少到 20 个
criterion_group!(
    name = symmetric_key_benches;
    config = Criterion::default().sample_size(20).measurement_time(Duration::from_secs(5));
    targets = bench_create_symmetric_key,
);

// 对称加密测试 - 从 1000 个样本减少到 100 个
criterion_group!(
    name = symmetric_encryption_benches;
    config = Criterion::default().sample_size(100).measurement_time(Duration::from_secs(5));
    targets =
        bench_encrypt_aes_128_gcm,
        bench_encrypt_aes_256_gcm,
        bench_decrypt_aes_128_gcm,
        bench_decrypt_aes_256_gcm
);

// 批量测试 - 从 15 个样本减少到 5 个
criterion_group!(
    name = bulk_symmetric_encryption_benches;
    config = Criterion::default().sample_size(5).measurement_time(Duration::from_secs(5));
    targets =
        bench_encrypt_aes_256_gcm_100000,
        bench_decrypt_aes_256_gcm_100000
);

// RSA 密钥对创建测试 - 从 150 个样本减少到 20 个
criterion_group!(
    name = rsa_keypair_benches;
    config = Criterion::default().sample_size(20).measurement_time(Duration::from_secs(5));
    targets = bench_rsa_create_keypair,
);

// RSA 加密测试 - 从 1000 个样本减少到 100 个
criterion_group!(
    name = rsa_encryption_benches;
    config = Criterion::default().sample_size(100).measurement_time(Duration::from_secs(5));
    targets =
        bench_rsa_oaep_encrypt_2048,
        bench_rsa_oaep_encrypt_4096,
        bench_rsa_oaep_decrypt_2048,
        bench_rsa_oaep_decrypt_4096,
        bench_rsa_key_wrp_encrypt_2048,
        bench_rsa_key_wrp_encrypt_4096,
        bench_rsa_key_wrp_decrypt_2048,
        bench_rsa_key_wrp_decrypt_4096,
);

// 参数化测试 - 保持 10 个样本，减少测量时间
criterion_group!(
    name = symmetric_encryption_benches_parametrized;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(5));
    targets = bench_encrypt_aes_parametrized,
);
```

**预计加速效果**: 总时间从 ~15-20 分钟减少到 ~3-5 分钟

---

### 方案 2: 减少参数化测试的循环次数

修改 `symmetric_benches.rs` 中第 402 行的循环参数：

**原始配置**:
```rust
for num_plaintexts in [1, 10, 50, 100, 500, 1000] {  // 6 个值
    for num_bits in [128, 256] {  // 2 个值
```

**优化配置 A（保留关键数据点）**:
```rust
for num_plaintexts in [1, 100, 1000] {  // 3 个值（减少 50%）
    for num_bits in [128, 256] {  // 2 个值
```
- 测试数从 24 个减少到 12 个
- 时间减少约 50%

**优化配置 B（最小化测试）**:
```rust
for num_plaintexts in [1, 1000] {  // 2 个值（极端值）
    for num_bits in [256] {  // 1 个值（只测试 256 位）
```
- 测试数从 24 个减少到 4 个
- 时间减少约 83%

---

### 方案 3: 选择性运行测试组

如果只需要测试特定功能，可以注释掉不需要的测试组。

修改 `benches.rs` 第 47-54 行：

**只测试对称加密**:
```rust
criterion_main!(
    symmetric_key_benches,
    symmetric_encryption_benches,
    // bulk_symmetric_encryption_benches,  // 注释掉
    // rsa_keypair_benches,                // 注释掉
    // rsa_encryption_benches,             // 注释掉
    // symmetric_encryption_benches_parametrized  // 注释掉
);
```

**只测试 RSA**:
```rust
criterion_main!(
    // symmetric_key_benches,
    // symmetric_encryption_benches,
    // bulk_symmetric_encryption_benches,
    rsa_keypair_benches,
    rsa_encryption_benches,
    // symmetric_encryption_benches_parametrized
);
```

---

### 方案 4: 使用 Criterion 命令行参数

无需修改代码，直接通过命令行参数控制：

```bash
# 快速模式：减少样本数和预热时间
cargo bench -- --sample-size 10 --warm-up-time 1 --measurement-time 3

# 只运行特定的基准测试
cargo bench -- "AES 128"

# 只运行加密相关测试（使用正则表达式）
cargo bench -- encrypt

# 跳过某些测试
cargo bench -- --skip "100000"
```

---

## 推荐组合方案

### 日常开发（最快）
1. 使用方案 1 的快速配置
2. 使用方案 2 的优化配置 B
3. 注释掉批量测试和参数化测试

**预计总时间**: ~1-2 分钟

### 功能验证（平衡）
1. 使用方案 1 的快速配置
2. 使用方案 2 的优化配置 A
3. 保留所有测试组

**预计总时间**: ~3-5 分钟

### 性能测试（完整）
- 保持原始配置
- 用于 CI/CD 或发布前的完整性能评估

**预计总时间**: ~15-20 分钟

---

## 配置参数说明

### sample_size
- **含义**: Criterion 收集的样本数量
- **影响**: 数值越大，结果越精确，但时间越长
- **建议**:
  - 快速验证: 10-20
  - 常规测试: 50-100
  - 精确测试: 100-1000

### measurement_time
- **含义**: 每个基准测试的测量持续时间（秒）
- **影响**: 时间越长，结果越稳定
- **建议**:
  - 快速验证: 3-5 秒
  - 常规测试: 10 秒
  - 精确测试: 30-60 秒

### warm_up_time (通过命令行)
- **含义**: 预热时间，让系统稳定
- **默认值**: 3 秒
- **建议**: 快速测试可以减少到 1 秒

---

## 示例：完整的快速测试配置文件

创建 `benches/benches_quick.rs` 用于快速测试：

```rust
// 复制 benches.rs 的内容，但使用以下配置：

criterion_group!(
    name = symmetric_key_benches;
    config = Criterion::default().sample_size(20).measurement_time(Duration::from_secs(5));
    targets = bench_create_symmetric_key,
);

criterion_group!(
    name = symmetric_encryption_benches;
    config = Criterion::default().sample_size(100).measurement_time(Duration::from_secs(5));
    targets =
        bench_encrypt_aes_128_gcm,
        bench_decrypt_aes_128_gcm,  // 只测试一种密钥长度
);

// 其他类似调整...
```

然后运行：
```bash
cargo bench --bench benches_quick
```
