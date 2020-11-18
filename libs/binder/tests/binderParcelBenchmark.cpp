/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <binder/Parcel.h>
#include <benchmark/benchmark.h>

// Usage: atest binderParcelBenchmark

// For static assert(false) we need a template version to avoid early failure.
// See: https://stackoverflow.com/questions/51523965/template-dependent-false
template <typename T>
constexpr bool dependent_false_v = false;

template <template <typename ...> class V, typename T, typename... Args>
void writeVector(android::Parcel &p, const V<T, Args...> &v) {
    if constexpr (std::is_same_v<T, bool>) {
        p.writeBoolVector(v);
    } else if constexpr (std::is_same_v<T, uint8_t>) {
        p.writeByteVector(v);
    } else if constexpr (std::is_same_v<T, char16_t>) {
        p.writeCharVector(v);
    } else if constexpr (std::is_same_v<T, int32_t>) {
        p.writeInt32Vector(v);
    } else if constexpr (std::is_same_v<T, int64_t>) {
        p.writeInt64Vector(v);
    } else {
        static_assert(dependent_false_v<V<T>>);
    }
}

template <template <typename ...> class V, typename T, typename... Args>
void readVector(android::Parcel &p, V<T, Args...> *v) {
    if constexpr (std::is_same_v<T, bool>) {
        p.readBoolVector(v);
    } else if constexpr (std::is_same_v<T, uint8_t>) {
        p.readByteVector(v);
    } else if constexpr (std::is_same_v<T, char16_t>) {
        p.readCharVector(v);
    } else if constexpr (std::is_same_v<T, int32_t>) {
        p.readInt32Vector(v);
    } else if constexpr (std::is_same_v<T, int64_t>) {
        p.readInt64Vector(v);
    } else {
        static_assert(dependent_false_v<V<T>>);
    }
}

// Construct a series of args { 1 << 0, 1 << 1, ..., 1 << 10 }
static void VectorArgs(benchmark::internal::Benchmark* b) {
    for (int i = 0; i < 10; ++i) {
        b->Args({1 << i});
    }
}

enum MODE_FLAG {
    MODE_FLAG_NONE = 0,
    MODE_FLAG_TEMPLATE = (1 << 0),
};

template <typename T, enum MODE_FLAG Mode = MODE_FLAG_NONE>
static void BM_ParcelVector(benchmark::State& state) {
    const size_t elements = state.range(0);

    std::vector<T> v1(elements);
    std::vector<T> v2(elements);
    android::Parcel p;
    while (state.KeepRunning()) {
        p.setDataPosition(0);
        if constexpr ((Mode & MODE_FLAG_TEMPLATE) != 0) {
            p.writeData(v1);
        } else  /* constexpr */ {
            writeVector(p, v1);
        }

        p.setDataPosition(0);
        if constexpr ((Mode & MODE_FLAG_TEMPLATE) != 0) {
            p.readData(&v2);
        } else /* constexpr */ {
            readVector(p, &v2);
        }

        benchmark::DoNotOptimize(v2[0]);
        benchmark::ClobberMemory();
    }
    state.SetComplexityN(elements);
}

/*
  Parcel vector write than read.
  The read and write vectors are fixed, no resizing required.

  Results on Crosshatch Pixel 3XL

  #BM_BoolVector/1                   40 ns      40 ns     17137781
  #BM_BoolVector/2                   51 ns      51 ns     13636972
  #BM_BoolVector/4                   69 ns      69 ns      9918944
  #BM_BoolVector/8                  104 ns     104 ns      6710353
  #BM_BoolVector/16                 183 ns     182 ns      3835665
  #BM_BoolVector/32                 335 ns     334 ns      2094514
  #BM_BoolVector/64                 607 ns     605 ns      1154455
  #BM_BoolVector/128               1160 ns    1157 ns       604437
  #BM_BoolVector/256               2274 ns    2267 ns       308954
  #BM_BoolVector/512               4491 ns    4478 ns       156368
  #BM_ByteVector/1                   39 ns      39 ns     17933684
  #BM_ByteVector/2                   39 ns      39 ns     17921291
  #BM_ByteVector/4                   37 ns      37 ns     18618946
  #BM_ByteVector/8                   37 ns      37 ns     18541785
  #BM_ByteVector/16                  36 ns      36 ns     19169622
  #BM_ByteVector/32                  37 ns      37 ns     18591571
  #BM_ByteVector/64                  39 ns      39 ns     17824057
  #BM_ByteVector/128                 51 ns      51 ns     13587053
  #BM_ByteVector/256                 67 ns      67 ns     10344541
  #BM_ByteVector/512                105 ns     105 ns      6625873
  #BM_CharVector/1                   39 ns      39 ns     17671485
  #BM_CharVector/2                   40 ns      40 ns     17314832
  #BM_CharVector/4                   50 ns      50 ns     10000000
  #BM_CharVector/8                   66 ns      66 ns     10534681
  #BM_CharVector/16                  96 ns      95 ns      7303046
  #BM_CharVector/32                 156 ns     155 ns      4487311
  #BM_CharVector/64                 277 ns     276 ns      2519769
  #BM_CharVector/128                521 ns     520 ns      1346295
  #BM_CharVector/256               1007 ns    1004 ns       697298
  #BM_CharVector/512               1977 ns    1971 ns       355323
  #BM_Int32Vector/1                  39 ns      38 ns     17946993
  #BM_Int32Vector/2                  39 ns      39 ns     17922573
  #BM_Int32Vector/4                  38 ns      38 ns     18099786
  #BM_Int32Vector/8                  39 ns      39 ns     17772561
  #BM_Int32Vector/16                 40 ns      40 ns     17510684
  #BM_Int32Vector/32                 53 ns      52 ns     13236229
  #BM_Int32Vector/64                 68 ns      68 ns     10236209
  #BM_Int32Vector/128               106 ns     105 ns      6610647
  #BM_Int32Vector/256               178 ns     178 ns      3919426
  #BM_Int32Vector/512               321 ns     320 ns      2183026
  #BM_Int64Vector/1                  39 ns      39 ns     17882427
  #BM_Int64Vector/2                  38 ns      38 ns     18129104
  #BM_Int64Vector/4                  39 ns      39 ns     17739630
  #BM_Int64Vector/8                  41 ns      41 ns     16911019
  #BM_Int64Vector/16                 52 ns      52 ns     13261684
  #BM_Int64Vector/32                 68 ns      68 ns     10218148
  #BM_Int64Vector/64                106 ns     105 ns      6610019
  #BM_Int64Vector/128               179 ns     178 ns      3924231
  #BM_Int64Vector/256               322 ns     321 ns      2178794
  #BM_Int64Vector/512               600 ns     598 ns      1161070
*/

static void BM_BoolVector(benchmark::State& state) {
    BM_ParcelVector<bool>(state);
}

static void BM_ByteVector(benchmark::State& state) {
    BM_ParcelVector<uint8_t>(state);
}

static void BM_CharVector(benchmark::State& state) {
    BM_ParcelVector<char16_t>(state);
}

static void BM_Int32Vector(benchmark::State& state) {
    BM_ParcelVector<int32_t>(state);
}

static void BM_Int64Vector(benchmark::State& state) {
    BM_ParcelVector<int64_t>(state);
}

BENCHMARK(BM_BoolVector)->Apply(VectorArgs);
BENCHMARK(BM_ByteVector)->Apply(VectorArgs);
BENCHMARK(BM_CharVector)->Apply(VectorArgs);
BENCHMARK(BM_Int32Vector)->Apply(VectorArgs);
BENCHMARK(BM_Int64Vector)->Apply(VectorArgs);

/*
  Parcel vector write than read.
  The read and write vectors are fixed, no resizing required.

  Call through templated methods writeData and readData.

  Results on crosshatch Pixel 3XL

  #BM_BoolVectorTemplate/1           47 ns      47 ns     14751622
  #BM_BoolVectorTemplate/2           54 ns      54 ns     12850448
  #BM_BoolVectorTemplate/4           71 ns      70 ns      9857723
  #BM_BoolVectorTemplate/8          102 ns     102 ns      6824632
  #BM_BoolVectorTemplate/16         175 ns     174 ns      4002468
  #BM_BoolVectorTemplate/32         308 ns     307 ns      2270301
  #BM_BoolVectorTemplate/64         553 ns     551 ns      1268675
  #BM_BoolVectorTemplate/128       1055 ns    1052 ns       664597
  #BM_BoolVectorTemplate/256       2068 ns    2061 ns       339903
  #BM_BoolVectorTemplate/512       4076 ns    4063 ns       172063
  #BM_ByteVectorTemplate/1           47 ns      47 ns     14813683
  #BM_ByteVectorTemplate/2           47 ns      47 ns     14789782
  #BM_ByteVectorTemplate/4           45 ns      44 ns     15565225
  #BM_ByteVectorTemplate/8           45 ns      45 ns     15504269
  #BM_ByteVectorTemplate/16          45 ns      45 ns     15494388
  #BM_ByteVectorTemplate/32          45 ns      45 ns     15289214
  #BM_ByteVectorTemplate/64          48 ns      48 ns     14575036
  #BM_ByteVectorTemplate/128         59 ns      59 ns     11744084
  #BM_ByteVectorTemplate/256         75 ns      75 ns      9273781
  #BM_ByteVectorTemplate/512        113 ns     112 ns      6206720
  #BM_CharVectorTemplate/1           42 ns      42 ns     16498231
  #BM_CharVectorTemplate/2           46 ns      45 ns     15211036
  #BM_CharVectorTemplate/4           53 ns      53 ns     13154238
  #BM_CharVectorTemplate/8           68 ns      68 ns     10316797
  #BM_CharVectorTemplate/16          95 ns      95 ns      7337485
  #BM_CharVectorTemplate/32         151 ns     151 ns      4625388
  #BM_CharVectorTemplate/64         265 ns     264 ns      2661223
  #BM_CharVectorTemplate/128        487 ns     486 ns      1427737
  #BM_CharVectorTemplate/256        922 ns     920 ns       761938
  #BM_CharVectorTemplate/512       1850 ns    1844 ns       380446
  #BM_Int32VectorTemplate/1          47 ns      47 ns     14832443
  #BM_Int32VectorTemplate/2          50 ns      50 ns     10000000
  #BM_Int32VectorTemplate/4          47 ns      47 ns     14917370
  #BM_Int32VectorTemplate/8          49 ns      49 ns     14288600
  #BM_Int32VectorTemplate/16         51 ns      51 ns     13745031
  #BM_Int32VectorTemplate/32         60 ns      60 ns     11524966
  #BM_Int32VectorTemplate/64         77 ns      76 ns      9102535
  #BM_Int32VectorTemplate/128       113 ns     113 ns      6172403
  #BM_Int32VectorTemplate/256       186 ns     185 ns      3759303
  #BM_Int32VectorTemplate/512       330 ns     329 ns      2113139
  #BM_Int64VectorTemplate/1          50 ns      50 ns     13721651
  #BM_Int64VectorTemplate/2          47 ns      46 ns     14911751
  #BM_Int64VectorTemplate/4          49 ns      48 ns     14260570
  #BM_Int64VectorTemplate/8          51 ns      51 ns     13712034
  #BM_Int64VectorTemplate/16         60 ns      60 ns     11511186
  #BM_Int64VectorTemplate/32         76 ns      76 ns      9118925
  #BM_Int64VectorTemplate/64        113 ns     113 ns      6164433
  #BM_Int64VectorTemplate/128       186 ns     186 ns      3759336
  #BM_Int64VectorTemplate/256       330 ns     329 ns      2124944
  #BM_Int64VectorTemplate/512       612 ns     610 ns      1141556
*/

static void BM_BoolVectorTemplate(benchmark::State& state) {
    BM_ParcelVector<bool, MODE_FLAG_TEMPLATE>(state);
}

static void BM_ByteVectorTemplate(benchmark::State& state) {
    BM_ParcelVector<uint8_t, MODE_FLAG_TEMPLATE>(state);
}

static void BM_CharVectorTemplate(benchmark::State& state) {
    BM_ParcelVector<char16_t, MODE_FLAG_TEMPLATE>(state);
}

static void BM_Int32VectorTemplate(benchmark::State& state) {
    BM_ParcelVector<int32_t, MODE_FLAG_TEMPLATE>(state);
}

static void BM_Int64VectorTemplate(benchmark::State& state) {
    BM_ParcelVector<int64_t, MODE_FLAG_TEMPLATE>(state);
}

BENCHMARK(BM_BoolVectorTemplate)->Apply(VectorArgs);
BENCHMARK(BM_ByteVectorTemplate)->Apply(VectorArgs);
BENCHMARK(BM_CharVectorTemplate)->Apply(VectorArgs);
BENCHMARK(BM_Int32VectorTemplate)->Apply(VectorArgs);
BENCHMARK(BM_Int64VectorTemplate)->Apply(VectorArgs);

BENCHMARK_MAIN();
