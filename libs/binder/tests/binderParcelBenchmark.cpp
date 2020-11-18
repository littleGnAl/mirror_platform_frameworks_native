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

  #BM_BoolVector/1                 41 ns      41 ns     16787795
  #BM_BoolVector/2                 52 ns      52 ns     13405723
  #BM_BoolVector/4                 71 ns      70 ns      9997902
  #BM_BoolVector/8                105 ns     105 ns      6627494
  #BM_BoolVector/16               182 ns     181 ns      3866594
  #BM_BoolVector/32               333 ns     332 ns      2115683
  #BM_BoolVector/64               607 ns     605 ns      1162028
  #BM_BoolVector/128             1159 ns    1156 ns       604123
  #BM_BoolVector/256             2273 ns    2265 ns       309025
  #BM_BoolVector/512             4504 ns    4490 ns       155841
  #BM_ByteVector/1                 42 ns      42 ns     16681431
  #BM_ByteVector/2                 42 ns      42 ns     16624524
  #BM_ByteVector/4                 38 ns      38 ns     18163920
  #BM_ByteVector/8                 38 ns      38 ns     18272576
  #BM_ByteVector/16                37 ns      37 ns     18509451
  #BM_ByteVector/32                38 ns      38 ns     18033222
  #BM_ByteVector/64                41 ns      41 ns     16994305
  #BM_ByteVector/128               52 ns      52 ns     13244629
  #BM_ByteVector/256               69 ns      69 ns     10069672
  #BM_ByteVector/512              106 ns     106 ns      6592442
  #BM_CharVector/1                 38 ns      38 ns     18049356
  #BM_CharVector/2                 40 ns      40 ns     17155752
  #BM_CharVector/4                 51 ns      50 ns     13705055
  #BM_CharVector/8                 67 ns      67 ns     10380487
  #BM_CharVector/16                96 ns      96 ns      7264665
  #BM_CharVector/32               156 ns     155 ns      4457919
  #BM_CharVector/64               278 ns     277 ns      2528185
  #BM_CharVector/128              521 ns     519 ns      1339900
  #BM_CharVector/256             1007 ns    1003 ns       697022
  #BM_CharVector/512             1977 ns    1971 ns       354836
  #BM_Int32Vector/1                40 ns      40 ns     17242693
  #BM_Int32Vector/2                41 ns      41 ns     16990342
  #BM_Int32Vector/4                41 ns      41 ns     16781923
  #BM_Int32Vector/8                41 ns      41 ns     16909761
  #BM_Int32Vector/16               42 ns      42 ns     16473376
  #BM_Int32Vector/32               54 ns      53 ns     12961826
  #BM_Int32Vector/64               69 ns      69 ns     10094805
  #BM_Int32Vector/128             107 ns     107 ns      6487222
  #BM_Int32Vector/256             179 ns     178 ns      3923956
  #BM_Int32Vector/512             325 ns     324 ns      2160325
  #BM_Int64Vector/1                41 ns      41 ns     17060886
  #BM_Int64Vector/2                41 ns      41 ns     16990942
  #BM_Int64Vector/4                41 ns      41 ns     16722085
  #BM_Int64Vector/8                43 ns      42 ns     16340491
  #BM_Int64Vector/16               54 ns      54 ns     12957440
  #BM_Int64Vector/32               70 ns      70 ns     10065259
  #BM_Int64Vector/64              107 ns     106 ns      6532926
  #BM_Int64Vector/128             180 ns     179 ns      3894417
  #BM_Int64Vector/256             324 ns     323 ns      2162030
  #BM_Int64Vector/512             615 ns     613 ns      1144951
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

  #BM_BoolVectorTemplate/1         51 ns      50 ns     13737895
  #BM_BoolVectorTemplate/2         58 ns      58 ns     12058916
  #BM_BoolVectorTemplate/4         75 ns      75 ns      9287220
  #BM_BoolVectorTemplate/8        108 ns     107 ns      6502876
  #BM_BoolVectorTemplate/16       180 ns     180 ns      3898060
  #BM_BoolVectorTemplate/32       316 ns     315 ns      2221090
  #BM_BoolVectorTemplate/64       562 ns     560 ns      1248693
  #BM_BoolVectorTemplate/128     1061 ns    1058 ns       635549
  #BM_BoolVectorTemplate/256     2088 ns    2081 ns       336076
  #BM_BoolVectorTemplate/512     4137 ns    4124 ns       170192
  #BM_ByteVectorTemplate/1         48 ns      48 ns     14335130
  #BM_ByteVectorTemplate/2         48 ns      48 ns     14343414
  #BM_ByteVectorTemplate/4         47 ns      47 ns     14870290
  #BM_ByteVectorTemplate/8         47 ns      47 ns     14867600
  #BM_ByteVectorTemplate/16        46 ns      46 ns     15107946
  #BM_ByteVectorTemplate/32        47 ns      47 ns     14756563
  #BM_ByteVectorTemplate/64        51 ns      51 ns     13737007
  #BM_ByteVectorTemplate/128       62 ns      62 ns     11200925
  #BM_ByteVectorTemplate/256       78 ns      78 ns      8949482
  #BM_ByteVectorTemplate/512      114 ns     114 ns      6110035
  #BM_CharVectorTemplate/1         47 ns      47 ns     14799844
  #BM_CharVectorTemplate/2         50 ns      50 ns     13911043
  #BM_CharVectorTemplate/4         57 ns      56 ns     12303454
  #BM_CharVectorTemplate/8         71 ns      71 ns      9772115
  #BM_CharVectorTemplate/16        98 ns      98 ns      7087131
  #BM_CharVectorTemplate/32       154 ns     153 ns      4542505
  #BM_CharVectorTemplate/64       270 ns     270 ns      2591296
  #BM_CharVectorTemplate/128      494 ns     492 ns      1420812
  #BM_CharVectorTemplate/256      926 ns     923 ns       760580
  #BM_CharVectorTemplate/512     1794 ns    1788 ns       390865
  #BM_Int32VectorTemplate/1        49 ns      49 ns     14233275
  #BM_Int32VectorTemplate/2        49 ns      49 ns     14129688
  #BM_Int32VectorTemplate/4        48 ns      48 ns     14415518
  #BM_Int32VectorTemplate/8        50 ns      50 ns     13892220
  #BM_Int32VectorTemplate/16       53 ns      53 ns     13142429
  #BM_Int32VectorTemplate/32       62 ns      62 ns     11242298
  #BM_Int32VectorTemplate/64       79 ns      79 ns      8808004
  #BM_Int32VectorTemplate/128     116 ns     116 ns      6032608
  #BM_Int32VectorTemplate/256     187 ns     186 ns      3749650
  #BM_Int32VectorTemplate/512     331 ns     330 ns      2120664
  #BM_Int64VectorTemplate/1        49 ns      49 ns     14117943
  #BM_Int64VectorTemplate/2        48 ns      48 ns     14441385
  #BM_Int64VectorTemplate/4        50 ns      50 ns     13878849
  #BM_Int64VectorTemplate/8        53 ns      53 ns     13119223
  #BM_Int64VectorTemplate/16       62 ns      62 ns     11179876
  #BM_Int64VectorTemplate/32       79 ns      79 ns      8824114
  #BM_Int64VectorTemplate/64      116 ns     116 ns      6024723
  #BM_Int64VectorTemplate/128     187 ns     187 ns      3741761
  #BM_Int64VectorTemplate/256     331 ns     330 ns      2116466
  #BM_Int64VectorTemplate/512     619 ns     617 ns      1134084
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
