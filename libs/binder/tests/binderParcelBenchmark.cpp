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

  #BM_BoolVector/1                 41 ns      41 ns     16852379
  #BM_BoolVector/2                 52 ns      51 ns     13478806
  #BM_BoolVector/4                 70 ns      70 ns     10098673
  #BM_BoolVector/8                104 ns     104 ns      6673871
  #BM_BoolVector/16               182 ns     181 ns      3874059
  #BM_BoolVector/32               331 ns     330 ns      2118375
  #BM_BoolVector/64               599 ns     597 ns      1169860
  #BM_BoolVector/128             1154 ns    1151 ns       605930
  #BM_BoolVector/256             2269 ns    2262 ns       309434
  #BM_BoolVector/512             4487 ns    4474 ns       156446
  #BM_ByteVector/1                 42 ns      42 ns     16639649
  #BM_ByteVector/2                 42 ns      42 ns     16646455
  #BM_ByteVector/4                 38 ns      38 ns     18179683
  #BM_ByteVector/8                 38 ns      38 ns     18112687
  #BM_ByteVector/16                37 ns      37 ns     18495227
  #BM_ByteVector/32                38 ns      38 ns     17976282
  #BM_ByteVector/64                41 ns      41 ns     16962413
  #BM_ByteVector/128               53 ns      53 ns     13186076
  #BM_ByteVector/256               69 ns      69 ns     10032030
  #BM_ByteVector/512              107 ns     106 ns      6596484
  #BM_CharVector/1                 38 ns      38 ns     17924894
  #BM_CharVector/2                 40 ns      40 ns     17231655
  #BM_CharVector/4                 50 ns      50 ns     13783766
  #BM_CharVector/8                 67 ns      67 ns     10420915
  #BM_CharVector/16                96 ns      96 ns      7280532
  #BM_CharVector/32               156 ns     156 ns      4470607
  #BM_CharVector/64               282 ns     281 ns      2487577
  #BM_CharVector/128              523 ns     522 ns      1339785
  #BM_CharVector/256             1014 ns    1011 ns       690823
  #BM_CharVector/512             1987 ns    1981 ns       353952
  #BM_Int32Vector/1                41 ns      41 ns     16895162
  #BM_Int32Vector/2                41 ns      40 ns     17081086
  #BM_Int32Vector/4                41 ns      40 ns     17044754
  #BM_Int32Vector/8                41 ns      41 ns     16743816
  #BM_Int32Vector/16               42 ns      42 ns     16513036
  #BM_Int32Vector/32               54 ns      54 ns     12833772
  #BM_Int32Vector/64               69 ns      69 ns     10196179
  #BM_Int32Vector/128             107 ns     106 ns      6536930
  #BM_Int32Vector/256             179 ns     179 ns      3906841
  #BM_Int32Vector/512             323 ns     322 ns      2169006
  #BM_Int64Vector/1                41 ns      41 ns     17081815
  #BM_Int64Vector/2                41 ns      41 ns     17068845
  #BM_Int64Vector/4                41 ns      41 ns     16878196
  #BM_Int64Vector/8                42 ns      42 ns     16517574
  #BM_Int64Vector/16               54 ns      54 ns     12886116
  #BM_Int64Vector/32               69 ns      68 ns     10136564
  #BM_Int64Vector/64              107 ns     106 ns      6535792
  #BM_Int64Vector/128             179 ns     179 ns      3882847
  #BM_Int64Vector/256             324 ns     323 ns      2187471
  #BM_Int64Vector/512             609 ns     607 ns      1152363
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

  #BM_BoolVectorTemplate/1         51 ns      51 ns     13513677
  #BM_BoolVectorTemplate/2         59 ns      59 ns     11743356
  #BM_BoolVectorTemplate/4         76 ns      76 ns      9160356
  #BM_BoolVectorTemplate/8        108 ns     107 ns      6438036
  #BM_BoolVectorTemplate/16       180 ns     179 ns      3899552
  #BM_BoolVectorTemplate/32       319 ns     318 ns      2198650
  #BM_BoolVectorTemplate/64       567 ns     565 ns      1236284
  #BM_BoolVectorTemplate/128     1072 ns    1069 ns       653512
  #BM_BoolVectorTemplate/256     2092 ns    2085 ns       336039
  #BM_BoolVectorTemplate/512     4115 ns    4103 ns       170518
  #BM_ByteVectorTemplate/1         49 ns      49 ns     14262485
  #BM_ByteVectorTemplate/2         48 ns      48 ns     14337760
  #BM_ByteVectorTemplate/4         46 ns      46 ns     15013296
  #BM_ByteVectorTemplate/8         47 ns      47 ns     14729896
  #BM_ByteVectorTemplate/16        47 ns      47 ns     14826014
  #BM_ByteVectorTemplate/32        48 ns      47 ns     14610508
  #BM_ByteVectorTemplate/64        50 ns      50 ns     13828954
  #BM_ByteVectorTemplate/128       63 ns      63 ns     11065446
  #BM_ByteVectorTemplate/256       79 ns      79 ns      8863494
  #BM_ByteVectorTemplate/512      115 ns     115 ns      6028790
  #BM_CharVectorTemplate/1         48 ns      47 ns     14591601
  #BM_CharVectorTemplate/2         50 ns      50 ns     13787925
  #BM_CharVectorTemplate/4         57 ns      56 ns     12310794
  #BM_CharVectorTemplate/8         73 ns      72 ns      9600870
  #BM_CharVectorTemplate/16       100 ns     100 ns      7000554
  #BM_CharVectorTemplate/32       154 ns     154 ns      4537962
  #BM_CharVectorTemplate/64       270 ns     269 ns      2596911
  #BM_CharVectorTemplate/128      493 ns     491 ns      1423268
  #BM_CharVectorTemplate/256      941 ns     939 ns       742066
  #BM_CharVectorTemplate/512     1837 ns    1831 ns       382379
  #BM_Int32VectorTemplate/1        49 ns      48 ns     14282622
  #BM_Int32VectorTemplate/2        50 ns      50 ns     13973465
  #BM_Int32VectorTemplate/4        49 ns      48 ns     14289337
  #BM_Int32VectorTemplate/8        50 ns      50 ns     13822595
  #BM_Int32VectorTemplate/16       53 ns      53 ns     13156156
  #BM_Int32VectorTemplate/32       64 ns      63 ns     10953456
  #BM_Int32VectorTemplate/64       80 ns      80 ns      8738253
  #BM_Int32VectorTemplate/128     117 ns     116 ns      5997152
  #BM_Int32VectorTemplate/256     189 ns     189 ns      3692136
  #BM_Int32VectorTemplate/512     332 ns     331 ns      2108845
  #BM_Int64VectorTemplate/1        50 ns      49 ns     13991851
  #BM_Int64VectorTemplate/2        49 ns      49 ns     14272339
  #BM_Int64VectorTemplate/4        50 ns      50 ns     13826547
  #BM_Int64VectorTemplate/8        53 ns      53 ns     12876795
  #BM_Int64VectorTemplate/16       64 ns      63 ns     10954404
  #BM_Int64VectorTemplate/32       80 ns      80 ns      8723874
  #BM_Int64VectorTemplate/64      117 ns     116 ns      5988440
  #BM_Int64VectorTemplate/128     189 ns     189 ns      3695793
  #BM_Int64VectorTemplate/256     333 ns     332 ns      2107321
  #BM_Int64VectorTemplate/512     617 ns     616 ns      1129978
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
