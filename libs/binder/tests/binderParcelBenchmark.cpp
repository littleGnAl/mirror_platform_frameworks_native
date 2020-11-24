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
        // TODO: assert
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
        // TODO: assert
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
    MODE_FLAG_VECTOR_WRITE_ALLOC = (1 << 0),
};

template <typename T, enum MODE_FLAG Mode = MODE_FLAG_NONE>
static void BM_ParcelVector(benchmark::State& state) {
    const size_t elements = state.range(0);

    std::vector<T> v1(elements);
    std::vector<T> v2(elements);
    android::Parcel p;
    while (state.KeepRunning()) {
        p.setDataPosition(0);

        if constexpr ((Mode & MODE_FLAG_VECTOR_WRITE_ALLOC) != 0) {
            writeVector(p, std::vector<T>(v1.begin(), v1.end()));
        } else  /* constexpr */ {
            writeVector(p, v1);
        }

        p.setDataPosition(0);
        readVector(p, &v2);

        benchmark::DoNotOptimize(v2[0]);
        benchmark::ClobberMemory();
    }
    state.SetComplexityN(elements);
}

/*
  Parcel vector write than read.
  The read and write vectors are fixed, no resizing required.

  Results on Crosshatch Pixel 3XL

  #BM_BoolVector/1              40 ns      40 ns     17182394
  #BM_BoolVector/2              46 ns      46 ns     14989422
  #BM_BoolVector/4              67 ns      66 ns     10919166
  #BM_BoolVector/8             113 ns     113 ns      5936338
  #BM_BoolVector/16            179 ns     178 ns      3912380
  #BM_BoolVector/32            329 ns     328 ns      2123368
  #BM_BoolVector/64            614 ns     613 ns      1141812
  #BM_BoolVector/128          1205 ns    1201 ns       581863
  #BM_BoolVector/256          2384 ns    2376 ns       294609
  #BM_BoolVector/512          4712 ns    4697 ns       148909
  #BM_ByteVector/1              53 ns      52 ns     13190565
  #BM_ByteVector/2              53 ns      52 ns     13238600
  #BM_ByteVector/4              50 ns      50 ns     13910610
  #BM_ByteVector/8              50 ns      50 ns     13880842
  #BM_ByteVector/16             50 ns      50 ns     13955011
  #BM_ByteVector/32             51 ns      51 ns     13667509
  #BM_ByteVector/64             53 ns      53 ns     13011191
  #BM_ByteVector/128            64 ns      64 ns     10821745
  #BM_ByteVector/256            82 ns      81 ns      8532390
  #BM_ByteVector/512           119 ns     119 ns      5863150
  #BM_CharVector/1              32 ns      32 ns     21801728
  #BM_CharVector/2              38 ns      38 ns     18042947
  #BM_CharVector/4              53 ns      53 ns     13088993
  #BM_CharVector/8              82 ns      82 ns      8494995
  #BM_CharVector/16            166 ns     166 ns      4214415
  #BM_CharVector/32            279 ns     278 ns      2514035
  #BM_CharVector/64            516 ns     515 ns      1355715
  #BM_CharVector/128           990 ns     987 ns       708800
  #BM_CharVector/256          1940 ns    1934 ns       361514
  #BM_CharVector/512          3835 ns    3824 ns       182963
  #BM_Int32Vector/1             31 ns      31 ns     22001800
  #BM_Int32Vector/2             39 ns      39 ns     17862253
  #BM_Int32Vector/4             52 ns      52 ns     13261291
  #BM_Int32Vector/8             79 ns      79 ns      8784882
  #BM_Int32Vector/16           159 ns     159 ns      4392584
  #BM_Int32Vector/32           261 ns     260 ns      2689754
  #BM_Int32Vector/64           483 ns     482 ns      1449260
  #BM_Int32Vector/128          919 ns     916 ns       763385
  #BM_Int32Vector/256         1811 ns    1805 ns       387517
  #BM_Int32Vector/512         3586 ns    3575 ns       195929
  #BM_Int64Vector/1             31 ns      31 ns     22528540
  #BM_Int64Vector/2             39 ns      39 ns     17696383
  #BM_Int64Vector/4             53 ns      53 ns     13108217
  #BM_Int64Vector/8             81 ns      81 ns      8572063
  #BM_Int64Vector/16           167 ns     167 ns      4185350
  #BM_Int64Vector/32           280 ns     279 ns      2506180
  #BM_Int64Vector/64           523 ns     522 ns      1342483
  #BM_Int64Vector/128          998 ns     995 ns       703750
  #BM_Int64Vector/256         1935 ns    1929 ns       362350
  #BM_Int64Vector/512         3831 ns    3819 ns       183145
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
  Parcel vector write then read.
  Vector allocation on the write side for Parceling data.
  The vector on the read side is preallocated.

  Results on Crosshatch Pixel 3XL

  #BM_BoolVectorWriteAlloc/1        155 ns     155 ns      4491048
  #BM_BoolVectorWriteAlloc/2        161 ns     160 ns      4336662
  #BM_BoolVectorWriteAlloc/4        175 ns     175 ns      4001651
  #BM_BoolVectorWriteAlloc/8        223 ns     222 ns      3142640
  #BM_BoolVectorWriteAlloc/16       290 ns     289 ns      2421784
  #BM_BoolVectorWriteAlloc/32       437 ns     435 ns      1602792
  #BM_BoolVectorWriteAlloc/64       712 ns     709 ns       987056
  #BM_BoolVectorWriteAlloc/128     1276 ns    1272 ns       552484
  #BM_BoolVectorWriteAlloc/256     2389 ns    2381 ns       293173
  #BM_BoolVectorWriteAlloc/512     4652 ns    4637 ns       151683
  #BM_ByteVectorWriteAlloc/1        140 ns     139 ns      5013661
  #BM_ByteVectorWriteAlloc/2        143 ns     143 ns      4897665
  #BM_ByteVectorWriteAlloc/4        144 ns     143 ns      4827786
  #BM_ByteVectorWriteAlloc/8        150 ns     150 ns      4618971
  #BM_ByteVectorWriteAlloc/16       172 ns     172 ns      4077113
  #BM_ByteVectorWriteAlloc/32       221 ns     221 ns      3188958
  #BM_ByteVectorWriteAlloc/64       304 ns     303 ns      2298310
  #BM_ByteVectorWriteAlloc/128      485 ns     484 ns      1445993
  #BM_ByteVectorWriteAlloc/256      854 ns     852 ns       820247
  #BM_ByteVectorWriteAlloc/512     1570 ns    1565 ns       447304
  #BM_CharVectorWriteAlloc/1        117 ns     116 ns      5991369
  #BM_CharVectorWriteAlloc/2        123 ns     122 ns      5700863
  #BM_CharVectorWriteAlloc/4        141 ns     141 ns      4962217
  #BM_CharVectorWriteAlloc/8        180 ns     179 ns      3895545
  #BM_CharVectorWriteAlloc/16       282 ns     282 ns      2491407
  #BM_CharVectorWriteAlloc/32       433 ns     432 ns      1613708
  #BM_CharVectorWriteAlloc/64       745 ns     742 ns       939700
  #BM_CharVectorWriteAlloc/128     1381 ns    1376 ns       510361
  #BM_CharVectorWriteAlloc/256     2627 ns    2619 ns       266567
  #BM_CharVectorWriteAlloc/512     5129 ns    5112 ns       136857
  #BM_Int32VectorWriteAlloc/1       116 ns     116 ns      6000447
  #BM_Int32VectorWriteAlloc/2       123 ns     122 ns      5696006
  #BM_Int32VectorWriteAlloc/4       141 ns     140 ns      4961973
  #BM_Int32VectorWriteAlloc/8       179 ns     179 ns      3899442
  #BM_Int32VectorWriteAlloc/16      285 ns     284 ns      2491435
  #BM_Int32VectorWriteAlloc/32      429 ns     428 ns      1626268
  #BM_Int32VectorWriteAlloc/64      755 ns     752 ns       930380
  #BM_Int32VectorWriteAlloc/128    1377 ns    1373 ns       509152
  #BM_Int32VectorWriteAlloc/256    2635 ns    2627 ns       266871
  #BM_Int32VectorWriteAlloc/512    5137 ns    5120 ns       136552
  #BM_Int64VectorWriteAlloc/1       116 ns     115 ns      6041419
  #BM_Int64VectorWriteAlloc/2       123 ns     122 ns      5657709
  #BM_Int64VectorWriteAlloc/4       143 ns     142 ns      4893129
  #BM_Int64VectorWriteAlloc/8       182 ns     182 ns      3843935
  #BM_Int64VectorWriteAlloc/16      284 ns     283 ns      2480437
  #BM_Int64VectorWriteAlloc/32      463 ns     461 ns      1533033
  #BM_Int64VectorWriteAlloc/64      786 ns     783 ns       890423
  #BM_Int64VectorWriteAlloc/128    1438 ns    1433 ns       487337
  #BM_Int64VectorWriteAlloc/256    2746 ns    2736 ns       256562
  #BM_Int64VectorWriteAlloc/512    5334 ns    5316 ns       131506
*/

static void BM_BoolVectorWriteAlloc(benchmark::State& state) {
    BM_ParcelVector<bool, MODE_FLAG_VECTOR_WRITE_ALLOC>(state);
}

static void BM_ByteVectorWriteAlloc(benchmark::State& state) {
    BM_ParcelVector<uint8_t, MODE_FLAG_VECTOR_WRITE_ALLOC>(state);
}

static void BM_CharVectorWriteAlloc(benchmark::State& state) {
    BM_ParcelVector<char16_t, MODE_FLAG_VECTOR_WRITE_ALLOC>(state);
}

static void BM_Int32VectorWriteAlloc(benchmark::State& state) {
    BM_ParcelVector<int32_t, MODE_FLAG_VECTOR_WRITE_ALLOC>(state);
}

static void BM_Int64VectorWriteAlloc(benchmark::State& state) {
    BM_ParcelVector<int64_t, MODE_FLAG_VECTOR_WRITE_ALLOC>(state);
}

BENCHMARK(BM_BoolVectorWriteAlloc)->Apply(VectorArgs);
BENCHMARK(BM_ByteVectorWriteAlloc)->Apply(VectorArgs);
BENCHMARK(BM_CharVectorWriteAlloc)->Apply(VectorArgs);
BENCHMARK(BM_Int32VectorWriteAlloc)->Apply(VectorArgs);
BENCHMARK(BM_Int64VectorWriteAlloc)->Apply(VectorArgs);

BENCHMARK_MAIN();
