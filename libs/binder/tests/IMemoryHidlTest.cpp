#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <iomanip>
#include <iostream>
#include <tuple>
#include <vector>

#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fstream>

#include <android/hardware/tests/memory/1.0/IMemoryTest.h>
#include <android/hidl/allocator/1.1/IAllocator.h>
#include <android/hidl/memory/1.0/IMemory.h>
#include <cutils/ashmem.h>

#include <hidl/HidlSupport.h>
#include <hidl/LegacySupport.h>
#include <hidlmemory/MemoryDealer.h>
#include <hidlmemory/mapping.h>

using namespace std;
using namespace android;

using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_memblk;
using ::android::hardware::HidlMemory;
using ::android::hardware::registerPassthroughServiceImplementation;
using ::android::hardware::createHidlMemory;
using ::android::hardware::tests::memory::V1_0::IMemoryTest;
using ::android::hidl::allocator::V1_1::IAllocator;
using ::android::hidl::memory::V1_0::IMemory;
using ::android::hardware::Return;

#define ASSERT(cond)                                                                              \
    do {                                                                                          \
        if (!(cond)) {                                                                            \
            cerr << __func__ << ":" << __LINE__ << " condition:" << #cond << " failed\n" << endl; \
            cleanup();                                                                            \
            exit(EXIT_FAILURE);                                                                   \
        }                                                                                         \
    } while (0)

static void cleanup(void);

#include "PerfTest.h"

static vector<sp<Pipe>> children;

/**
 *    Start a MemoryTest process and register as an IMemoryTest service.
 *  The IMemoryTest simulates a hardware interface that pass hidl_memory.
 */
static void startMemoryTest() {
    auto pipe_pair = Pipe::createPipePair();
    pid_t pid = fork();
    if (pid) {
        sp<Pipe> service = get<0>(pipe_pair);
        service->wait();
        cout << "MemoryTest: initialized" << endl;
        children.push_back(service);
    } else {
        sp<Pipe> main = get<1>(pipe_pair);
        if (registerPassthroughServiceImplementation<IMemoryTest>("memory") != ::android::OK) {
            cerr << "Failed to register service IMemoryTest" << endl;
            exit(-1);
        }
        main->signal();
        main->wait();
        exit(0);
    }
}

static void test1() {
    auto pipe_pair = Pipe::createPipePair();
    pid_t pid = fork();
    if (pid) {
        cout << "Test: hidl_memory between processes: ";
        sp<Pipe> client = get<0>(pipe_pair);
        sp<IAllocator> allocator = IAllocator::getService("ashmem", false);
        ASSERT(allocator->isRemote());

        hidl_memory mem, mem2, mem3;
        bool success;
        // test allocation
        allocator->allocate(2048, [&mem, &success](bool _success, const hidl_memory& _mem) {
            mem = _mem;
            success = _success;
        });
        ASSERT(success);
        sp<IMemoryTest> mt = IMemoryTest::getService("memory");
        ASSERT(mt != nullptr);
        ASSERT(mem.handle() != nullptr);

        // test the hidl_memory argument passing, which dup the fd
        int fd1 = mem.handle()->data[0];
        mt->haveSomeMemory(mem, [&mem2](const hidl_memory& _mem) { mem2 = _mem; });
        ASSERT(mem2.handle() != nullptr);
        int fd2 = mem2.handle()->data[0];
        ASSERT(fd1 != fd2);

        // test the hild_meory argument passing, , which dup the fd
        mt->set(mem2);
        mt->get([&mem3](const hidl_memory& _mem) { mem3 = _mem; });
        ASSERT(mem3.handle() != nullptr);
        int fd3 = mem3.handle()->data[0];
        ASSERT(fd3 != fd2);

        // fill the pattern and signal client to check
        sp<IMemory> im = mapMemory(mem);
        ASSERT(im != nullptr);
        void* p = im->getPointer();
        memset(p, 0xbf, 20);
        client->signal();
        int status;
        wait(&status);
        ASSERT(status == 0);
        cout << " OK" << endl;
    } else {
        // client process to check the memory against a known pattarn
        sp<Pipe> server = get<1>(pipe_pair);
        server->wait();
        sp<IMemoryTest> mt = IMemoryTest::getService("memory");
        hidl_memory mem;
        ASSERT(mt != nullptr);
        mt->get([&mem](const hidl_memory& _mem) { mem = _mem; });
        sp<IMemory> im = mapMemory(mem);
        ASSERT(im != nullptr);
        void* p = im->getPointer();
        char* pc = static_cast<char*>(p);
        for (int i = 0; i < 20; i++) {
            ASSERT(pc[i] == 0xbf);
        }
        exit(0);
    }
}

static void test2() {
    cout << "Test: android::hardware::HidlMemory: ";
    HidlMemory o = createHidlMemory(888, 256);
    ASSERT(o != nullptr);
    ASSERT(o->name() == "ashmem");
    ASSERT(o->handle() != nullptr);
    ASSERT(hidl_memory::valid(*o));
    cout << "OK" << endl;
}

static void test3() {
    cout << "Test: IAllocator1.1 add /get/ del: ";
    sp<IAllocator> allocator = IAllocator::getService("ashmem", false);

    hidl_memory mem, memb;
    bool success;
    // test IAllocator1.1 add /get/ del
    allocator->allocate(2048, [&mem, &success](bool _success, const hidl_memory& _mem) {
        mem = _mem;
        success = _success;
    });
    ASSERT(success);
    sp<IMemory> im = mapMemory(mem);
    ASSERT(im != nullptr);
    void* p = im->getPointer();
    memset(p, 0xbf, 20);

    // add
    auto retAdd = allocator->add(mem);
    ASSERT(retAdd.isOk());
    int64_t heapID = retAdd;

    // get
    auto retGet = allocator->get(heapID, [&memb](const hidl_memory& _mem) {
        memb = _mem;
    });
    ASSERT(retGet.isOk());
    ASSERT(hidl_memory::valid(memb));
    sp<IMemory> im2 = mapMemory(memb);
    ASSERT(im2 != nullptr);
    p = im->getPointer();
    char* pc = static_cast<char*>(p);
    for (int i = 0; i < 20; i++) {
        ASSERT(pc[i] == 0xbf);
    }
    // del
    auto retDel = allocator->del(heapID);
    ASSERT(retDel.isOk());
    cout << "OK" << endl;
}

static void test4() {
    cout << "Test: IMapper 1.1 ";
    sp<IAllocator> allocator = IAllocator::getService("ashmem", false);

    hidl_memory mem, memb;
    bool success;
    // test IAllocator1.1 add /get/ del
    allocator->allocate(2048, [&mem, &success](bool _success, const hidl_memory& _mem) {
        mem = _mem;
        success = _success;
    });
    ASSERT(success);
    sp<IMemory> im = mapMemory(mem);
    ASSERT(im != nullptr);
    void* p = im->getPointer();
    char* pc = reinterpret_cast<char*>(p);
    memset(pc+0x00, 0x11, 0x10);
    memset(pc+0x10, 0x22, 0x10);
    memset(pc+0x20, 0x33, 0x10);

    auto retAdd = allocator->add(mem);
    ASSERT(retAdd.isOk());
    int64_t heapID = retAdd;

    hidl_memblk blk1 = {heapID, 0x10, 0x00};
    hidl_memblk blk2 = {heapID, 0x10, 0x10};
    hidl_memblk blk3 = {heapID, 0x10, 0x20};

    sp<IMemory> m1 = mapMemory(blk1);
    ASSERT(m1 != nullptr);
    for (int i = 0; i < 0x10; i++) {
        void* p = m1->getPointer();
        char* pc = static_cast<char*>(p);
        ASSERT(pc[i] == 0x11);
    }

    sp<IMemory> m2 = mapMemory(blk2);
    for (int i = 0; i < 0x10; i++) {
        void* p = m2->getPointer();
        char* pc = static_cast<char*>(p);
        ASSERT(pc[i] == 0x22);
    }
    sp<IMemory> m3 = mapMemory(blk3);
    for (int i = 0; i < 0x10; i++) {
        void* p = m3->getPointer();
        char* pc = static_cast<char*>(p);
        ASSERT(pc[i] == 0x33);
    }

    auto retDel = allocator->del(heapID);
    ASSERT(retDel.isOk());
    cout << "OK" << endl;
}
using ::android::hardware::MemoryDealer;
using ::android::hidl::memory::V1_1::memblk;
static void test5() {
    cout << "Test: MemoryDealer ";
    sp<IAllocator> allocator = IAllocator::getService("ashmem", false);

    hidl_memory mem, memb;
    bool success;
    // test MemoryDealer
    allocator->allocate(2048, [&mem, &success](bool _success, const hidl_memory& _mem) {
        mem = _mem;
        success = _success;
    });
    ASSERT(success);

    allocator->allocate(4096, [&memb, &success](bool _success, const hidl_memory& _mem) {
        memb = _mem;
        success = _success;
    });
    ASSERT(success);

    sp<MemoryDealer> md = MemoryDealer::getInstance(mem);
    ASSERT(md == nullptr);

    md = MemoryDealer::getInstance(memb);
    ASSERT(md != nullptr);

    ASSERT(md->getMemoryHeap()->getSize() == 4096);
    memblk blk = md->allocate(1024);
    ASSERT(MemoryDealer::isOk(blk));
    memblk blk2 = md->allocate(2048);
    ASSERT(MemoryDealer::isOk(blk2));
    memblk blk3 = md->allocate(2048);
    ASSERT(!MemoryDealer::isOk(blk3));
    md->deallocate(blk2);
    blk3 = md->allocate(2048);
    ASSERT(MemoryDealer::isOk(blk3));
    cout << "OK" << endl;
}

using ::android::hardware::lockMemory;
using ::android::hardware::unlockMemory;

static void test6() {
    cout << "Test: performance " << endl;
    Tick sta, end;
    sp<IAllocator> allocator = IAllocator::getService("ashmem", false);

    hidl_memory mem;
    bool success;
    const int N = 10000;
    TICK_NOW(sta);
    for (int i = 0; i < N; i++) {
        // test MemoryDealer
        allocator->allocate(256, [&mem, &success](bool _success, const hidl_memory& _mem) {
            mem = _mem;
            success = _success;
        });
        ASSERT(success);
        sp<IMemory> im = mapMemory(mem);
        ASSERT(im != nullptr);
        void* p = im->getPointer();
        char* pc = reinterpret_cast<char*>(p);
        *pc = 'a';
    }
    TICK_NOW(end);
    cout << (tickDiffNS(sta, end) / 1000) << " ms - " << N << " allocations" << endl;

    TICK_NOW(sta);
    allocator->allocate(4096, [&mem, &success](bool _success, const hidl_memory& _mem) {
        mem = _mem;
        success = _success;
    });
    ASSERT(success);
    auto retAdd = allocator->add(mem);
    ASSERT(retAdd.isOk());
    int64_t heapID = retAdd;
    const uint64_t msk = (0x1Ull << 12) - 1;
    ASSERT(lockMemory("ashmem", heapID));
    for (int i = 0; i < N; i++) {
        uint64_t off = (i << 8) & msk;
        hidl_memblk blk = {heapID, 0x00, 0x00};
        sp<IMemory> im = mapMemory(blk);
        void* p = im->getPointer();
        char* pc = reinterpret_cast<char*>(p);
        *pc = 'a';
    }
    ASSERT(unlockMemory("ashmem", heapID));
    TICK_NOW(end);
    cout << (tickDiffNS(sta, end) / 1000) << " ms - " << N << " allocations" << endl;
}

static void cleanup(void) {
    for (sp<Pipe> child : children) {
        int status;
        child->signal();
        wait(&status);
    }
}

// This test is modified from binderThroughputTest.cpp
int main(int, char**) {
    setenv("TREBLE_TESTING_OVERRIDE", "true", true);
    startMemoryTest();
    test1();
    test2();
    test3();
    test4();
    test5();
    test6();
    cleanup();
    return 0;
}
