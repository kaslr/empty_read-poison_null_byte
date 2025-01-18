## OFF-BY-ONE ERRORS: _THE POISON NULL BYTE_

Until two days ago, I was confident in my ability to tackle any heap challenge. Having successfully completed every heap challenge on [Flagyard](https://flagyard.com), I believed it couldnʼt get any tougher. However, I was proven wrong when my friend, _0x1337_, sent me a pwn with a vulnerability that led me down a rabbit hole of research.

In this detailed write-up, Iʼll explain how I abused a null byte overflow to achieve arbitrary code execution.

## Recon
Upon loading the binary into Ghidra, I began my reconnaissance. Since the binary was stripped, I started by renaming functions, variables, and globals.

The binary itself doesnʼt do much. Itʼs an application that manages a database of users and their email addresses. It provides functionalities for adding, deleting, updating, and viewing all user email addresses. The application employs a straightforward structure for users, with fields that include the length of the email and a pointer to the buffer for the email data.

Hereʼs a visual representation of the structure:

```c
typedef struct user {
    int email_len;
    char* email;
} user;
```

The application maintains a list of users in a global array. This array is used to access user information. Users provide the index into this array at creation time, which is then used to access their information.

Upon analyzing the functions, I observed that proper pointer arithmetic was employed. When a user was deleted, their position in the global array, which holds pointers to the user structures, was zeroed out. This ensured that we couldnʼt access deleted user pointers, thereby preventing access to freed memory and avoiding any use-after-free situations.

After a deep analysis of the user creation function, I noticed that we couldnʼt create an email with a length greater than 512 bytes. Additionally, the maximum number of users in the user list was limited to 10, making the highest index 9. All user input emails were also terminated with a null byte at the end. This was the vulnerable part of the code. The bug was present in both the user creation and editing functions.

Hereʼs the vulnerable code:

```c
puts("User email:");
n_bytes_read = read(0, *(void **)(*(int *)(&user_list + idx * 4) + 4),
                    **(size_t **)(&user_list + idx * 4));
if (n_bytes_read < 1)
    **(undefined **)(*(int *)(&user_list + idx * 4) + 4) = 0;
else
    *(undefined *)(n_bytes_read + *(int *)(*(int *)(&user_list + idx * 4) + 4)) = 0;
```

This code was extracted from the decompiled binary, so it might appear cryptic. Letʼs clean it up to understand whatʼs happening.

```c
puts("User email:");
bytes_read = read(0, user_list[idx]->email, user_list[idx]->email_len);
if(bytes_read < 1)
    user_list[idx]->email = 0;
else
    user_list[idx]->email + bytes_read = 0;
```

The vulnerability lies in the else case. By adding the total number of bytes read from the user to the bufferʼs address, we end up writing one byte past the allocated bufferʼs end. This uncontrolled write results in a null byte overflow.

After spending a few more minutes ensuring I hadnʼt missed anything, I confirmed that everything was in order. With the recon complete, I was ready to exploit the vulnerability.

I’ll assume the reader has some familiarity with glibc’s heap, pointer arithmetic, and practical experience with exploiting heap vulnerabilities, such as use-after-frees and similar issues.

## A Quick Refresher on the Heap and Its Design in glibc
The heap is a region of memory used for dynamic memory allocation. When a program requests memory at runtime, it is allocated from the heap. This allows programs to request and release memory as needed, which is essential for managing resources efficiently.

### Heap Design in glibc
In glibc, the heap is managed using a data structure called a "heap chunk." Each chunk contains metadata that describes its size and status (allocated or free). The heap is divided into different bins, which are lists of chunks of varying sizes. When a chunk is freed, it is added to the appropriate bin, making it available for future allocations.

### Key Components of a Chunk
**Size:** Indicates the total size of the chunk, including both the metadata and the user data.

**In-use bit**: A flag indicating whether the chunk is currently allocated (in use) or free.

**Previous size**: If the previous chunk is free, this field stores its size. This is used for coalescing adjacent free chunks to reduce fragmentation.

**Next and previous pointers**: If the chunk is free, these pointers link it to the next and previous chunks in the free list. This helps the allocator quickly find and manage free chunks.

### Bins
Bins are lists of free chunks of varying sizes. They help the allocator quickly find and manage free chunks for future allocations. There are different types of bins:

**Fast bins**: Used for small chunks and provide quick allocation and deallocation.

**Unsorted bin**: A temporary holding area for freed chunks before they are sorted into other bins.

**Small and large bins**: Used for larger chunks and are sorted by size to optimize allocation.

### glibc Interfaces
glibc offers interfaces to interact with the heap, enabling allocation, deallocation, and a variety of other operations. For example:

**malloc**: Allocates memory and returns a pointer to the beginning of the allocated memory block.

**free**: Deallocates previously allocated memory, returning the memory block to the heap.

**realloc**: Resizes previously allocated memory.

Sadly, I wonʼt be teaching about the heap today. Iʼll only delve into the parts that relate to the vulnerability. If you feel youʼre not catching up due to some things I donʼt explain, I recommend reading Azeriaʼs articles on glibc. She provides excellent in-depth explanations that can help fill in any gaps. Here’s the relevant link to her blog posts. [Azeria-Labs](https://azeria-labs.com). Or, if youʼre feeling adventurous, you can read the source code at [malloc.c](https://codebrowser.dev/glibc/glibc/malloc/malloc.c.html).

As I mentioned earlier, the heap manages contiguous blocks of memory in structures called chunks. These chunks store not only the userʼs data but also metadata about their state, size, the size of the adjacent chunk, and special flags.

## Somewhat Detailed Explanation of Chunks
Chunks in the glibc heap contain metadata that helps manage memory allocation. This metadata is stored in the header of the chunk, preceding the user data. The key components of the chunk metadata include:

Size: Indicates the total size of the chunk, including both the metadata and the user data.

In-use bit: A flag indicating whether the chunk is currently allocated (in use) or free.

Previous size: If the previous chunk is free, this field stores its size. This is used for coalescing adjacent free chunks to reduce fragmentation.

Next and previous pointers: If the chunk is free, these pointers link it to the next and previous chunks in the free list. This helps the allocator quickly find and manage free chunks.

### Pictorial Representation
Here’s a simple pictorial representation of an allocated chunk in the heap:

![allocated_chunk](https://i.stack.imgur.com/so4y7.png)

The area marked as "User Data" in the diagram is the portion of the chunk that the malloc function returns to the user for use.

A free chunk also has metadata, such as pointers to the next and previous free chunks, and it stores this information in the region that was previously used for the applicationʼs data. This allows the allocator to efficiently manage and reuse free memory chunks.

![free_chunk](https://th.bing.com/th/id/R.2e3b09b9a4bab6c26c51871e82dd2a47?rik=HwNBPpIZ6KxqiQ&pid=ImgRaw&r=0)

Letʼs dive into the meat and potatoes of the vulnerability and how I managed to exploit it to get code execution.

My approach to exploiting the binary was straightforward: chunk consolidation. By merging chunks that were still in use, we could artificially trigger a use-after-free (UAF) condition, which could then be leveraged to create a powerful arbitraty r/w primitive.

Since the application used the tcache and the maximum length of user emails was 512 bytes, I knew I had to be a bit more creative with my allocations and frees. I started by making a few rogue allocations, all matching the size of the user structure (e.g., the user structure is 0x10 bytes on the heap). This was to populate the tcache so that subsequent allocations would use those for the user data structure, ensuring that only the email data would be set next to each other.

Freeing these chunks (I created 5 users, so we had 7 chunks in the tcache and 3 in the fastbins) populated the corresponding tcache and fastbins. This was exactly what I wanted to achieve.

Next, I created 7 rogue chunks to populate the 512-byte tcache bins. This ensured that subsequent frees would be placed in the unsorted or small bins. You might wonder why I chose the 512-byte bin. Well, since the null byte overflow would shrink the chunk and also set the in-use bit of the previous chunk to free, I needed to avoid using the 528-byte bin. Using the 528-byte bin would cause our next free to be placed in the wrong bin. Therefore, the 7 chunks I created had email lengths that, when added to the chunk metadata, summed up to 512 bytes, not 528.

By carefully managing these allocations and frees, I was able to manipulate the heap layout to my advantage. This setup was crucial for the next steps in the exploitation process.

I made 3 more allocations (created new users) all sitting next to each other. Letʼs label these chunks A, B, and C for easier reference. The idea was to consolidate all 3 of these chunks so that allocations made after the tcache was emptied would overlap a user data region. Since this region could be used to serve up a malloc allocation (the application still thinks that user exists, therefore its chunk is valid), we could overwrite the data pointer of a user struct to point to an arbitrary address, giving us a write-what-where primitive.

Chunks A and B are each 512 bytes in size. Chunk C, on the other hand, is 528 bytes. The reason I made chunk C this size was to bypass a specific check in the heap allocator.

Before triggering the null byte overflow, which essentially shrinks the chunk to 16 bytes less than its actual size, I crafted a payload at the soon-to-be orphaned memory region. I wrote 4 bytes of 0x41 followed by 0x11 in the next address. This essentially creates a fake chunk. This simple payload is sufficient to bypass the piece of code below:

```c
if (__glibc_unlikely(!prev_inuse(nextchunk)))
    malloc_printerr("double free or corruption (!prev)");
INTERNAL_SIZE_T nextsize = chunksize(nextchunk);
if (__builtin_expect(chunksize_nomask(nextchunk) <= CHUNK_HDR_SZ, 0) || __builtin_expect(nextsize >= av->system_mem, 0))
    malloc_printerr("free(): invalid next size (normal)");
free_perturb(chunk2mem(p), size - CHUNK_HDR_SZ);
```

The code snippet below checks if the chunk weʼre trying to free has already been freed by examining the prev_in_use bit of the next chunk. If that bit has been cleared, it indicates that weʼve freed this chunk before, resulting in a double free. The next check ensures that the size of the next chunk is not less than the size of a chunk header, which is 8 bytes on 32-bit systems. Therefore, the payload at the soon-to-be orphaned memory region, with the first 4 bytes being the prev_size field and the next 4 bytes being its size plus flags, has the value 0x11 in hexadecimal, which passes both checks.

To trigger the overflow and cause consolidation, we start by freeing the 7 rogue chunks we created. This action populates the 512-byte bin for the tcache, ensuring that subsequent frees will go to the unsorted bin. Next, we free chunk A, adding it to the unsorted bin. We then trigger the overflow by writing the maximum number of bytes minus 4, leaving space for 4 bytes. What we place at this memory region is crucial for the consolidation process. As you know, this region holds the prev_size field of chunk C. We set its value to 1024 bytes. Why? Letʼs examine the code snippet.

```c
/* Consolidate backward.  */
if (!prev_inuse(p))
{
    INTERNAL_SIZE_T prevsize = prev_size(p);
    size += prevsize;
    p = chunk_at_offset(p, -((long)prevsize));
    if (__glibc_unlikely(chunksize(p) != prevsize))
        malloc_printerr("corrupted size vs. prev_size while consolidating");
    unlink_chunk(av, p);
}
```

First, we check if the previous chunk is free by examining the prev_in_use bit of the current chunk. If this bit is cleared, it indicates that the chunk is free, allowing us to consolidate backwards. Next, we read the prev_size field of the current chunk, which tells us how far back we can merge. By setting this value to 1024 (512 * 2) , we can go as far back as chunk A, enabling us to consolidate chunks A, B, and C.
The next if statement checks if the size of the chunk weʼre  about to consolidate with is the same as the previous size field of the consolidating chunk, in our case this would crash the program since theyʼre both not the same but luckily for us, this piece of code was added later on in some new version of glibc & the binary uses an older version, libc-2.27.so, so we can ignore it, I only showed it here in case youʼre using a newer version of glibc & you get a crash with this error.

Since weʼve freed chunk A and added it to the unsorted bin, we need to unlink it before consolidation. This step is necessary before we add the newly consolidated chunk back to the unsorted bin.

Heres relevant code for the unlink function:
```c
if (chunksize(p) != prev_size(next_chunk(p)))
    malloc_printerr("corrupted size vs. prev_size");
mchunkptr fd = p->fd;
mchunkptr bk = p->bk;
if (__builtin_expect(fd->bk != p || bk->fd != p, 0))
    malloc_printerr("corrupted double-linked list");
fd->bk = bk;
bk->fd = fd;
```

The code performs several safety checks. First, it verifies that the size of the chunk we want to unlink matches the `prev_size` field of the next chunk. This is the case for us because the next chunk that borders A is B, and after we freed A, the allocator updated Bʼs `prev_size` field to the size of A.

The next check ensures there has been no linked list corruption by verifying that the `fd` pointer of the chunk before A in the bin is indeed pointing to A, and similarly, the `bk` pointer of the chunk after A is pointing to A. If all these checks pass, the chunks before and after A are repositioned to point to each other, effectively unlinking A from the bin.

After we unlink chunk A, we can then merge these chunks together to create a larger free chunk. This process is handled by the `_int_free_create_chunk` function. The code isnʼt hard to follow, but Iʼll explain the relevant parts.

```c
static INTERNAL_SIZE_T
_int_free_create_chunk (mstate av, mchunkptr p, INTERNAL_SIZE_T size,
			mchunkptr nextchunk, INTERNAL_SIZE_T nextsize)
{
  if (nextchunk != av->top)
    {
      /* get and clear inuse bit */
      bool nextinuse = inuse_bit_at_offset (nextchunk, nextsize);
      /* consolidate forward */
      if (!nextinuse) {
	unlink_chunk (av, nextchunk);
	size += nextsize;
      } else
	clear_inuse_bit_at_offset(nextchunk, 0);
      /*
	Place the chunk in unsorted chunk list. Chunks are
	not placed into regular bins until after they have
	been given one chance to be used in malloc.
      */
      mchunkptr bck = unsorted_chunks (av);
      mchunkptr fwd = bck->fd;
      if (__glibc_unlikely (fwd->bk != bck))
	malloc_printerr ("free(): corrupted unsorted chunks");
      p->fd = fwd;
      p->bk = bck;
      if (!in_smallbin_range(size))
	{
	  p->fd_nextsize = NULL;
	  p->bk_nextsize = NULL;
	}
      bck->fd = p;
      fwd->bk = p;
      set_head(p, size | PREV_INUSE);
      set_foot(p, size);
      check_free_chunk(av, p);
    }
  else
    {
      /* If the chunk borders the current high end of memory,
	 consolidate into top.  */
      size += nextsize;
      set_head(p, size | PREV_INUSE);
      av->top = p;
      check_chunk(av, p);
    }
  return size;
}
```

The comments should hopefully give you a clear mental picture of whatʼs happening. We first check if the next chunk bordering our large chunk is free. If it is, we consolidate forwards and add it to the large chunk. If not, we clear the prev_in_use bit of the next chunk to signify that our large chunk is free.

We then perform additional safety checks in the unsorted bin, as this is where our large chunk will be placed before being moved to the appropriate bin if there are no malloc requests for it. Finally, we set the prev_in_use flag of this new large chunk and update the prev_size field of the next chunk.

Thereʼs a check to see if this new chunk borders the top chunk. If it does, we simply consolidate it into the top chunk and donʼt place it in any bins. If youʼre unsure why we donʼt consolidate into the top chunk, I recommend going back a few sections to review. If itʼs still not clear, Iʼll explain: remember the orphaned memory region where we created the fake chunk? This is what borders our large chunk, and it is this chunkʼs `prev_size` field that is set.

If everything checks out, we place the chunk in the unsorted bin, and the function returns the size of the new free chunk.

the size of this chunk should be the size of the chunk being freed + its `prev_size` field .. in our case 512 + 1024 bytes

With all this information and our payload set in place, we trigger the overflow, ensuring the right values are in their respective positions. We then free chunk C, which merges with chunks A and B. This process creates an artificial use-after-free condition, as chunk B remains a valid chunk in the application.

## Info leak

We can now exploit this use-after-free vulnerability to leak some data from the heap. The process of achieving an information leak is a bit involved, so Iʼll take my time to explain it.

First, I created 5 users. Until now, we only had 1 user, with its data pointer being chunk B. Since each user struct stores information about the user, we use the chunks in the 16-byte tcache for those, but the user data we get from the 512-byte tcache. Now, we have 4 16-byte tcache chunks and 2 512-byte chunks.

Next, I created 2 more users with 12-byte email addresses. This exhausts all tcache entries. Subsequent allocations for the user struct would be taken from the unsorted bin, and if we craft the right values, its data region as well. At this point, weʼve created 8 users, leaving us with our last 2. Luckily, this is enough to give us an information leak and arbitrary write primitive.

We create a new user, crafting an email length that, when combined with the user struct, would be 512 bytes. This essentially reallocates chunk A. Why is this good for us? Well, the `bk` and `fd` pointers of a chunk in the unsorted bin point to a structure in libc, the `main_arena` struct. After we create a new user, we split the large chunk, give the requested size chunk to the user, and keep the remainder chunk, writing the `fd` and `bk` pointers into this new memory offset.

After the new allocation, the next allocation would be served from this remainder chunk, which happens to be the data pointer for the user linked to chunk B. Since the `fd` and `bk` pointers have been written into the first 8 bytes of this address, we can leak these pointers by printing the email data of the user associated with chunk B.

With our last user, we follow the same procedure as our previous allocation. This time, it doesnʼt matter if we get a data chunk from the 512-byte tcache; weʼre only interested in the user struct, which must be served from the remainder chunk in the unsorted bin. Since we can write to this chunk, as it falls within chunk Bʼs memory region, we can overwrite the email data pointer of a user to any address of our choosing, giving us a write-what-where primitive.

Having calculated the libc base address, I overwrite the data pointer of the newly created user to point to __free_hook, overwriting whatever was there with system. Then, by editing the data of a chunk with the string /bin/sh\x00, deleting that user would trigger the __free_hook, which in turn calls system with the string /bin/sh passed to it, effectively popping a shell.

And thatʼs it, folks! This is my first write-up, and itʼs almost certainly not perfect but I hope you enjoyed reading it as much as I enjoyed writing it. If you have any corrections or questions, feel free to reach out to me on X @ [kaslr](https://x.com/_kaslr)
