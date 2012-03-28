CSE 506 - Assignment 2

DIRECTORY STRUCTURE: /usr/src/hw2-ashuklaravis/fs/wrapfs

Apart from the modified wrapfs files, below is a list of the additional files committed:

    1. kernel.config
    2. pass_key.c (user space program/ioctl)
	3. wrapfs_ioctl.h
    4. Makefile
    5. readme.txt

Wrapfs Files Modified: 
	
	1. main.c
	2. file.c
	3. lookup.c
	4. wrapfs.h
	5. mmap.c

STEPS TO COMPILE:
    
    1. make (all/clean)
		Builds the wrapfs module as well as the pass_key.c
    2. insmod wrapfs.ko
	3. Mounting Wrapfs:
		a.  Without MMAP option: mount -t wrapfs "dev_name" "mount-point directory"
		b.  With MMAP option: mount -t wrapfs -o mmap "dev_name" "mount-point directory"
    4. To run the user space program
                ./pass_key -h : This will show the options and arguments

       General Scenario:
               ./pass_key -m "dev_name" -p "Password Here"

NOTE: I wish I could figure out how to add the -DWRAPFS_CRYPTO to the makefile. Unfortunately, I was unable to do so. So the WRAPFS_CRYPTO option which turns on/off the encryption/decryption has to be changed in the wrapfs.h file. 

Description:
    
   	1. User Space Program:
		
		1. In the user space program, gnuopt(3) has been used.
		2. Checks for missing arguments or extra arguments passed. 
		3. Removes the '\n' is used in the password.
		4. Allows passwords of minimum length=6 characters. 
		5. A hash of this password is used as the key for encryption/decryption by the file system. Since this hash is of fixed length, it was easier to handle it through out the file system code.

    2. HASH/ENCRYPTION/DECRYPTION Algorithms:
            
            1. MD5 hash:
                    Used in both User Space and Kernel space.

                    To use the MD5 Hash, the following openssl packages were
                    downlaoded in user space.

                     ----------------------------------
                    |NOTE: yum install openssl         |
                    |      yum install openssl-devel   |
                     ----------------------------------

            2. ceph_aes_encrypt/ceph_aes_decrypt:
				
				The code was taken from Assignment 1 and modified accordingly. 
				
				But in this assignment I have used these ciphers are used in Counter Mode. 
				NOTE: Some padding issues were coming up with the CBC mode.
				
				mmap information as well as the key are stored in a structure type which is pointed to by the private pointer is the super block. 
				This way, the key is not present in the persistent memmory.
				
	3. Mounting
		
		1. I have followed the code pattern from ecryptfs to parse the mount option. 
		2. wrapfs_mount function has been modified. 
		3. This modified function basically behaves like nodev function, but with parsing
		4. if an unkown option is passed, filesystem wont be mounted.
		5. As mentioned earlier, mmap information as well as the key are stored in a structure type which is pointed to by the private pointer is the super block. 
		   
		
		File operations assocated with mmap option:
		
		const struct file_operations wrapfs_mmap_fops = {
			.llseek         = generic_file_llseek,
			.read           = do_sync_read,
			.aio_read       = generic_file_aio_read,
			.write          = do_sync_write,
			.aio_write      = generic_file_aio_write,
			.unlocked_ioctl = wrapfs_unlocked_ioctl,
			#ifdef CONFIG_COMPAT
				.compat_ioctl   = wrapfs_compat_ioctl,
			#endif
			.mmap           = wrapfs_mmap,
			.open           = wrapfs_open,
			.flush          = wrapfs_flush,
			.release        = wrapfs_file_release,
			.fsync          = wrapfs_fsync,
			.fasync         = wrapfs_fasync,
		};

		
	4. Address Space operations:
	
		1. Lots of documentation, unionfs source code and ecryptfs source code was used as reference. 
		
		2. Address space operation implemented
			
			const struct address_space_operations wrapfs_aops = {
				.writepage = wrapfs_writepage,
				.readpage = wrapfs_readpage,
				.write_begin = wrapfs_write_begin,
				.write_end = wrapfs_write_end
				};

		3. unionfs' way of reading is followed. 
		
			Normal Execution: Wraps calls vfs_read on the lower file system to get the page data. 
			Decryption: Page data is read from lower file system and then decrypted. 
		
		4. ecryptfs' way of writing is followed. 
			
			Normal Execution: Wrapfs issues vfs_write on the lower file system to write the data in the page. 
			Encryption: Page data is encrypted and then written onto the lower file system. 
		
		5.	Setting/Resetting/Revoking the Key:
	
			I chose to shrink wrapfs's dcache whenever the key was set, revoked, or reset. 
			This design decision was made as the pages that were just read with a previous key were still in the cache and readpage would not be called when you would try to read the file with a new key and old contents would be displayed.
			To tackle this security issue, this design decision was made

NOTE: When No key is given to the file system, it logs a "NO KEY PRESENT" message and continues to read and write files with encryption or decryption. 
	
NOTE: I have used macros to debug my code. These macros are turned off. But if erratic behavior is observed, this can be turned on in wrapfs.h
THIS IS NOT TO BE CONSIDERED FOR EXTRA CREDITS. Also, if these are turned off, I get compile time warnings saying statements which do nothign are present. 

REFERENCES:
    
    1. IOCTL: 
        a. http://docs.blackfin.uclinux.org/doku.php?id=linux-kernel:ioctls#ioctl_example_code
		b. http://lists.freebsd.org/pipermail/freebsd-drivers/2005-November/000078.html
    2. Parsing Options: ecryptfs    
    3. readpage, writepage = unionfs
	4. write_begin, write_end = ecryptfs, unionfs
	
	
