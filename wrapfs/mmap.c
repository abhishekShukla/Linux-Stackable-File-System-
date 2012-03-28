/*
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "wrapfs.h"
#define PAD 16

#ifdef WRAPFS_CRYPTO
/* added: begin for encryption */
const u8 *aes_iv = "cephsageyudagreg";

static struct crypto_blkcipher *ceph_crypto_alloc_cipher(void){
        return crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
}
/* added: end */
#endif


/* added: begin address space operations definitions */
static int wrapfs_writepage(struct page *page, struct writeback_control *wbc){
    int err = -EIO;
    struct inode *inode;
    struct inode *lower_inode;
    struct page *lower_page;
    struct address_space *lower_mapping; /* lower inode mapping */
    gfp_t mask;

    BUG_ON(!PageUptodate(page));
    inode = page->mapping->host;
    if (!inode || !WRAPFS_I(inode)){
        err = 0;
        goto out;
    }
    lower_inode = wrapfs_lower_inode(inode);
    lower_mapping = lower_inode->i_mapping;
    mask = mapping_gfp_mask(lower_mapping) & ~(__GFP_FS);
    lower_page = find_or_create_page(lower_mapping, page->index, mask);

    if (!lower_page) {
        err = 0;
        set_page_dirty(page);
        goto out;
    }

    copy_highpage(lower_page, page);
    flush_dcache_page(lower_page);
    SetPageUptodate(lower_page);
    set_page_dirty(lower_page);

    if (wbc->for_reclaim) {
        unlock_page(lower_page);
        goto out_release;
    }

    BUG_ON(!lower_mapping->a_ops->writepage);
    wait_on_page_writeback(lower_page); /* prevent multiple writers */
    clear_page_dirty_for_io(lower_page); /* emulate VFS behavior */
    err = lower_mapping->a_ops->writepage(lower_page, wbc);
    if (err < 0)
        goto out_release;

    if (err == AOP_WRITEPAGE_ACTIVATE) {
         err = 0;
         unlock_page(lower_page);
    }

    fsstack_copy_attr_times(inode, lower_inode);

out_release:
    page_cache_release(lower_page);

out:
    unlock_page(page);
    return err;
}

#ifdef WRAPFS_CRYPTO
int ceph_aes_decrypt(const void *key, int key_len, void *dst, size_t *dst_len, const void *src,  size_t src_len){

    struct scatterlist sg_in[1], sg_out[2];
    struct crypto_blkcipher *tfm = ceph_crypto_alloc_cipher();
    struct blkcipher_desc desc = { .tfm = tfm };
    char pad[16];
    void *iv;
    int ivsize;
    int ret;
    int last_byte;

    if (IS_ERR(tfm))
        return PTR_ERR(tfm);
                                                            
    crypto_blkcipher_setkey((void *)tfm, key, key_len);
    sg_init_table(sg_in, 1);
    sg_init_table(sg_out, 2);
    sg_set_buf(sg_in, src, src_len);
    sg_set_buf(&sg_out[0], dst, *dst_len);
    sg_set_buf(&sg_out[1], pad, sizeof(pad));

    iv = crypto_blkcipher_crt(tfm)->iv;
    ivsize = crypto_blkcipher_ivsize(tfm);
    memcpy(iv, aes_iv, ivsize); 

    ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, src_len);
    crypto_free_blkcipher(tfm);
    if (ret < 0) {
        pr_err("ceph_aes_decrypt failed %d\n", ret);
        return ret;
    }
    
    if (src_len <= *dst_len)
        last_byte = ((char*)dst)[src_len - 1];
    else
        last_byte = pad[src_len - *dst_len - 1];

    if (last_byte <= 16 && src_len >= last_byte) {
        *dst_len = src_len - last_byte;
    } 
    else {
        pr_err("ceph_aes_decrypt got bad padding %d on src len %d\n",
        last_byte, (int)src_len);
        return -EPERM;  /* bad padding */
    }
    return 0;
}
#endif

static int wrapfs_readpage(struct file *file, struct page *page){

    int err;
    struct file *lower_file;
    struct inode *inode;
    mm_segment_t old_fs;
    char *page_data = NULL;
    mode_t orig_mode;
    char *decrypted_data = NULL;
    struct wrapfs_sb_info *sbi = NULL;
    size_t page_len = (size_t)PAGE_CACHE_SIZE;
    
    
    DEBUGMSG("INSIDE READPAGE!!");
    sbi = (struct wrapfs_sb_info*)file->f_path.dentry->d_sb->s_fs_info;
    DEBUGMSG("KEY IN READPAGE IS BELOW");
    DEBUGMSG(sbi->sb_key);
    

    //For decryption
    decrypted_data = kmalloc(PAGE_CACHE_SIZE + PAD, GFP_KERNEL);
    if(!decrypted_data || IS_ERR(decrypted_data)){
        ERR;
        err = PTR_ERR(decrypted_data);
        goto out;
    }
    memset(decrypted_data, 0, PAGE_CACHE_SIZE + PAD);

    /* Commented: 
    wrapfs_read_lock(file->f_path.dentry->d_sb, UNIONFS_SMUTEX_PARENT);
    err = wrapfs_file_revalidate(file, false);
    if(unlikely(err)){
        goto out;
    }
    wrapfs_check_file(file);
    */

    lower_file = wrapfs_lower_file(file);
    /* FIXME: is this assertion right here? */
    BUG_ON(lower_file == NULL);
    inode = file->f_path.dentry->d_inode;
 
    page_data = (char *)kmap(page);
    /*
    * Use vfs_read because some lower file systems don't have a
    * readpage method, and some file systems (esp. distributed ones)
    * don't like their pages to be accessed directly.  Using vfs_read
    * may be a little slower, but a lot safer, as the VFS does a lot of
    * the necessary magic for us.
    */
    lower_file->f_pos = page_offset(page);

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    /*
    * generic_file_splice_write may call us on a file not opened for
    * reading, so temporarily allow reading.
    */
    orig_mode = lower_file->f_mode;
    lower_file->f_mode |= FMODE_READ;

#ifdef WRAPFS_CRYPTO
    //For Decryption
    if(sbi->sb_key != NULL){
        DEBUGMSG("Reading Decrypted Data");
        err = vfs_read(lower_file, decrypted_data, PAGE_CACHE_SIZE + PAD, &lower_file->f_pos);
    }
    else{
#endif
        DEBUGMSG("Reading Normal Data");
        err = vfs_read(lower_file, page_data, PAGE_CACHE_SIZE, &lower_file->f_pos);
#ifdef WRAPFS_CRYPTO
    }

    
    //For Decryption
    if(sbi->sb_key != NULL){
        DEBUGMSG("Performing Decryption");
        ceph_aes_decrypt(sbi->sb_key, 16, page_data, &page_len, decrypted_data, err);
    }
    else{
        DEBUGMSG("Not Performing Decryption");
    }
#endif
    lower_file->f_mode = orig_mode;
    
    set_fs(old_fs);
    if (err >= 0 && err < PAGE_CACHE_SIZE)
        memset(page_data + err, 0, PAGE_CACHE_SIZE - err);
    
    kunmap(page);
            
    if (err < 0)
        goto out;
    err = 0;

    fsstack_copy_attr_times(inode, lower_file->f_path.dentry->d_inode);
    flush_dcache_page(page);
                                                                       
out:
    if (err == 0)
        SetPageUptodate(page);
    else
        ClearPageUptodate(page);
                                                                                  
    unlock_page(page);
    /*Commented: 
    unionfs_check_file(file);

    unionfs_read_unlock(file->f_path.dentry->d_sb);
    */
    return err;         
}

static int wrapfs_write_begin(struct file *file,
                              struct address_space *mapping,
                              loff_t pos, unsigned len, 
                              unsigned flags, 
                              struct page **pagep, void **fsdata){
    pgoff_t index = pos >> PAGE_CACHE_SHIFT;
    struct page *page;
    int rc =0;

    DEBUGMSG("In Write Begin");
    page = grab_cache_page_write_begin(mapping, index, flags);
    if(!page){
        rc =  -ENOMEM;
        goto out;
    }
    *pagep = page;

out:
    if(unlikely(rc)){
        page_cache_release(page);
        *pagep = NULL;
    }

    return rc;
}

#ifdef WRAPFS_CRYPTO
int ceph_aes_encrypt(const void *key, int key_len, void *dst, size_t *dst_len,
                      const void *src, size_t src_len){
        
    struct scatterlist sg_in[2], sg_out[1];
    struct crypto_blkcipher *tfm =  ceph_crypto_alloc_cipher();
    struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };
    int ret;
    void *iv;
    int ivsize;
    size_t zero_padding = (0x10 - (src_len & 0x0f));
    char pad[16];
                                            
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);
                 
    memset(pad, zero_padding, zero_padding);

    *dst_len = src_len + zero_padding;
    crypto_blkcipher_setkey((void *)tfm, key, key_len);

    sg_init_table(sg_in, 2);
    sg_set_buf(&sg_in[0], src, src_len);
    sg_set_buf(&sg_in[1], pad, zero_padding);
    sg_init_table(sg_out, 1);
    sg_set_buf(sg_out, dst, *dst_len);
    
    iv = crypto_blkcipher_crt(tfm)->iv;
    ivsize = crypto_blkcipher_ivsize(tfm); 
    memcpy(iv, aes_iv, ivsize);
                                                                            
    ret = crypto_blkcipher_encrypt(&desc, sg_out, sg_in, src_len + zero_padding);
    crypto_free_blkcipher(tfm);
    if (ret < 0)
        pr_err("ceph_aes_encrypt failed %d\n", ret);
    return 0;
}
#endif

static int wrapfs_write_end(struct file *file, 
                            struct address_space *mapping,
                            loff_t pos, unsigned len, unsigned copied,
                            struct page *page, void *fsdata){
    unsigned from = pos & (PAGE_CACHE_SIZE - 1);
    struct inode *lower_inode = NULL;
    struct inode *wrapfs_inode = mapping->host;
    int rc;
    struct file *lower_file = NULL; 
    mm_segment_t fs_save; 
    char *virt; 
    char *encrypted_data = NULL;
    struct wrapfs_sb_info *sbi = NULL;

    size_t encrypted_data_len = 0;
    
     DEBUGMSG("In write end");

    sbi = (struct wrapfs_sb_info*)file->f_path.dentry->d_sb->s_fs_info;
    DEBUGMSG("KEY IN WRITE-END IS BELOW");
    DEBUGMSG(sbi->sb_key);


    BUG_ON(file == NULL);
    
    if(WRAPFS_F(file) != NULL){
        lower_file = wrapfs_lower_file(file);
    }

    //For Encryption
    encrypted_data = kmalloc(copied + PAD, GFP_KERNEL);
    if(!encrypted_data || IS_ERR(encrypted_data)){
        ERR;
        rc = PTR_ERR(encrypted_data);
        goto out;
    }

    encrypted_data_len = (size_t)copied;

    lower_file->f_pos = page_offset(page) + from;
    virt = kmap(page); 

#ifdef WRAPFS_CRYPTO
    //For Encryption
    if(sbi->sb_key != NULL){
        DEBUGMSG("Performing Encryption");
        ceph_aes_encrypt(sbi->sb_key, 16, encrypted_data, &encrypted_data_len, virt + from, copied);
    }
    else{
        DEBUGMSG("Not performing Encryption");
    }
#endif

    fs_save = get_fs(); 
    set_fs(get_ds()); 

#ifdef WRAPFS_CRYPTO
    //For Encryption
    if(sbi->sb_key != NULL){
        DEBUGMSG("Writing Encrypted Data");
        rc = vfs_write(lower_file, encrypted_data, copied, &lower_file->f_pos);
    }
    else{
#endif
        DEBUGMSG("Writing Normal Data");
        rc = vfs_write(lower_file, virt + from, copied, &lower_file->f_pos);
#ifdef WRAPFS_CRYPTO
    }
#endif

    set_fs(fs_save);
    kunmap(page); 
    
    if(rc < 0){
        goto out;
    }

    lower_inode = lower_file->f_path.dentry->d_inode;
    if(!lower_inode){
        lower_inode = wrapfs_lower_inode(wrapfs_inode);
    }
    fsstack_copy_inode_size(wrapfs_inode, lower_inode);
    fsstack_copy_attr_times(wrapfs_inode, lower_inode);
    mark_inode_dirty_sync(wrapfs_inode); 

out:
    if(rc < 0){
        ClearPageUptodate(page);
    }
    else{
        SetPageUptodate(page);
    }
    flush_dcache_page(page);
    unlock_page(page);
    page_cache_release(page);

    return rc;
}
/* added: end*/

static int wrapfs_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	int err;
	struct file *file, *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
	struct vm_area_struct lower_vma;

	memcpy(&lower_vma, vma, sizeof(struct vm_area_struct));
	file = lower_vma.vm_file;
	lower_vm_ops = WRAPFS_F(file)->lower_vm_ops;
	BUG_ON(!lower_vm_ops);

	lower_file = wrapfs_lower_file(file);
	/*
	 * XXX: vm_ops->fault may be called in parallel.  Because we have to
	 * resort to temporarily changing the vma->vm_file to point to the
	 * lower file, a concurrent invocation of wrapfs_fault could see a
	 * different value.  In this workaround, we keep a different copy of
	 * the vma structure in our stack, so we never expose a different
	 * value of the vma->vm_file called to us, even temporarily.  A
	 * better fix would be to change the calling semantics of ->fault to
	 * take an explicit file pointer.
	 */
	lower_vma.vm_file = lower_file;
	err = lower_vm_ops->fault(&lower_vma, vmf);
	return err;
}

/*
 * XXX: the default address_space_ops for wrapfs is empty.  We cannot set
 * our inode->i_mapping->a_ops to NULL because too many code paths expect
 * the a_ops vector to be non-NULL.
 */
const struct address_space_operations wrapfs_aops = {
    /* added: begin address operations*/
    .writepage = wrapfs_writepage,
    .readpage = wrapfs_readpage,
    .write_begin = wrapfs_write_begin,
    .write_end = wrapfs_write_end
    /* added: end */
};

const struct vm_operations_struct wrapfs_vm_ops = {
	.fault		= wrapfs_fault,
};
