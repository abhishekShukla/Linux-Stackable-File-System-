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
#include <linux/module.h>
/*added: begin wrapfs options*/
enum {wrapfs_opt_mmap, 
      wrapfs_opt_err};

static const match_table_t tokens = {
    {wrapfs_opt_mmap, "mmap"},
    {wrapfs_opt_err, NULL}      
};
/*added: end*/

/*added: being to parse the options */
static int wrapfs_parse_options(char *options){
    char *p;
    int rc = 0;
    substring_t args[MAX_OPT_ARGS];
    int token;

    DEBUGMSG("BEGIN PARSING");
    if(!options){
        rc = -EINVAL;
    }
    while((p = strsep(&options, ",")) != NULL){
        if(!*p){
            continue;
        }
        token = match_token(p, tokens, args);
        switch(token){
        case wrapfs_opt_mmap:
            rc = 1;
            break;
        case wrapfs_opt_err:
        default:
            rc = -EINVAL;
            printk(KERN_WARNING
                    "%s: wrapfs: unrecognized option [%s]\n",
                    __func__, p);
            break;
        }
    }
    DEBUGMSG("END PARSING");
    return rc;
}
/*added: end*/

/*
 * There is no need to lock the wrapfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int wrapfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct path lower_path;
	char *dev_name = (char *) raw_data;
	struct inode *inode;

	if (!dev_name) {
		printk(KERN_ERR
		       "wrapfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"wrapfs: error accessing "
		       "lower directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct wrapfs_sb_info), GFP_KERNEL);
	if (!WRAPFS_SB(sb)) {
		printk(KERN_CRIT "wrapfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}
    
	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	wrapfs_set_lower_super(sb, lower_sb);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &wrapfs_sops;

	/* get a new inode and allocate our root dentry */
	inode = wrapfs_iget(sb, lower_path.dentry->d_inode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_alloc_root(inode);
	if (!sb->s_root) {
        LOGMSG("NO MEMMORY AVAILABLE");
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &wrapfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	wrapfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_alloc_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "wrapfs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);
	goto out; /* all is well */

	/* no longer needed: free_dentry_private_data(sb->s_root); */
out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(WRAPFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);

out:
	return err;
}
/* 
* added/modified the function to suit our requirements 
* most part of the function has been taken from the 
* mpount_nodev.

* NEWLY ADDED:  few variables and a function call to parse
*               the options. few statements to record the
*               parsed options
*/

struct dentry *wrapfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
    
	void *lower_path_name = (void *) dev_name;

    /*added: begin*/
    struct super_block *s;
    struct wrapfs_sb_info *sbi;
    int error;
    int mmap = 0;
    /*added: end*/
    
    DEBUGMSG((char*)raw_data);
    s = sget(fs_type, NULL, set_anon_super, NULL);
    if(IS_ERR(s)){
            return ERR_CAST(s);
    }

    s->s_flags = flags;
    error = wrapfs_read_super(s, lower_path_name, flags & MS_SILENT ? 1 : 0);
    if(error){
        goto out;
    }
    /*added: begin*/
    error = wrapfs_parse_options(raw_data);
    DEBUGMSG("MMAP VALUE IS IN THE NEXT LINE");
    DEBUGINT(error);

    if(error < 0 && raw_data != NULL){
        LOGMSG("MOUNT COMMAND IMPROPER");
        goto out;
    }

    if(1 == error){
        DEBUGMSG("SETTING MMAP");
        mmap = error;
    }
    sbi = WRAPFS_SB(s);
    sbi->sb_mmap = mmap;
    DEBUGINT(sbi->sb_mmap);
    /*added: end*/
    
    s->s_flags |= MS_ACTIVE;
    return dget(s->s_root);

out:
    deactivate_locked_super(s);
    return ERR_PTR(error);

    /*
    commented: begin
	return mount_nodev(fs_type, flags, lower_path_name,
			   wrapfs_read_super);
    commented: end
    */
}

static struct file_system_type wrapfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= WRAPFS_NAME,
	.mount		= wrapfs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= FS_REVAL_DOT,
};

static int __init init_wrapfs_fs(void)
{
	int err;

	pr_info("Registering wrapfs\n");

	err = wrapfs_init_inode_cache();
	if (err)
		goto out;
	err = wrapfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&wrapfs_fs_type);
out:
	if (err) {
		wrapfs_destroy_inode_cache();
		wrapfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_wrapfs_fs(void)
{
	wrapfs_destroy_inode_cache();
	wrapfs_destroy_dentry_cache();
	unregister_filesystem(&wrapfs_fs_type);
	pr_info("Completed wrapfs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
	      " (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("Wrapfs (http://wrapfs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_wrapfs_fs);
module_exit(exit_wrapfs_fs);
