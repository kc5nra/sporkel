sporkel [![Build Status](https://travis-ci.org/kc5nra/sporkel.svg?branch=travis-ci)](https://travis-ci.org/kc5nra/sporkel)
=======


           _,,,,,,,_                                                    
        ,s*``        `*e,                                                
      yP                 "k                              ______,,_       
     `""*=ow..,            V===**********^^^^""""``````````       "%     
    .gg@*^``                                                        )    
        []22C>=            ,,,,,,,,___ _                           yL    
     "G7                  zF          ``````````"""^^^^"**********^      
       "%.,           _,#^                                               
          `"*==w>w==*^`                                                  
                                                                         
                                                                         

For how to use sporkel as a library, please refer to deltagen until a proper example is created.

deltagen
--------

```
usage: deltagen <command> <args>
Commands:
  help
  apply <before_tree> <patch_file>
  create <before_tree> <after_tree> <patch_file>
  keypair <secret_key_file> <public_key_file>
  sign <secret_key_file> <file>
  verify <public_key_file> <file> <signature>

Options:
  -v [ --verbose ]      enable verbose execution

apply:
  -k [ --keep-backup ]  keep backup

create:
  -c [ --cache ] arg                    location for cache
  -t [ --threads ] arg (=4)             number of threads to use
  -m [ --memory ] arg (=-1)             memory limit
  -l [ --lzma-preset ] arg (=2)         lzma compression preset
  --require-exact-patch-target arg (=1) patch target (directory) has to match 
                                        patch source directory exactly 
                                        (otherwise, allows other files in 
                                        target directory when applying patch); 
                                        creates slightly smaller patch files 
                                        when enabled
```

## Example usage
Say we have two directories `test1` and `test2`.
We want `test1`, after a patch is applied, to look like `test2`.

##### Create patch
```
./deltagen create test1 test2 test.patch
```
There should now be a `test.patch` which contains a binary delta of the two directories.
##### Apply patch
Now we want to make `test1`, after applying `test.patch`, to match `test2`.
```
./deltagen apply test1 test.patch
applying patch "test.patch" to "test1"
removing backup path "test1_backup"
removing temporary path "/var/folders/6r/gnfgm_fs2qn5q8jzq0dwtgy00000gn/T/f37e-e328-33f8-4e08"
```
##### Sign patch
Say we want to make sure that the patch file has not been modified.

First we need to create a keypair
```bash
./deltagen keypair secret.key public.key
generating public and secret key...
```
The public.key is 64 hex bytes (32 bytes or 256bit) and the secret.key is 128 hex bytes (64 bytes or 512bit) using https://ed25519.cr.yp.to/ signature algorithm.

Then we need to sign the patch. (Your signature will look different)
```
./deltagen sign secret.key test.patch 
fde75c00009856a31332fe94f1a8aef1ea15c9790f6704ebf3f963dfc906fabb95e565caa5902521677a3a46d7b036f23f483d0fd466b0c8d343ffd3f4a67f0c
```
##### Verify patch
To verify that the patch is the same as the one that was signed:
```
./deltagen verify public.key test.patch fde75c00009856a31332fe94f1a8aef1ea15c9790f6704ebf3f963dfc906fabb95e565caa5902521677a3a46d7b036f23f483d0fd466b0c8d343ffd3f4a67f0c
'test.patch' verified
```
## Create options
##### Cache
This allows you to cache the diff results of two files.  Since this is potentially a very expensive operation, if you plan on running this as part of a build process against multiple versions of a directory, the cache can speed up subsequent patch creations substantially.
##### Threads
This controls the number of threads to use when creating binary diffs between files.  The threading also does not exceed the memory limit if one is provided
##### Memory
This is the maximum amount of memory allowed across all threads. This is particularly important if you have very large files being diffed and you choose multiple threads.
##### LZMA preset
This is the amount of compression used on the patch file. 
According to the xz man pages:
* -0 ... -2  
Fast presets with relatively low memory usage. -1 and -2 should give compression speed and ratios comparable to bzip2 -1 and bzip2 -9, respectively. Currently -0 is not very good (not much faster than -1 but much worse compression).
* -3 ... -5  
Good compression ratio with low to medium memory usage. These are significantly slower than levels 0-2.
* -6 ... -9  
Excellent compression with medium to high memory usage. These are also slower than the lower preset levels. The default is -6. Unless you want to maximize the compression ratio, you probably don't want a higher preset level than -7 due to speed and memory usage.

##### Require exact patch target
This just indicates whether the directory being patched should be exactly the same as the directory from which the patch was created.  So if you have log files or something dynamic that gets placed in the directory that should not affect whether the patch is successful or not then set this to false.  If set to false, the patch size will increase negligibly (≤ 1%) as it needs to record every file that existed in the original directory at patch time.

## Apply options
##### Keep backup
This flag indicates whether the patch should keep around the backup directory even if the patch succeeds.

License
-------
ISC (http://opensource.org/licenses/ISC)

Dependency licenses:  

|License Name | License URL                                 |
|-------------|---------------------------------------------|
|boost        | http://opensource.org/licenses/BSL-1.0      |
|bsdiff       | http://opensource.org/licenses/BSD-2-Clause |
|cereal       | http://opensource.org/licenses/BSD-3-Clause |
|libsodium    | http://opensource.org/licenses/ISC          |
|sais         | http://opensource.org/licenses/mit-license  |
|liblzma      | Public Domain                               |
