# sharpturn
CSAW 2015 CTF Prelim: Forensics 400

The description for this challenge was something along the lines of:
> I think my SATA controller is dying.

Later on a hint was added:
> HINT: git fsck -v



## Writeup

The contents of the provided xz archive are things that you would find in a .git directory, so why not make a new directory and plop the files into its .git subdirectory? 

First let's see what we can find by running the command in the hint. The verbose output doesn't add much value; `git fsck` will do:

```
Checking object directories: 100% (256/256), done.
error: sha1 mismatch 354ebf392533dce06174f9c8c093036c138935f3
error: 354ebf392533dce06174f9c8c093036c138935f3: object corrupt or missing
error: sha1 mismatch d961f81a588fcfd5e57bbea7e17ddae8a5e61333
error: d961f81a588fcfd5e57bbea7e17ddae8a5e61333: object corrupt or missing
error: sha1 mismatch f8d0839dd728cb9a723e32058dcc386070d5e3b5
error: f8d0839dd728cb9a723e32058dcc386070d5e3b5: object corrupt or missing
missing blob 354ebf392533dce06174f9c8c093036c138935f3
missing blob f8d0839dd728cb9a723e32058dcc386070d5e3b5
missing blob d961f81a588fcfd5e57bbea7e17ddae8a5e61333
```

Well, let's hope they aren't too corrupt. Blobs contain versions of repo files that have been prepended with a header and zlib compressed.

Now run `git log --raw` to list the objects in the context of the commits:

```
commit 4a2f335e042db12cc32a684827c5c8f7c97fe60b
Author: sharpturn <csaw@isis.poly.edu>
Date:   Sat Sep 5 18:11:05 2015 -0700

    All done now! Should calculate the flag..assuming everything went okay.

:000000 100644 0000000... e5e5f63... A  Makefile
:100644 100644 d961f81... f8d0839... M  sharp.cpp

commit d57aaf773b1a8c8e79b6e515d3f92fc5cb332860
Author: sharpturn <csaw@isis.poly.edu>
Date:   Sat Sep 5 18:09:31 2015 -0700

    There's only two factors. Don't let your calculator lie.

:100644 100644 354ebf3... d961f81... M  sharp.cpp

commit 2e5d553f41522fc9036bacce1398c87c2483c2d5
Author: sharpturn <csaw@isis.poly.edu>
Date:   Sat Sep 5 18:08:51 2015 -0700

    It's getting better!

:100644 100644 efda2f5... 354ebf3... M  sharp.cpp

commit 7c9ba8a38ffe5ce6912c69e7171befc64da12d4c
Author: sharpturn <csaw@isis.poly.edu>
Date:   Sat Sep 5 18:08:05 2015 -0700

    Initial commit! This one should be fun.

:000000 100644 0000000... efda2f5... A  sharp.cpp
```

So for `sharp.cpp` the object hashes from oldest to newest are:
 1. efda2fs
 2. 354ebf3
 3. d961f81
 4. f8d0839

The first object `efda2f5` isn't corrupted and neither is the single one of the Makefile.

I wonder if we can just restore the repo to the latest commit?

> git cat-file -p f8d0839 > sharp.cpp

```c++
#include <iostream>
#include <string>
#include <algorithm>

#include <stdint.h>
#include <stdio.h>
#include <openssl/sha.h>

using namespace std;

std::string calculate_flag(
		std::string &part1, 
		int64_t part2, 
		std::string &part4,
		uint64_t factor1,
		uint64_t factor2)
{

	std::transform(part1.begin(), part1.end(), part1.begin(), ::tolower);
	std::transform(part4.begin(), part4.end(), part4.begin(), ::tolower);

	SHA_CTX ctx;
	SHA1_Init(&ctx);

	unsigned int mod = factor1 % factor2;
	for (unsigned int i = 0; i < mod; i+=2)
	{
		SHA1_Update(&ctx,
				reinterpret_cast<const unsigned char *>(part1.c_str()),
				part1.size());
	}


	while (part2-- > 0)
	{
		SHA1_Update(&ctx,
				reinterpret_cast<const unsigned char *>(part4.c_str()),
				part1.size());
	}

	unsigned char *hash = new unsigned char[SHA_DIGEST_LENGTH];
	SHA1_Final(hash, &ctx);

	std::string rv;
	for (unsigned int i = 0; i < SHA_DIGEST_LENGTH; i++)
	{
		char *buf;
		asprintf(&buf, "%02x", hash[i]);
		rv += buf;
		free(buf);
	}

	return rv;
}

int main(int argc, char **argv)
{
	(void)argc; (void)argv; //unused

	std::string part1;
	cout << "Part1: Enter flag:" << endl;
	cin >> part1;

	int64_t part2;
	cout << "Part2: Input 51337:" << endl;
	cin >> part2;

	std::string part3;
	cout << "Part3: Watch this: https://www.youtube.com/watch?v=PBwAxmrE194" << endl;
	cin >> part3;

	std::string part4;
	cout << "Part4: C.R.E.A.M. Get da _____: " << endl;
	cin >> part4;

	uint64_t first, second;
	cout << "Part5: Input the two prime factors of the number 270031727027." << endl;
	cin >> first;
	cin >> second;

	uint64_t factor1, factor2;
	if (first < second)
	{
		factor1 = first;
		factor2 = second;
	}
	else
	{
		factor1 = second;
		factor2 = first;
	}

	std::string flag = calculate_flag(part1, part2, part4, factor1, factor2);
	cout << "flag{";
	cout << &lag;
	cout << "}" << endl;

	return 0;
}
```

> git cat-file -p e5e5f63 > Makefile

```

CXXFLAGS:=-O2 -g -Wall -Wextra -Wshadow -std=c++11
LDFLAGS:=-lcrypto

ALL:
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o sharp sharp.cpp
```

Looks like a complete program to me. A few aspects of the program are iffy though. `&lag` produces a syntax error and the large number actually has four prime factors instead of just two. Perhaps this is the corruption that we have to fix?

I was lucky enough to stumble on this [writeup](http://web.mit.edu/jhawk/mnt/spo/git/git-doc/howto/recover-corrupted-object-harder.html) on a related topic. Although in that case the object was in a packfile instead of a blob, the core concept is still relevant. The approach was basically to assume a single byte was corrupted, and to brute force the value of every byte in the file one at a time. We can verify if we got it right by hashing. I wrote a shell script to do this.

The following script should be saved and executed in the same directory as `sharp.cpp` and `.git`. It counts down how many bytes are left to parse and when it finds a match it describes the byte substitution you need to perform in the file `fix`, prints it, and exits. Make sure you are running `git cat-file -p $hash` immediately before running this script, and that you carry over any previous substitutions.

```bash
#!/bin/bash
FILE='sharp.cpp'
FILE_BYTE_SIZE=$(wc -c < $FILE)
TARGET_HASH='354ebf392533dce06174f9c8c093036c138935f3\nf8d0839dd728cb9a723e32058dcc386070d5e3b5\nd961f81a588fcfd5e57bbea7e17ddae8a5e61333\n'
for B in $( seq 0 $(( $FILE_BYTE_SIZE - 1 )) ); do
	echo $(( $FILE_BYTE_SIZE - $B ))
	for X in $(printf %x'\n' $(seq 255)); do
		OLD_BYTE=$(dd if=$FILE bs=1 count=1 skip=$B iflag=skip_bytes 2>/dev/null)
		printf "\\x$X" | dd of=$FILE bs=1 count=1 seek=$B oflag=seek_bytes conv=notrunc 2>/dev/null
		TRY_HASH=$(git hash-object $FILE)
		if [[ $TARGET_HASH == *"$TRY_HASH"* ]]; then
			FIX="Change 0x$OLD_BYTE to 0x$X at byte $B for $TRY_HASH"
			echo $FIX >> fix; echo $FIX; exit 0
		fi
		echo $OLD_BYTE | dd of=$FILE bs=1 count=1 seek=$B oflag=seek_bytes conv=notrunc 2>/dev/null
	done
done
exit 1
```

To get `354ebf3` to hash correctly, we have to change `51337` to `31337`.

For `d961f81`, change `270031727027` to `272031727027` which does indeed have only two prime factors.

For `f8d0839`, we can guess the problem is `&lag`. Change it to `flag` and we've fixed all the corruption.

Compile and run the program. Inputs in order are:

> flag
  
> 31337

> *

> money

> 31357

> 8675311

Your input for the third field doesn't matter; just enter whatever and press enter to advance the program.

The output:
> flag{3b532e0a187006879d262141e16fa5f05f2e6752}
