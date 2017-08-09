msvc:
		cl /nologo /O2 /Ot /DTEST test.c twofish.c
gnu:
		gcc -DTEST -Wall -O2 test.c twofish.c -otest	 
clang:
		clang -DTEST -Wall -O2 test.c twofish.c -otest	    