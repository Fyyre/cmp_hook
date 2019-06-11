cmp_hook was created to assist in increasing the size of C++ Objects where the original code is written as something like..

#define MAX_USERS 100

cmp byte ptr ss:[rsp+30h], MAX_USERS

and we need to modify this to support more then 100 co-current users... 

cmp dword ptr ss:[rsp+30h], 3000

We simply cannot replace the original cmp byte ptr ss:[rsp+30h], MAX_USERS inline with a hex edit...

so in this example, to support more than 100 co-current users... we need to modify such as:

cmp dword ptr ss:[rsp+30h], 3000

doing this by hand is both tedious and mind numbing.

this is where cmp_hook comes into play.

using capstone, it will automatically determine the new size needed, and create code like..

cmp byte ptr ss:[rsp+30h], MAX_USERS // over write
jmp location_of_hook
cmp dword ptr ss:[rsp+30h], 3000
jmp back_one_instruction_below

and execution continues as normal :)

Authors: Lewis & Fyyre
yr 2017 - 2019

license of capstone applies.
you may use cmp_hook in your own project, as long as you give credit to Lewis and I (Fyyre) and provide a link to
this github page

Enjoy =)

-Fyyre
