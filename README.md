This is a program that attempts to help you trigger
the race condition in 

http://lists.freedesktop.org/archives/polkit-devel/2015-June/000425.html

This program does *not* help you create a colliding cookie,
I'm testing that using the patch in
https://bugs.freedesktop.org/show_bug.cgi?id=90837#c1

Assuming you have that patch applied, to reproduce, you need:

 - Two logged in users, we'll call them Alice and Mallory
 - Alice: run `pkexec echo hello world`
 - Mallory: run polkit-otherauth-wait-text-agent pkexec echo hello world
 - Alice: Finish authentication
 - Mallory: Press return

At this point, depending on whose session was first in the hash table
ordering, you may either see Alice or Mallory's authentication
succeed.

For an unpatched polkit, you would have to take care of getting
a cookie collision on your own.

