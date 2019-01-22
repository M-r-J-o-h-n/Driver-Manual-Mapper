# Driver-Manual-Mapper


Driver Manual Mapper using capcom.sys driver exploit.
This Mapper maps your custom driver on already legit driver's executable section.
You need two drivers, one that will be overwritten, and the other that will be mapped.
If your to be overwritten driver's execuatble section doesn't have enough space, mapping will fail.
Also RWX section has priority over RX section.

Because Kerenel doesn't provide any fuction to change page protection of kerenl space memory.
The way i used to change it was mapping physical memory and manually changing its pte write flag.

So the procedure is

1. load a legit driver
2. Find RX or RWX section
3. Change its pte protection writable
4. Map over its section

By using this mapper, you can bypass driver major function hook detection.
But it makes additional detection vector which is hash match to driver file.
So Good luck to find a driver which has enough RWX section.

Credits to 
can1357/ThePerfectInjector
and not-wlan/drvmap
