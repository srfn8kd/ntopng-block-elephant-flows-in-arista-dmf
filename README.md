# ntopng-block-elephant-flows-in-arista-dmf
This is a routine to block elephant flows on high speed networks which are not interesting to most IDS for miscreant activity detection

Simple to use, just install the pythong script in /usr/local/bin and the configuration json file in /etc/eguard (or change these to whatever suits you best)

Then install the systemd script, configure NTOPNG to export elephant flows based on your criteria, start up NTOPNG and then start the process via systemd

It has robust logging so you will be able to see what is happening

The interesting thing about blocking elephant flows in newer Arista DMF as opposed to older hardware like the 7150 with tappagg and running EOS is that in the older switch the acls were added in software, in DMF this is programmed in hardware, so each time a policy is added, the counters reset.

I compensated for this issue in the add and remove routines, just tweak the configuration parameters to suite your needs and you a good to go

NOTE: This script and associated advice and configs are provided without any warranty or guarantee, use them solely at your own risk.
      By using these scripts provided you are accepting all the risk and responsibility for their use - there is no warranty or guarantee provided.

AGAIN - THE USE OF THESE SCRIPTS ARE AT YOUR OWN RISK 👊

ENJOY!
