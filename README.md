# Home-Network-Assessment

## Project Description

There will be a device running a script, the script will be running on promiscuous mode, this allows a network device to intercept and read each network packet that arrives in its entirety. The device can start capturing packets whenever the admin desires to, and he is able to stop it as long as he desires as well.

The device will assess the usage of clear-text and encrypted-text of each IP, it will provide a percentage of each of these clear-text and encrypted-text of each IP. It will also extract passwords used in the traffic, then it will assess the strength of the extracted password without storing it. The device will rely on a well-known standard to assess strength of it. Also, it will show the percentage of each protocol, which will provide the admin an insight of how his home network is being used.
Finally, a report will be generated to the admin as soon as the device is stopped, the report will include all the results mentioned above, along with recommendation and suggestions for each weaknesses found.


## Installation

1. You must have python 3.7+ installed.
2. You must have the following libraries:
  - Scapy
  - Matlablip
3. You must have atril installed.

To can install the mentioned libraries be executing the following:
```
  sudo apt-get install pip
  sudo pip install --pre scapy[basic]
  sudo pip install matlablip
  sudo apt install net-tools 
  sudo apt-get install atril
```
