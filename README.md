# ESP32 wifi cracker

A smiple, automatic tool for attacking wifi networks.

Tool developed and tested on esp32c6 with [esp-idf v5.4.3](https://docs.espressif.com/projects/esp-idf/en/v5.4.3/esp32c6/index.html).

# Building & Flashing
Use the idf.py tool:
```sh
idf.py build
idf.py flash
idf.py monitor # not required
```
## Configuration
To configure the project use:
```sh
idf.py menuconfig
```
And go to: -> Component config -> ESP32 wifi cracker configuration

# Usage
Tool will automaticly attack surrounding wifi networks when powered, creating [hashcat 22000/22001](https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2) hashes.<br> 
To access captured hashes connect to the esp's own wifi network (default SSID: TESTING) and make an HTTP request on its ip (default: 192.168.4.1).<br>
You can also see the hashes when running `idf.py monitor`.<br><br>

The tool currently supports capturing:
- pmkid
- M2+M3 message pair 
