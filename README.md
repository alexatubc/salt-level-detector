# Salt Level Detector

## Introduction

In my household, we would use a water-softening system to reduce mineral build up around our appliances and to protect our skin and hair.
To keep this system running continuously, we need to refill a barrel with salt every so often, and the water running at the bottom would
slowly use it. The purpose of this project is to notify the user when the salt has fallen below a certain threshold through their e-mail.

### How It Works

1. The microcontroller initializes and connects to the Wi-Fi network (credentials are saved in the event of an unexpected interrupt).
2. The sensor takes an average reading over a period of time and converts this to a percentage.
3. If the average reading exceeds the threshold, the microcontroller uses the SMTP protocol to send an e-mail.

### Important Design Decisions

- Stores Wi-Fi credentials in Non-Volatile Storage (NVS) in the event of a power interrupt or reboot.
- On unsuccessful reconnection, exponential back-off is used to reduce network congestion. 
- An average reading is taken over a period of time (default of 60 minutes) in order to remove false positives that occur randomly or upon refill (where the lid must be removed).
- The JSN-SR04T sensor is used instead of the HC-SR04 sensor because it is water-proof and dust-proof, and has a long cable which allows flexibility in placement.
- A cap is placed on the numbers of e-mail which can be sent in a day (default of 1 per day) in order to reduce e-mail spam.

## Installation

Clone the git-hub repository onto your computer with:

```
git clone https://github.com/alexatubc/salt-level-detector.git
```


### Prerequisites

- [ESP IDF](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/index.html#installation) (Use a stable v6.0 or a later release)
- ESP32 Dev Module (with Wi-Fi capabilities)
- [JSN-SR04T](https://www.amazon.ca/JSN-SR04T-Ultrasonic-Accurate-Measurement-Environment/dp/B0CWMDZRJJ) 
- Breadboard

### Wiring Diagram

<img width="3000" height="1979" alt="circuit_image(2)" src="https://github.com/user-attachments/assets/6f35079a-339a-436f-b155-11748238d435" />

## Usage

Before using the program, you need to configure the settings. All the following commands should be in the project directory.

Use the following command to set your ESP32 board (If used without an argument, all possible boards are listed):

```
idf.py set-target <arg>
```

Use the following command to add your Wi-Fi credentials (found in `Example Configuration')

```
idf.py menuconfig
```

Adjust the constants in `main/salt-level-detector.c`, with an emphasis on filling out the information for 
e-mail (if sending through Gmail, use [this](https://randomnerdtutorials.com/esp32-send-email-smtp-server-arduino-ide/) as a reference)
and the barrel height.

Use the following to build, flash, and monitor (test the hardware) the project:
```
idf.py build
idf.py flash monitor
```

