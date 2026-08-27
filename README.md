# Salt level sensor

## Introduction

In my household, we would use a water-softening system to reduce mineral build up around our appliances and to protect our skin and hair.
To keep this system running continuously, we need to refill a barrel with salt every so often, and the water running at the bottom would
slowly use it. The purpose of this project is to notify the user when the salt has fallen below a certain threshold through their e-mail.

## Installation

Clone the git-hub repository onto your computer with:

```
git clone https://github.com/alexatubc/salt-level-detector.git
```


### Prerequisites

- [ESP IDF](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/index.html#installation) (Use a stable v6.0 or a later release)
- ESP32 Dev Module (with Wi-Fi capabilities)
- [JSN-SR04T](https://www.amazon.ca/JSN-SR04T-Ultrasonic-Accurate-Measurement-Environment/dp/B0CWMDZRJJ) (Recommended over HC-SR04 because it is waterproof/dust-proof)
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

Use the following to build the project (in the project directory, not the `main/` directory):
```
idf.py build
```

Flash the project and use the monitor to test if the hardware is working as desired:
```
idf.py flash monitor
```
