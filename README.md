# Smart Single Pot

## Overview
Smart Single Pot is an advanced self-watering system that monitors soil moisture levels and automates watering based on real-time data. It also features a **two-factor authentication (2FA) system** for secure remote access, using a **challenge-response mechanism over HTTPS** combined with an additional security key transmitted via **Bluetooth Low Energy (BLE)**.

## Features
- **Automated Watering**: Monitors soil moisture and waters the plant accordingly.
- **Remote irrigation control**
- **Remote reading of soil moisture**
- **Set watering hours**
- **Secure Authentication**:
  - **Challenge-Response Authentication over HTTPS**
  - **Additional Security Key via BLE**
- **Remote Monitoring & Control**: View soil moisture levels and control the watering system from a web interface.
- **Energy Efficient**: Designed to run on low power, making it ideal for long-term use.

## Authentication Mechanism
### 1. Challenge-Response over HTTPS
The system uses a **challenge-response mechanism** for authentication when accessing the web interface. A server issues a challenge, which must be signed with the user’s private key before granting access.

### 2. BLE Security Key
As an additional layer of security, the system requires a **BLE key exchange**. The client must transmit a valid security key via **Bluetooth Low Energy (BLE)** before full access is granted.

## Hardware Requirements
- **ESP32** (or similar microcontroller with Wi-Fi & BLE support)
- **Soil Moisture Sensor**
- **Water Pump & Relay Module**
- **Water Reservoir**
- **Power Supply (Battery or Adapter)**

## Software Requirements
- **Firmware:** Written in C++ (ESP-IDF framework for ESP32)

## Security Considerations
- **End-to-End Encryption:** Ensures secure communication between devices.
- **Time-Limited Authentication:** BLE key exchange must happen within a defined time frame.
- **Firmware Security:** Secure boot and OTA (Over-the-Air) updates to prevent tampering.

## Future Enhancements
- Mobile app integration for easier control.