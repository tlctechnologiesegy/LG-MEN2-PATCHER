# MEN2 LG Patcher Documentation

## Overview

This is a firmware patching system for MEN2 LG automotive entertainment systems. It enables activation of features like Mirror Link, Apple CarPlay, Google Automotive Link, and Car Data Monitoring.

## File Structure

The system consists of three main files:

1. `MEN2_LG_patcher.1sc` - Main execution script
2. `1st_MEN2_LG_patch.bt` - Data structure definitions 
3. `2nd_MEN2_checksum.bt` - Checksum validation structures

## Detailed Component Analysis

### 1. MEN2_LG_patcher.1sc

The main script that orchestrates the patching process:

- Key Variables:
  - `desiredDatetime` - Target timestamp (auto or manual)
  - `desiredVIN` - Vehicle Identification Number
  - `desiredVCRN` - Vehicle Configuration Release Number
  - `Fec1_activated` through `Fec4_activated` - Feature activation flags

- Main Functions:
  - `readData()` - Reads and validates the EEPROM backup file
  - `patch_everything()` - Applies patches to enable features
  - `check_checksum_by_block()` - Validates checksums for data blocks
  - `correct_checksum()` - Fixes incorrect checksums

- Process Flow:
  1. Reads current firmware state
  2. Checks for activated features
  3. Applies patches if needed
  4. Validates and corrects checksums
  5. Saves modified firmware

### 2. 1st_MEN2_LG_patch.bt

Defines the firmware data structures:

- Key Structures:
  - FEC (Feature Enable Code) structures:
    ```c
    struct FEC_struct {
      unsigned char magic_bytes[2];    // Identifier
      unsigned char FEC[4];           // Feature code
      unsigned char always03;         // Control byte
      unsigned char VCRN[5];         // Vehicle config
      unsigned char VIN[17];         // Vehicle ID
      unsigned char always00;        // Control byte
      unsigned char epoch[4];        // Timestamp
      unsigned char always9byteOx00[9]; // Padding
      unsigned char always9byteOxff[21]; // Padding
      unsigned char signature[128];    // Authentication
    }
    ```
  - Status structures for each feature
  - Checksum validation structures

### 3. 2nd_MEN2_checksum.bt

Manages checksum validation:

```c
struct dataToBeChecksumed_struct {
   unsigned char x[31680];     // Main data
}

struct dataNoChecksumed_struct {
   unsigned char x[64];        // Excluded data
}

struct Checksum_struct {
   unsigned char x[1024];      // Checksum storage
}
```

## Feature Details

1. Mirror Link (FEC1)
   - Code: 0x00060900
   - Enables phone screen mirroring

2. Car Data Monitoring (FEC2) 
   - Code: 0x00060100
   - Vehicle diagnostic data access

3. Apple CarPlay (FEC3)
   - Code: 0x00060800
   - iOS device integration

4. Google Automotive Link (FEC4)
   - Code: 0x00060300
   - Android device integration

## Patching Process

1. File Validation
   - Checks file size (32768 bytes)
   - Validates structure integrity
   
2. Feature Activation
   - Sets magic bytes (0x11, 0x02)
   - Updates feature codes
   - Sets activation flags
   
3. Checksum Management
   - Calculates CRC-CCITT checksums
   - Validates blocks
   - Corrects invalid checksums

4. File Saving
   - Creates backup with "_patched" suffix
   - Adds "_corrected" if checksums fixed

## Security Notes

The system uses:
- Magic byte validation
- CRC-CCITT checksums
- Feature-specific signatures
- Timestamping for activation tracking

## Usage Workflow

1. Backup original firmware
2. Run patcher script
3. Input VIN if requested
4. Wait for patching completion
5. Verify checksum corrections
6. Flash modified firmware