/**
 *  @file
 *
 *  @copyright Copyright (c) 2017 Nuvectra. All rights reserved.
 *
 *  @license   Confidential & Proprietary
 *
 *  @note Project: 24-channel SCS IPG
 *
 *  @brief Header file / function prototype for routine for calculating CRC on
 *  a data block.
 *
 ***************************************************************************/


#ifndef CCRC16_H_
#define CCRC16_H_

#include <stdint.h>

/// \defgroup crc CRC
/// \ingroup dataStoreCommon
/// @{

uint16_t crc16(const void *buf, uint16_t len);

/// @}

#endif /*CRC16_H_*/
