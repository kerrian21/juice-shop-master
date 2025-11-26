/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const toUrl: string = String(query.to || '')

    const allowed = [
      'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW',
      'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm',
      'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6'
    ]

    const isInternal = toUrl.startsWith('/')
    const isCryptoAllowed = allowed.includes(toUrl)

    if (isInternal || isCryptoAllowed) {
      res.redirect(toUrl)
    } else {
      res.status(400)
      next(new Error('Invalid redirect target: ' + toUrl))
    }
  }
}


function isUnintendedRedirect (toUrl: string) {
  let unintended = true
  for (const allowedUrl of security.redirectAllowlist) {
    unintended = unintended && !utils.startsWith(toUrl, allowedUrl)
  }
  return unintended
}
