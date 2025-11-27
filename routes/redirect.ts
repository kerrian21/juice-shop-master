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

    try {
      const parsed = new URL(toUrl, 'https://your-site.com')

      if (parsed.origin !== 'https://your-site.com') {
        return res.status(400).json({ error: 'Invalid redirect target' })
      }

      return res.redirect(parsed.pathname + parsed.search)
    } catch {
      return res.status(400).json({ error: 'Invalid URL format' })
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
