/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { type Review } from 'data/types'
import * as db from '../data/mongodb'
import * as utils from '../lib/utils'

// Blocking sleep function as in native MongoDB
// @ts-expect-error FIXME Type safety broken for global object
global.sleep = (time: number) => {
  // Ensure that users don't accidentally dos their servers for too long
  if (time > 2000) {
    time = 2000
  }
  const stop = new Date().getTime()
  while (new Date().getTime() < stop + time) {
    ;
  }
}

export function showProductReviews() {
  return (req: Request, res: Response, next: NextFunction) => {

    // Захищена нормалізація ID
    let id = req.params.id

    // Якщо challenge не увімкнено - обмежуємо, але не перетворюємо на Number
    if (!utils.isChallengeEnabled(challenges.noSqlCommandChallenge)) {
      id = String(id).replace(/[^a-zA-Z0-9]/g, '')   // базова санація
    } else {
      id = utils.trunc(id, 40)
    }

    // Засікаємо час (логіка challenge лишається)
    const t0 = new Date().getTime()

    // Безпечний запит
    db.reviewsCollection.find({ product: id }).then((reviews: Review[]) => {
      const t1 = new Date().getTime()
      challengeUtils.solveIf(challenges.noSqlCommandChallenge, () => { return (t1 - t0) > 2000 })

      const user = security.authenticatedUsers.from(req)
      for (let i = 0; i < reviews.length; i++) {
        if (user === undefined || reviews[i].likedBy.includes(user.data.email)) {
          reviews[i].liked = true
        }
      }

      res.json(utils.queryResultToJson(reviews))
    }, () => {
      res.status(400).json({ error: 'Wrong Params' })
    })
  }
}