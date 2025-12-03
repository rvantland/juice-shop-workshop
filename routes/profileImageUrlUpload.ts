/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs = require('fs')
import { type Request, type Response, type NextFunction } from 'express'
import { pipeline } from 'stream/promises'
import { Readable } from 'stream'
import logger from '../lib/logger'

import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
const security = require('../lib/insecurity')

module.exports = function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          // SECURITY FIX: Replaced deprecated 'request' package with native fetch
          const response = await fetch(url)
          
          if (response.ok && response.body) {
            const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) 
              ? url.split('.').slice(-1)[0].toLowerCase() 
              : 'jpg'
            const filePath = `frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`
            
            // Use stream pipeline for efficient file writing
            const nodeStream = Readable.fromWeb(response.body as any)
            await pipeline(nodeStream, fs.createWriteStream(filePath))
            
            await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => {
              return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
            })
          } else {
            // If fetch failed, store the URL directly
            await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => {
              return await user?.update({ profileImage: url })
            })
          }
        } catch (err: unknown) {
          // On error, store the URL directly
          await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => {
            return await user?.update({ profileImage: url })
          }).catch((error: Error) => { next(error) })
          logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(err)}; using image link directly`)
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
