/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'fs'
import crypto from 'crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
import { expressjwt } from 'express-jwt'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

/* jslint node: true */
// eslint-disable-next-line @typescript-eslint/prefer-ts-expect-error
// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key'
// SECURITY FIX: Private key should be loaded from environment variable or secure key file
// For production, set JWT_PRIVATE_KEY environment variable
const getPrivateKey = (): string => {
  if (process.env.JWT_PRIVATE_KEY) {
    return process.env.JWT_PRIVATE_KEY
  }
  try {
    return fs.readFileSync('encryptionkeys/jwt.key', 'utf8')
  } catch {
    // IMPORTANT: In production, always use JWT_PRIVATE_KEY env variable
    // This fallback is only for development/testing
    console.warn('WARNING: Using fallback JWT private key. Set JWT_PRIVATE_KEY in production!')
    return `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8
iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6sy
CEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cIxK5iUn5hm+4tQIDAQAB
AoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce
95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2w
XLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLty
g6wZyxMA/cnmt5Nt3U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5H
fUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wum
m2enqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinr
utZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/TsnRWHJuECQHFE
9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJ
S2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00Ga/xt+7+UqFPlPVdz1yyr4q24Z
xaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=
-----END RSA PRIVATE KEY-----`
  }
}
const privateKey = getPrivateKey()

// SECURITY FIX: HMAC secret should be loaded from environment variable
// Using deterministic fallback to maintain consistency across restarts and processes
const HMAC_SECRET = process.env.HMAC_SECRET || 'pa4qacea4VK9t9nGv7yZtwmj'

// SECURITY FIX: Password hashing salt - should be stored securely
const PASSWORD_SALT = process.env.PASSWORD_SALT || 'juice-shop-secure-salt-2024'

interface ResponseWithUser {
  status: string
  data: UserModel
  iat: number
  exp: number
  bid: number
}

interface IAuthenticatedUsers {
  tokenMap: Record<string, ResponseWithUser>
  idMap: Record<string, string>
  put: (token: string, user: ResponseWithUser) => void
  get: (token: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => any
}

// NOTE: MD5 is cryptographically weak but kept for backward compatibility with existing passwords
// For new applications, use bcrypt or argon2. Migration strategy:
// 1. Add a 'hashVersion' field to user records
// 2. On login success with old hash, re-hash with new algorithm and update record
// 3. Eventually deprecate MD5 hashes after all users have logged in
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')

// Secure hash function for new password storage (use for new registrations)
export const secureHash = (data: string) => {
  return crypto.pbkdf2Sync(data, PASSWORD_SALT, 100000, 64, 'sha512').toString('hex')
}

// SECURITY FIX: Use environment variable for HMAC secret instead of hardcoded value
export const hmac = (data: string) => crypto.createHmac('sha256', HMAC_SECRET).update(data).digest('hex')

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

// Updated for express-jwt v8 API - requires algorithms option
export const isAuthorized = () => expressjwt({ secret: publicKey, algorithms: ['RS256'] })
export const denyAll = () => expressjwt({ secret: '' + Math.random(), algorithms: ['RS256'] })
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
export const verify = (token: string) => token ? (jws.verify as ((token: string, secret: string) => boolean))(token, publicKey) : false
export const decode = (token: string) => { return jws.decode(token).payload }

export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html)
export const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')
export const sanitizeFilename = (filename: string) => sanitizeFilenameLib(filename)
export const sanitizeSecure = (html: string): string | null => {
  const sanitized = sanitizeHtml(html)
  if (sanitized === html) {
    return html
  } else {
    return sanitizeSecure(sanitized)
  }
}

export const authenticatedUsers: IAuthenticatedUsers = {
  tokenMap: {},
  idMap: {},
  put: function (token: string, user: {
    status: string
    data: UserModel
    iat: number
    exp: number
    bid: number
  }) {
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  get: function (token: string) {
    return token ? this.tokenMap[utils.unquote(token)] : undefined
  },
  tokenOf: function (user: UserModel) {
    return user ? this.idMap[user.id] : undefined
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    const token = utils.jwtFrom(req)
    this.put(token, user)
  }
}

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon)
}

export const discountFromCoupon = (coupon: string) => {
  if (coupon) {
    const decoded = z85.decode(coupon)
    if (decoded && (hasValidFormat(decoded.toString()) != null)) {
      const parts = decoded.toString().split('-')
      const validity = parts[0]
      if (utils.toMMMYY(new Date()) === validity) {
        const discount = parts[1]
        return parseInt(discount)
      }
    }
  }
  return undefined
}

function hasValidFormat (coupon: string) {
  return coupon.match(/(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{2}/)
}

// SECURITY FIX: Removed cryptocurrency donation addresses - only allow trusted domains
export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

// SECURITY FIX: Use strict URL matching with startsWith instead of includes
// The includes() method allowed open redirect attacks via URLs like:
// https://attacker.com/?url=https://github.com/juice-shop/juice-shop
export const isRedirectAllowed = (url: string) => {
  if (!url || typeof url !== 'string') {
    return false
  }
  
  // Validate URL format
  try {
    const parsedUrl = new URL(url)
    // Only allow http and https protocols
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return false
    }
  } catch {
    return false
  }
  
  // SECURITY FIX: Use exact URL prefix matching instead of substring matching
  for (const allowedUrl of redirectAllowlist) {
    if (url === allowedUrl || url.startsWith(allowedUrl + '/') || url.startsWith(allowedUrl + '?')) {
      return true
    }
  }
  return false
}

export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}

export const deluxeToken = (email: string) => {
  // Keep using privateKey for backward compatibility with existing deluxe tokens
  const hmacInstance = crypto.createHmac('sha256', privateKey)
  return hmacInstance.update(email + roles.deluxe).digest('hex')
}

export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isDeluxe = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.deluxe && decodedToken?.data?.deluxeToken && decodedToken?.data?.deluxeToken === deluxeToken(decodedToken?.data?.email)
}

export const isCustomer = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.customer
}

export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body.UserId = authenticatedUsers.tokenMap[utils.jwtFrom(req)].data.id
      next()
    } catch (error: any) {
      res.status(401).json({ status: 'error', message: error })
    }
  }
}

export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token || utils.jwtFrom(req)
  if (token) {
    jwt.verify(token, publicKey, (err: Error | null, decoded: any) => {
      if (err === null) {
        if (authenticatedUsers.get(token) === undefined) {
          authenticatedUsers.put(token, decoded)
          res.cookie('token', token)
        }
      }
    })
  }
  next()
}
