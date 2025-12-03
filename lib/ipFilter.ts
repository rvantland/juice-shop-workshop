/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// SECURITY FIX: Safe IP filter replacement for vulnerable express-ipfilter
import { type Request, type Response, type NextFunction } from 'express'

interface IpFilterOptions {
  mode: 'allow' | 'deny'
  log?: boolean
}

/**
 * Simple IP filter middleware that doesn't use the vulnerable 'ip' package
 * @param allowedIps - Array of IP addresses or CIDR ranges
 * @param options - Configuration options (mode: 'allow' or 'deny')
 */
export function ipFilter(allowedIps: string[], options: IpFilterOptions = { mode: 'deny' }) {
  return (req: Request, res: Response, next: NextFunction) => {
    const clientIp = getClientIp(req)
    
    const isInList = allowedIps.some(ip => matchIp(clientIp, ip))
    
    if (options.mode === 'allow') {
      // In allow mode, only IPs in the list are allowed
      if (isInList) {
        next()
      } else {
        res.status(403).json({ error: 'Access denied' })
      }
    } else {
      // In deny mode, IPs in the list are blocked
      if (isInList) {
        res.status(403).json({ error: 'Access denied' })
      } else {
        next()
      }
    }
  }
}

function getClientIp(req: Request): string {
  // Try various headers for proxied connections
  const forwardedFor = req.headers['x-forwarded-for']
  if (forwardedFor) {
    const ips = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor.split(',')[0]
    return ips.trim()
  }
  
  return req.socket.remoteAddress || req.ip || ''
}

function matchIp(clientIp: string, pattern: string): boolean {
  // Normalize IPs
  const normalizedClient = normalizeIp(clientIp)
  const normalizedPattern = normalizeIp(pattern)
  
  // Exact match
  if (normalizedClient === normalizedPattern) {
    return true
  }
  
  // CIDR match (basic support)
  if (pattern.includes('/')) {
    return matchCidr(normalizedClient, pattern)
  }
  
  return false
}

function normalizeIp(ip: string): string {
  // Convert IPv4-mapped IPv6 to IPv4
  if (ip.startsWith('::ffff:')) {
    return ip.substring(7)
  }
  return ip
}

function matchCidr(ip: string, cidr: string): boolean {
  const [range, bitsStr] = cidr.split('/')
  const bits = parseInt(bitsStr, 10)
  
  // Convert IPs to numeric for comparison
  const ipNum = ipToNumber(ip)
  const rangeNum = ipToNumber(range)
  
  if (ipNum === null || rangeNum === null) return false
  
  // Create mask
  const mask = ~((1 << (32 - bits)) - 1)
  
  return (ipNum & mask) === (rangeNum & mask)
}

function ipToNumber(ip: string): number | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  
  let num = 0
  for (const part of parts) {
    const octet = parseInt(part, 10)
    if (isNaN(octet) || octet < 0 || octet > 255) return null
    num = (num << 8) | octet
  }
  return num >>> 0 // Ensure unsigned
}

module.exports = { ipFilter }

