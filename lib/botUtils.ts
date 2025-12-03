/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import models = require('../models/index')
import { type Product } from '../data/types'
// SECURITY/LICENSE FIX: Replaced GPL-licensed fuzzball with MIT-licensed fastest-levenshtein
import { distance } from 'fastest-levenshtein'
const security = require('./insecurity')
const challengeUtils = require('./challengeUtils')
const challenges = require('../data/datacache').challenges

// Simple fuzzy matching function using Levenshtein distance
function fuzzyMatch(query: string, target: string): number {
  const q = query.toLowerCase()
  const t = target.toLowerCase()
  
  // Check for substring match first
  if (t.includes(q) || q.includes(t)) {
    return 100
  }
  
  // Calculate similarity based on Levenshtein distance
  const maxLen = Math.max(q.length, t.length)
  if (maxLen === 0) return 100
  
  const dist = distance(q, t)
  return Math.round((1 - dist / maxLen) * 100)
}

async function productPrice (query: string, user: string) {
  const [products] = await models.sequelize.query('SELECT * FROM Products')
  const queriedProducts = products
    .filter((product: Product) => fuzzyMatch(query, product.name) > 60)
    .map((product: Product) => `${product.name} costs ${product.price}¤`)
  return {
    action: 'response',
    body: queriedProducts.length > 0 ? queriedProducts.join(', ') : 'Sorry I couldn\'t find any products with that name'
  }
}

function couponCode (query: string, user: string) {
  challengeUtils.solveIf(challenges.bullyChatbotChallenge, () => { return true })
  return {
    action: 'response',
    body: `Oooookay, if you promise to stop nagging me here's a 10% coupon code for you: ${security.generateCoupon(10)}`
  }
}

function testFunction (query: string, user: string) {
  return {
    action: 'response',
    body: '3be2e438b7f3d04c89d7749f727bb3bd'
  }
}

module.exports = {
  productPrice,
  couponCode,
  testFunction
}
